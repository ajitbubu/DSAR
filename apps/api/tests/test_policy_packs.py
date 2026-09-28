"""Policy packs: validation, integrity pinning, immutability, catalogue (M2; T-22)."""

import copy
import json
import shutil
from pathlib import Path
from typing import Any

import pytest
import yaml
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from idprivacy.domain.intake.schemas import RightCode
from idprivacy.domain.policy.loader import (
    PackIntegrityError,
    PackValidationError,
    canonical_hash,
    load_all,
    parse,
    read_yaml,
)
from idprivacy.domain.policy.registry import PolicyRegistry, publish
from idprivacy.scripts.policy_packs import SCHEMA, schema_json
from tests.conftest import POLICY_PACKS, bearer

DPDP_FILE = POLICY_PACKS / "dpdp" / "1.0.0" / "pack.yaml"


@pytest.fixture
def dpdp() -> dict[str, Any]:
    return read_yaml(DPDP_FILE)


def test_dpdp_pack_loads_and_matches_manifest_pin() -> None:
    (loaded,) = [p for p in load_all(POLICY_PACKS) if p.pack.code == "DPDP"]
    assert loaded.pack.ref == "DPDP@1.0.0"
    assert loaded.pack.legal_review == "PENDING"


def test_rights_catalogue_has_all_six_and_only_erasure_executable(dpdp) -> None:
    pack = parse(dpdp)
    assert set(pack.rights) == set(RightCode)
    assert {c for c, r in pack.rights.items() if r.executable} == {RightCode.ERASURE}
    assert pack.rights[RightCode.ERASURE].workflow == "erasure"
    assert all(pack.rights[c].workflow == "manual" for c in RightCode if c != RightCode.ERASURE)


def test_sla_values_are_not_invented(dpdp) -> None:
    """D-9: response deadlines stay unset until legal validates them."""
    pack = parse(dpdp)
    assert all(rule.response_days is None and not rule.validated for rule in pack.sla.values())


def test_only_verified_identifiers_drive_discovery(dpdp) -> None:
    assert parse(dpdp).identity_resolution.discovery_assurance == ["VERIFIED"]


def test_tampered_pack_file_is_rejected(tmp_path: Path) -> None:
    root = tmp_path / "packs"
    shutil.copytree(POLICY_PACKS, root)
    target = root / "dpdp" / "1.0.0" / "pack.yaml"
    data = yaml.safe_load(target.read_text())
    data["rights"]["ACCESS"]["executable"] = True  # quietly change behaviour
    target.write_text(yaml.safe_dump(data))
    with pytest.raises(PackIntegrityError, match="does not match the manifest pin"):
        load_all(root)


def test_yaml_formatting_changes_do_not_change_the_hash(tmp_path: Path, dpdp) -> None:
    reformatted = tmp_path / "pack.yaml"
    reformatted.write_text("# a new comment\n" + yaml.safe_dump(dpdp, sort_keys=False))
    assert canonical_hash(read_yaml(reformatted)) == canonical_hash(dpdp)


def _mutate(content: dict[str, Any], path: str, value: Any) -> dict[str, Any]:
    out = copy.deepcopy(content)
    node = out
    keys = path.split(".")
    for key in keys[:-1]:
        node = node[int(key)] if isinstance(node, list) else node[key]
    last = keys[-1]
    if value is _DELETE:
        del node[last]
    elif isinstance(node, list):
        node[int(last)] = value
    else:
        node[last] = value
    return out


_DELETE = object()


@pytest.mark.parametrize(
    "path, value, message",
    [
        ("rights.NOMINATION", _DELETE, "rights catalogue incomplete"),
        ("rights.ERASURE.workflow", "nonexistent", "unknown workflow"),
        ("workflows.erasure.transitions.0.to", "DELETED_EVERYTHING", "to"),
        ("workflows.erasure.transitions.0.guards", ["trust_me"], "unknown guards"),
        ("workflows.erasure.transitions.3.permission", "case:obliterate", "permission"),
        ("workflows.erasure.transitions.3.permission", None, "must declare a permission"),
        ("workflows.erasure.transitions.0.permission", "case:review", "must not declare"),
        ("retention_rules.0.exception_code", None, "RETAIN requires an exception_code"),
        ("retention_rules.0.exception_code", "BECAUSE_I_SAID_SO", "unknown exception code"),
        (
            "sla.ERASURE",
            {"response_days": None, "clock_start": "VERIFIED", "validated": True},
            "must set response_days",
        ),
        ("sla.ERASURE", _DELETE, "exactly one SLA rule"),
        ("version", "1.0", "version"),
        ("unexpected_key", "x", "Extra inputs"),
        ("applicability.any_of", [{}], "at least one field"),
        ("rights.ERASURE.accepted_verification", [], "accepted_verification"),
    ],
)
def test_invalid_packs_are_rejected(dpdp, path: str, value: Any, message: str) -> None:
    with pytest.raises(PackValidationError, match=message):
        parse(_mutate(dpdp, path, value))


def test_duplicate_transition_is_rejected(dpdp) -> None:
    transitions = dpdp["workflows"]["erasure"]["transitions"]
    bad = _mutate(dpdp, "workflows.erasure.transitions", transitions + [transitions[0]])
    with pytest.raises(PackValidationError, match="duplicate transition"):
        parse(bad)


def test_republishing_a_version_with_different_content_is_refused(
    migrator_engine: Engine, dpdp
) -> None:
    (loaded,) = [p for p in load_all(POLICY_PACKS) if p.pack.code == "DPDP"]
    with Session(migrator_engine) as s, s.begin():
        assert publish(s, loaded).content_sha256 == loaded.sha256  # idempotent re-publish
    altered_content = _mutate(dpdp, "title", "Something else")
    altered = type(loaded)(parse(altered_content), altered_content, canonical_hash(altered_content))
    with pytest.raises(PackIntegrityError, match="immutable"):
        with Session(migrator_engine) as s, s.begin():
            publish(s, altered)


@pytest.mark.parametrize(
    "stmt",
    [
        "UPDATE policy_pack SET content = jsonb_set(content, '{title}', '\"x\"') "
        "WHERE code = 'DPDP'",
        "UPDATE policy_pack SET content_sha256 = repeat('0', 64) WHERE code = 'DPDP'",
        "DELETE FROM policy_pack WHERE code = 'DPDP'",
    ],
)
def test_published_pack_rows_are_immutable(migrator_engine: Engine, stmt: str) -> None:
    with pytest.raises(DBAPIError, match="immutable|cannot be deleted"):
        with migrator_engine.begin() as conn:
            conn.execute(text(stmt))


def test_app_role_cannot_write_policy_packs(app_engine: Engine) -> None:
    with pytest.raises(DBAPIError, match="permission denied"):
        with app_engine.begin() as conn:
            conn.execute(text("UPDATE policy_pack SET status = 'RETIRED'"))


def test_registry_detects_tampered_db_row(migrator_engine: Engine, app_engine: Engine) -> None:
    """Simulates a privileged attacker editing the stored pack with the trigger disabled."""
    with migrator_engine.begin() as conn:
        conn.execute(text("ALTER TABLE policy_pack DISABLE TRIGGER policy_pack_immutable"))
        conn.execute(
            text(
                "UPDATE policy_pack SET content = jsonb_set(content, "
                "'{rights,ACCESS,executable}', 'true') WHERE code = 'DPDP'"
            )
        )
        conn.execute(text("ALTER TABLE policy_pack ENABLE TRIGGER policy_pack_immutable"))
    try:
        with Session(app_engine) as s:
            with pytest.raises(PackIntegrityError, match="stored content was altered"):
                PolicyRegistry().get(s, "DPDP", "1.0.0")
    finally:
        with migrator_engine.begin() as conn:
            conn.execute(text("ALTER TABLE policy_pack DISABLE TRIGGER policy_pack_immutable"))
            conn.execute(
                text(
                    "UPDATE policy_pack SET content = jsonb_set(content, "
                    "'{rights,ACCESS,executable}', 'false') WHERE code = 'DPDP'"
                )
            )
            conn.execute(text("ALTER TABLE policy_pack ENABLE TRIGGER policy_pack_immutable"))


def test_published_json_schema_is_up_to_date() -> None:
    assert SCHEMA.exists(), "run `make policy-schema`"
    assert json.loads(SCHEMA.read_text()) == json.loads(schema_json()), (
        "schema drift: run `make policy-schema`"
    )


def test_catalogue_endpoint(client: TestClient, make_tenant, provision_user, make_token) -> None:
    _, subject = provision_user(make_tenant(), ["PRIVACY_ANALYST"])
    r = client.get("/v1/policy-packs", headers=bearer(make_token(subject)))
    assert r.status_code == 200
    (dpdp,) = [p for p in r.json() if p["code"] == "DPDP"]
    assert dpdp["version"] == "1.0.0" and len(dpdp["sha256"]) == 64
    assert {x["code"] for x in dpdp["rights"] if x["executable"]} == {"ERASURE"}
    assert all(x["sla_validated"] is False for x in dpdp["rights"])


def test_catalogue_requires_a_provisioned_staff_user(client: TestClient, make_token) -> None:
    assert client.get("/v1/policy-packs").status_code == 401
    assert (
        client.get("/v1/policy-packs", headers=bearer(make_token("unknown-user"))).status_code
        == 403
    )

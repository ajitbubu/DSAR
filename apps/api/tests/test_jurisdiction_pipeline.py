"""Post-verification pipeline: identity resolution + jurisdiction decision (M2)."""

import copy
import uuid
from datetime import timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text
from sqlalchemy.orm import Session

from idprivacy.domain.intake.pipeline import process_verified_case
from idprivacy.domain.policy.jurisdiction import JurisdictionInputs, decide
from idprivacy.domain.policy.loader import LoadedPack, canonical_hash, parse, read_yaml
from idprivacy.domain.policy.registry import PolicyRegistry, PublishedPack, publish
from idprivacy.platform.db import TenantContext, tenant_session
from tests.conftest import bff, tenant_slug
from tests.test_policy_packs import DPDP_FILE
from tests.test_public_intake import SUBMIT, form


def verified_case(
    client: TestClient,
    tenant: uuid.UUID,
    *,
    rights: list[str] | None = None,
    residency: str = "IN",
    email: str | None = None,
) -> uuid.UUID:
    body = form(
        tenant_slug(tenant),
        rights=rights or ["ERASURE"],
        residencyClaim=residency,
        contact={"channel": "EMAIL", "value": email or f"{uuid.uuid4().hex[:8]}@ex.in"},
    )
    r = client.post(SUBMIT, json=body, headers=bff())
    cid = r.json()["challengeId"]
    code = client.app.state.otp_provider.peek(uuid.UUID(cid))  # type: ignore[attr-defined]
    assert (
        client.post(
            f"/v1/public/verifications/{cid}/confirm", json={"code": code}, headers=bff()
        ).status_code
        == 200
    )
    with client.app.state.app_engine.connect() as conn:  # type: ignore[attr-defined]
        conn.execute(text("SELECT set_config('app.tenant_id', :t, false)"), {"t": str(tenant)})
        rid = conn.execute(
            text("SELECT request_id FROM identity_verification WHERE id = :c"), {"c": cid}
        ).scalar_one()
        conn.execute(text("SELECT set_config('app.tenant_id', '', false)"))
    return rid  # type: ignore[no-any-return]


def run(
    client: TestClient,
    tenant: uuid.UUID,
    request_id: uuid.UUID,
    registry: PolicyRegistry | None = None,
) -> Any:
    state = client.app.state  # type: ignore[attr-defined]
    with tenant_session(state.app_engine, TenantContext(tenant)) as s:
        return process_verified_case(
            s,
            request_id=request_id,
            registry=registry or PolicyRegistry(),
            keys=state.keys,
            cipher=state.cipher,
        )


def _case(engine: Engine, request_id: uuid.UUID) -> Any:
    with engine.connect() as conn:
        return conn.execute(
            text(
                "SELECT r.status, r.workflow_code, r.due_at, p.code, p.version, d.outcome, "
                "d.rationale, d.inputs FROM privacy_request r "
                "LEFT JOIN policy_pack p ON p.id = r.policy_pack_id "
                "JOIN jurisdiction_decision d ON d.request_id = r.id WHERE r.id = :r"
            ),
            {"r": request_id},
        ).one()


def test_verification_enqueues_pipeline_with_ids_only(
    client: TestClient, make_tenant, migrator_engine: Engine
) -> None:
    tenant = make_tenant()
    rid = verified_case(client, tenant)
    with migrator_engine.connect() as conn:
        topic, payload = conn.execute(
            text("SELECT topic, payload FROM outbox WHERE tenant_id = :t"), {"t": tenant}
        ).one()
    assert topic == "case.verified" and payload == {"request_id": str(rid)}


def test_erasure_case_is_pinned_to_dpdp_and_handed_to_its_workflow(
    client: TestClient, make_tenant, migrator_engine: Engine
) -> None:
    tenant = make_tenant()
    rid = verified_case(client, tenant)
    assert run(client, tenant, rid) == "JURISDICTION_DETERMINED"
    case = _case(migrator_engine, rid)
    assert (case.status, case.code, case.version, case.workflow_code, case.outcome) == (
        "JURISDICTION_DETERMINED",
        "DPDP",
        "1.0.0",
        "erasure",
        "APPLICABLE",
    )
    assert "DPDP@1.0.0 applies (tenant_region=IN)" in case.rationale
    assert case.inputs == {
        "tenant_region": "IN",
        "requester_residency": "IN",
        "right_code": "ERASURE",
        "verification_method": "OTP_EMAIL",
    }
    assert case.due_at is None  # SLA not legally validated (D-9)


@pytest.mark.parametrize(
    "right", ["ACCESS", "CORRECTION", "CONSENT_WITHDRAWAL", "GRIEVANCE", "NOMINATION"]
)
def test_placeholder_rights_go_to_manual_handling(
    client: TestClient, make_tenant, migrator_engine: Engine, right: str
) -> None:
    tenant = make_tenant()
    rid = verified_case(client, tenant, rights=[right])
    assert run(client, tenant, rid) == "PENDING_MANUAL_HANDLING"
    case = _case(migrator_engine, rid)
    assert (case.code, case.workflow_code) == ("DPDP", "manual")
    assert "manual handling (placeholder)" in case.rationale


def test_placeholder_right_triggers_no_automation(
    client: TestClient, make_tenant, migrator_engine: Engine
) -> None:
    tenant = make_tenant()
    rid = verified_case(client, tenant, rights=["NOMINATION"])
    run(client, tenant, rid)
    with migrator_engine.connect() as conn:
        topics = (
            conn.execute(text("SELECT topic FROM outbox WHERE tenant_id = :t"), {"t": tenant})
            .scalars()
            .all()
        )
    assert topics == ["case.verified"]  # nothing further was scheduled


def test_no_enabled_pack_routes_to_manual(
    client: TestClient, make_tenant, migrator_engine: Engine
) -> None:
    tenant = make_tenant(packs=())
    rid = verified_case(client, tenant)
    assert run(client, tenant, rid) == "PENDING_MANUAL_HANDLING"
    case = _case(migrator_engine, rid)
    assert (case.outcome, case.code, case.workflow_code) == ("NO_APPLICABLE_PACK", None, None)


def test_pack_not_applicable_outside_scope(
    client: TestClient, make_tenant, migrator_engine: Engine
) -> None:
    tenant = make_tenant(region="US")
    rid = verified_case(client, tenant, residency="OTHER")
    assert run(client, tenant, rid) == "PENDING_MANUAL_HANDLING"
    assert _case(migrator_engine, rid).outcome == "NO_APPLICABLE_PACK"


def test_requester_residency_alone_can_make_pack_apply(
    client: TestClient, make_tenant, migrator_engine: Engine
) -> None:
    tenant = make_tenant(region="US")
    rid = verified_case(client, tenant, residency="IN")
    assert run(client, tenant, rid) == "JURISDICTION_DETERMINED"
    assert "requester_residency=IN" in _case(migrator_engine, rid).rationale


def test_pipeline_is_idempotent_and_skips_unverified(
    client: TestClient, make_tenant, migrator_engine: Engine
) -> None:
    tenant = make_tenant()
    rid = verified_case(client, tenant)
    assert run(client, tenant, rid) == "JURISDICTION_DETERMINED"
    assert run(client, tenant, rid) is None  # redelivered message
    assert run(client, tenant, uuid.uuid4()) is None
    with migrator_engine.connect() as conn:
        n = conn.execute(
            text("SELECT count(*) FROM jurisdiction_decision WHERE request_id = :r"), {"r": rid}
        ).scalar_one()
    assert n == 1


def test_identity_resolution_persists_canonical_set_without_plaintext(
    client: TestClient, make_tenant, migrator_engine: Engine
) -> None:
    tenant = make_tenant()
    rid = verified_case(client, tenant, email="Mixed.Case@Example.IN")
    run(client, tenant, rid)
    with migrator_engine.connect() as conn:
        rows = conn.execute(
            text(
                "SELECT type, assurance, source, row_to_json(i)::text AS dump "
                "FROM request_identifier i WHERE request_id = :r ORDER BY type"
            ),
            {"r": rid},
        ).all()
    assert [(r.type, r.assurance, r.source) for r in rows] == [
        ("CUSTOMER_ID", "CLAIMED", "FORM"),
        ("EMAIL", "VERIFIED", "OTP"),
    ]
    dump = " ".join(r.dump for r in rows).lower()
    assert "mixed.case" not in dump and "cust-1001" not in dump


def test_pipeline_is_audited(client: TestClient, make_tenant, migrator_engine: Engine) -> None:
    tenant = make_tenant()
    rid = verified_case(client, tenant)
    run(client, tenant, rid)
    with migrator_engine.connect() as conn:
        actions = conn.execute(
            text(
                "SELECT action, details FROM audit_event WHERE tenant_id = :t AND object_id = :r "
                "ORDER BY seq"
            ),
            {"t": tenant, "r": rid},
        ).all()
    names = [a.action for a in actions]
    assert names[-3:] == ["identity.resolved", "jurisdiction.decided", "case.transitioned"]
    assert actions[-2].details["policy_pack"] == "DPDP@1.0.0"


# ---------- Pure decision logic and multi-pack priority -----------------------------


def _variant(**changes: Any) -> dict[str, Any]:
    content = copy.deepcopy(read_yaml(DPDP_FILE))
    for path, value in changes.items():
        node = content
        *parents, last = path.split("__")
        for key in parents:
            node = node[key]
        node[last] = value
    return content


def _published(content: dict[str, Any]) -> PublishedPack:
    return PublishedPack(uuid.uuid4(), parse(content), canonical_hash(content))


def test_verification_method_not_accepted_goes_to_manual() -> None:
    pack = _published(_variant(rights__ERASURE__accepted_verification=["OTP_SMS"]))
    d = decide([pack], JurisdictionInputs("IN", "IN", "ERASURE", "OTP_EMAIL"))
    assert (d.outcome, d.executable, d.workflow_code) == ("APPLICABLE", False, None)
    assert "not accepted" in d.rationale


def test_first_applicable_pack_in_priority_order_wins() -> None:
    first = _published(
        _variant(code="OTHERPACK", applicability={"any_of": [{"tenant_region": ["US"]}]})
    )
    second = _published(read_yaml(DPDP_FILE))
    d = decide([first, second], JurisdictionInputs("IN", "UNKNOWN", "ERASURE", "OTP_EMAIL"))
    assert d.pack is second
    d2 = decide([first, second], JurisdictionInputs("US", "UNKNOWN", "ERASURE", "OTP_EMAIL"))
    assert d2.pack is first


def test_validated_sla_sets_due_date(
    client: TestClient, make_tenant, migrator_engine: Engine
) -> None:
    content = _variant(
        code="SLATEST",
        version="9.9.9",
        sla__ERASURE={"response_days": 30, "clock_start": "VERIFIED", "validated": True},
    )
    with Session(migrator_engine) as s, s.begin():
        publish(s, LoadedPack(parse(content), content, canonical_hash(content)))
    tenant = make_tenant(packs=(("SLATEST", "9.9.9"),))
    rid = verified_case(client, tenant)
    run(client, tenant, rid)
    with migrator_engine.connect() as conn:
        due, verified = conn.execute(
            text(
                "SELECT r.due_at, v.verified_at FROM privacy_request r "
                "JOIN identity_verification v "
                "ON v.request_id = r.id WHERE r.id = :r"
            ),
            {"r": rid},
        ).one()
    assert due == verified + timedelta(days=30)

"""Retention engine, append-only decisions, overrides, legal holds (M4)."""

import uuid
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text
from sqlalchemy.exc import DBAPIError, IntegrityError

from idprivacy.domain.policy.loader import parse, read_yaml
from idprivacy.domain.policy.registry import PolicyRegistry
from idprivacy.domain.retention import service as retention
from idprivacy.domain.retention.engine import NO_RULE, MatchFacts, evaluate
from idprivacy.platform.db import TenantContext, tenant_session
from idprivacy.platform.models import PrivacyRequest
from tests.conftest import bearer
from tests.test_discovery import case_ready_for_discovery, discover_all
from tests.test_policy_packs import DPDP_FILE

REFS = {
    "crm:contact:c-1001": "DELETE",
    "crm:invoice:i-5001": "MANUAL_REVIEW",
    "docs:file:d-3001": "DELETE",
}


def evaluate_case(client: TestClient, tenant: uuid.UUID, rid: uuid.UUID) -> dict[str, int]:
    with tenant_session(client.app.state.app_engine, TenantContext(tenant)) as s:  # type: ignore[attr-defined]
        case = s.get(PrivacyRequest, rid)
        assert case is not None
        return retention.evaluate_case(s, request=case, registry=PolicyRegistry())


@pytest.fixture
def evaluated(client: TestClient, make_tenant, connector_factory) -> tuple[uuid.UUID, uuid.UUID]:
    tenant = make_tenant()
    rid = case_ready_for_discovery(client, tenant)
    discover_all(client, tenant, rid, connector_factory)
    evaluate_case(client, tenant, rid)
    return tenant, rid


def current(engine: Engine, rid: uuid.UUID) -> dict[str, tuple[str, str, str | None]]:
    with engine.connect() as conn:
        rows = conn.execute(
            text(
                "SELECT m.source_record_ref, d.decision, d.source, d.exception_code "
                "FROM retention_decision d JOIN data_match m ON m.id = d.data_match_id "
                "WHERE d.request_id = :r AND NOT EXISTS "
                "(SELECT 1 FROM retention_decision n WHERE n.supersedes_id = d.id)"
            ),
            {"r": rid},
        ).all()
    return {r[0]: (r[1], r[2], r[3]) for r in rows}


def status_of(engine: Engine, rid: uuid.UUID) -> tuple[str, int]:
    with engine.connect() as conn:
        return tuple(
            conn.execute(
                text(
                    "SELECT status, version FROM privacy_request "  # type: ignore[return-value]
                    "WHERE id = :r"
                ),
                {"r": rid},
            ).one()
        )


def staff(
    client: TestClient, provision_user, make_token, tenant: uuid.UUID, role: str
) -> dict[str, str]:
    _, sub = provision_user(tenant, [role])
    return bearer(make_token(sub))


# ---------- Engine ----------------------------------------------------------------------


def test_every_match_gets_exactly_one_decision_from_the_pack(
    evaluated, migrator_engine: Engine
) -> None:
    _, rid = evaluated
    assert {ref: d for ref, (d, *_rest) in current(migrator_engine, rid).items()} == REFS
    assert all(src == "ENGINE" for _d, src, _c in current(migrator_engine, rid).values())
    assert status_of(migrator_engine, rid)[0] == "RETENTION_EVALUATED"


def test_evaluation_is_idempotent(client: TestClient, evaluated, migrator_engine: Engine) -> None:
    tenant, rid = evaluated
    assert evaluate_case(client, tenant, rid) == {}  # already evaluated
    with migrator_engine.connect() as conn:
        n = conn.execute(
            text("SELECT count(*) FROM retention_decision WHERE request_id = :r"), {"r": rid}
        ).scalar_one()
    assert n == 3


def _pack():  # type: ignore[no-untyped-def]
    return parse(read_yaml(DPDP_FILE))


def test_rules_are_first_match_wins() -> None:
    held = MatchFacts("crm.invoice", frozenset({"financial"}), "VERIFIED", uuid.uuid4())
    assert evaluate(_pack(), held).rule_id == "legal-hold"  # beats financial-records
    claimed = MatchFacts("crm.contact", frozenset({"contact"}), "CLAIMED", None)
    out = evaluate(_pack(), claimed)
    assert (out.decision, out.exception_code) == ("MANUAL_REVIEW", "LINK_UNCONFIRMED")


def test_no_matching_rule_fails_safe_to_manual_review() -> None:
    content = read_yaml(DPDP_FILE)
    content["retention_rules"] = [
        r for r in content["retention_rules"] if r["id"] != "default-erase"
    ]
    out = evaluate(parse(content), MatchFacts("x.y", frozenset({"contact"}), "VERIFIED", None))
    assert (out.decision, out.rule_id) == ("MANUAL_REVIEW", NO_RULE)


# ---------- Database invariants --------------------------------------------------------


def _match_id(engine: Engine, rid: uuid.UUID, ref: str) -> uuid.UUID:
    with engine.connect() as conn:
        return conn.execute(
            text(
                "SELECT id FROM data_match WHERE request_id = :r AND "  # type: ignore[no-any-return]
                "source_record_ref = :f"
            ),
            {"r": rid, "f": ref},
        ).scalar_one()


def _head(engine: Engine, rid: uuid.UUID, ref: str) -> uuid.UUID:
    mid = _match_id(engine, rid, ref)
    with engine.connect() as conn:
        return conn.execute(
            text(  # type: ignore[no-any-return]
                "SELECT id FROM retention_decision d WHERE data_match_id = :m AND NOT EXISTS "
                "(SELECT 1 FROM retention_decision n WHERE n.supersedes_id = d.id)"
            ),
            {"m": mid},
        ).scalar_one()


@pytest.mark.parametrize(
    "columns, values, constraint",
    [
        ("decision, source, supersedes_id", "'RETAIN', 'ENGINE', :head", "retain_need"),
        (
            "decision, source, exception_code, exception_reason, decided_by, supersedes_id",
            "'DELETE', 'ANALYST_OVERRIDE', 'LEGAL_OBLIGATION', 'short', gen_random_uuid(), :head",
            "override_doc",
        ),
        (
            "decision, source, decided_by, supersedes_id",
            "'DELETE', 'ENGINE', gen_random_uuid(), :head",
            "engine_unattr",
        ),
        ("decision, source", "'DELETE', 'ENGINE'", "uq_retention_decision_root"),
        (
            "decision, source, supersedes_id",
            "'DELETE', 'ENGINE', :old",
            "uq_retention_decision_supersedes",
        ),
    ],
)
def test_db_enforces_decision_invariants(
    evaluated, migrator_engine: Engine, columns: str, values: str, constraint: str
) -> None:
    """Each statement violates exactly one invariant, even for the RLS-exempt owner.

    Check-constraint names are prefixed twice by Alembic's naming convention and then
    truncated, so they're matched by a distinctive fragment.
    """
    tenant, rid = evaluated
    mid = _match_id(migrator_engine, rid, "crm:contact:c-1001")
    old = _head(migrator_engine, rid, "crm:contact:c-1001")
    with migrator_engine.begin() as conn:  # a valid second link, so :old is superseded
        conn.execute(
            text(
                "INSERT INTO retention_decision (id, tenant_id, request_id, data_match_id, "
                "decision, source, supersedes_id) VALUES (gen_random_uuid(), :t, :r, :m, "
                "'DELETE', 'ENGINE', :old)"
            ),
            {"t": tenant, "r": rid, "m": mid, "old": old},
        )
    head = _head(migrator_engine, rid, "crm:contact:c-1001")
    with pytest.raises(IntegrityError, match=constraint):
        with migrator_engine.begin() as conn:
            conn.execute(
                text(
                    f"INSERT INTO retention_decision (id, tenant_id, request_id, data_match_id, "
                    f"{columns}) VALUES (gen_random_uuid(), :t, :r, :m, {values})"
                ),
                {"t": tenant, "r": rid, "m": mid, "head": head, "old": old},
            )


@pytest.mark.parametrize(
    "stmt", ["UPDATE retention_decision SET decision = 'DELETE'", "DELETE FROM retention_decision"]
)
def test_decisions_are_append_only(
    evaluated, app_engine: Engine, migrator_engine: Engine, stmt: str
) -> None:
    tenant, rid = evaluated
    with pytest.raises(DBAPIError, match="permission denied"):
        with tenant_session(app_engine, TenantContext(tenant)) as s:
            s.execute(text(stmt))
    with pytest.raises(DBAPIError, match="append-only"):
        with migrator_engine.begin() as conn:
            conn.execute(text(stmt + " WHERE request_id = :r"), {"r": rid})


# ---------- Review workflow + overrides via the API --------------------------------------


def transition(
    client: TestClient, rid: uuid.UUID, event: str, headers: dict[str, str], migrator_engine: Engine
) -> Any:
    version = status_of(migrator_engine, rid)[1]
    return client.post(
        f"/v1/cases/{rid}/transitions",
        json={"event": event, "expected_version": version},
        headers=headers,
    )


def override(
    client: TestClient,
    rid: uuid.UUID,
    ref: str,
    headers: dict[str, str],
    engine: Engine,
    **body: Any,
) -> Any:
    payload = {
        "decision": "RETAIN",
        "exception_code": "LEGAL_OBLIGATION",
        "exception_reason": "Unpaid invoice must be kept for GST records.",
        "expected_current_id": str(_head(engine, rid, ref)),
    }
    payload.update(body)
    return client.post(
        f"/v1/cases/{rid}/matches/{_match_id(engine, rid, ref)}/retention-decisions",
        json=payload,
        headers=headers,
    )


def test_full_review_flow(
    client: TestClient, evaluated, provision_user, make_token, migrator_engine: Engine
) -> None:
    tenant, rid = evaluated
    analyst = staff(client, provision_user, make_token, tenant, "PRIVACY_ANALYST")
    invoice = "crm:invoice:i-5001"

    # Overrides aren't possible until review starts.
    assert override(client, rid, invoice, analyst, migrator_engine).status_code == 409
    assert (
        transition(client, rid, "BEGIN_REVIEW", analyst, migrator_engine).json()["status"]
        == "UNDER_REVIEW"
    )

    # The manual-review guard blocks submission.
    blocked = transition(client, rid, "SUBMIT_FOR_APPROVAL", analyst, migrator_engine)
    assert blocked.status_code == 409 and "manual-review" in blocked.json()["title"]

    r = override(client, rid, invoice, analyst, migrator_engine)
    assert r.status_code == 201 and r.json()["source"] == "ANALYST_OVERRIDE"
    assert current(migrator_engine, rid)[invoice] == (
        "RETAIN",
        "ANALYST_OVERRIDE",
        "LEGAL_OBLIGATION",
    )

    view = client.get(f"/v1/cases/{rid}/retention", headers=analyst).json()
    item = next(i for i in view["items"] if i["source_record_ref"] == invoice)
    assert [h["decision"] for h in item["history"]] == ["MANUAL_REVIEW", "RETAIN"]
    assert view["unresolved_manual_review"] == 0
    assert {c["code"] for c in view["exception_codes"]} >= {"LEGAL_OBLIGATION", "LEGAL_HOLD"}

    done = transition(client, rid, "SUBMIT_FOR_APPROVAL", analyst, migrator_engine)
    assert done.status_code == 200 and done.json()["status"] == "PENDING_APPROVAL"
    # Decisions are frozen once submitted.
    assert override(client, rid, "crm:contact:c-1001", analyst, migrator_engine).status_code == 409


@pytest.fixture
def under_review(
    client: TestClient, evaluated, provision_user, make_token, migrator_engine: Engine
) -> tuple[uuid.UUID, uuid.UUID, dict[str, str]]:
    tenant, rid = evaluated
    analyst = staff(client, provision_user, make_token, tenant, "PRIVACY_ANALYST")
    transition(client, rid, "BEGIN_REVIEW", analyst, migrator_engine)
    return tenant, rid, analyst


@pytest.mark.parametrize(
    "body, code",
    [
        ({"exception_reason": "too short"}, 422),
        ({"exception_reason": "x" * 2001}, 422),
        ({"exception_reason": "Valid length but\u0000hidden"}, 422),
        ({"exception_code": "MADE_UP"}, 409),
        ({"exception_code": "lowercase"}, 422),
        ({"decision": "SHRED"}, 422),
        ({"expected_current_id": str(uuid.uuid4())}, 409),
        ({"extra": True}, 422),
    ],
)
def test_override_validation(
    client: TestClient, under_review, migrator_engine: Engine, body: dict[str, Any], code: int
) -> None:
    _, rid, analyst = under_review
    r = override(client, rid, "crm:invoice:i-5001", analyst, migrator_engine, **body)
    assert r.status_code == code


def test_override_permissions_and_tenancy(
    client: TestClient,
    under_review,
    make_tenant,
    provision_user,
    make_token,
    migrator_engine: Engine,
) -> None:
    tenant, rid, _ = under_review
    for role in ("APPROVER", "AUDITOR", "TENANT_ADMIN"):
        headers = staff(client, provision_user, make_token, tenant, role)
        assert (
            override(client, rid, "crm:invoice:i-5001", headers, migrator_engine).status_code == 403
        )
    outsider = staff(client, provision_user, make_token, make_tenant(), "PRIVACY_ANALYST")
    assert override(client, rid, "crm:invoice:i-5001", outsider, migrator_engine).status_code == 404


def test_stale_case_version_and_role_gated_events(
    client: TestClient, under_review, provision_user, make_token, migrator_engine: Engine
) -> None:
    tenant, rid, analyst = under_review
    stale = client.post(
        f"/v1/cases/{rid}/transitions",
        json={"event": "SUBMIT_FOR_APPROVAL", "expected_version": 1},
        headers=analyst,
    )
    assert stale.status_code == 409
    approver = staff(client, provision_user, make_token, tenant, "APPROVER")
    assert transition(client, rid, "REWORK", approver, migrator_engine).status_code == 409
    assert transition(client, rid, "START_FULFILMENT", analyst, migrator_engine).status_code in (
        403,
        409,
    )


# ---------- Legal holds -------------------------------------------------------------------


def place(client: TestClient, headers: dict[str, str], **body: Any) -> Any:
    payload = {"matter_ref": "LIT-2026-014", "reason": "Pending consumer court matter."}
    payload.update(body)
    return client.post("/v1/legal-holds", json=payload, headers=headers)


def test_hold_placed_before_evaluation_forces_retain(
    client: TestClient,
    make_tenant,
    connector_factory,
    provision_user,
    make_token,
    migrator_engine: Engine,
) -> None:
    tenant = make_tenant()
    rid = case_ready_for_discovery(client, tenant)
    analyst = staff(client, provision_user, make_token, tenant, "PRIVACY_ANALYST")
    hold = place(client, analyst, scope="CASE", case_id=str(rid))
    assert hold.status_code == 201
    discover_all(client, tenant, rid, connector_factory)
    evaluate_case(client, tenant, rid)
    decisions = current(migrator_engine, rid)
    assert {d for d, *_ in decisions.values()} == {"RETAIN"}
    assert {c for *_, c in decisions.values()} == {"LEGAL_HOLD"}


def test_hold_placed_after_evaluation_supersedes_open_decisions(
    client: TestClient, under_review, migrator_engine: Engine
) -> None:
    _, rid, analyst = under_review
    r = place(client, analyst, scope="DATA_PRINCIPAL", case_id=str(rid))
    assert r.status_code == 201 and r.json()["decisions_changed"] == 3
    assert {d for d, *_ in current(migrator_engine, rid).values()} == {"RETAIN"}
    # Held records can't be overridden to anything but RETAIN.
    blocked = override(
        client, rid, "crm:contact:c-1001", analyst, migrator_engine, decision="DELETE"
    )
    assert blocked.status_code == 409 and "legal hold" in blocked.json()["title"]


@pytest.mark.parametrize(
    "scope, ref, held",
    [
        ("RECORD_TYPE", "crm.invoice", {"crm:invoice:i-5001"}),
        ("CONNECTOR", "mock-docs", {"docs:file:d-3001"}),
    ],
)
def test_scoped_holds_only_touch_their_scope(
    client: TestClient, under_review, migrator_engine: Engine, scope: str, ref: str, held: set[str]
) -> None:
    _, rid, analyst = under_review
    assert place(client, analyst, scope=scope, scope_ref=ref).status_code == 201
    retained = {
        k
        for k, (d, _s, c) in current(migrator_engine, rid).items()
        if d == "RETAIN" and c == "LEGAL_HOLD"
    }
    assert retained == held


def test_release_does_not_revert_decisions(
    client: TestClient, under_review, migrator_engine: Engine
) -> None:
    _, rid, analyst = under_review
    hold_id = place(client, analyst, scope="CASE", case_id=str(rid)).json()["id"]
    before = current(migrator_engine, rid)
    assert client.post(f"/v1/legal-holds/{hold_id}/release", headers=analyst).status_code == 200
    assert client.post(f"/v1/legal-holds/{hold_id}/release", headers=analyst).status_code == 409
    assert current(migrator_engine, rid) == before


@pytest.mark.parametrize(
    "body",
    [
        {"scope": "CASE"},  # missing case_id
        {"scope": "CASE", "case_id": str(uuid.uuid4()), "scope_ref": "x"},
        {"scope": "CONNECTOR", "scope_ref": "mock-crm", "reason": "short"},
        {"scope": "RECORD_TYPE", "scope_ref": "Not A Type"},
        {"scope": "EVERYTHING", "scope_ref": "x"},
        {"scope": "CONNECTOR", "scope_ref": "mock-crm", "matter_ref": "<script>"},
    ],
)
def test_hold_validation(
    client: TestClient, make_tenant, provision_user, make_token, body: dict[str, Any]
) -> None:
    analyst = staff(client, provision_user, make_token, make_tenant(), "PRIVACY_ANALYST")
    assert place(client, analyst, **body).status_code == 422


def test_hold_permissions_and_tenancy(
    client: TestClient, under_review, make_tenant, provision_user, make_token
) -> None:
    tenant, rid, analyst = under_review
    auditor = staff(client, provision_user, make_token, tenant, "AUDITOR")
    assert place(client, auditor, scope="CASE", case_id=str(rid)).status_code == 403
    assert client.get("/v1/legal-holds", headers=auditor).status_code == 200
    outsider = staff(client, provision_user, make_token, make_tenant(), "PRIVACY_ANALYST")
    assert place(client, outsider, scope="CASE", case_id=str(rid)).status_code == 404
    hold_id = place(client, analyst, scope="CASE", case_id=str(rid)).json()["id"]
    assert client.get("/v1/legal-holds", headers=outsider).json() == []
    assert client.post(f"/v1/legal-holds/{hold_id}/release", headers=outsider).status_code == 404

"""Completion response, closure guard, dashboard and audit timeline (M8)."""

import uuid
from typing import Any

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy import Engine, text
from sqlalchemy.exc import DBAPIError

from idprivacy.domain.communications import service as communications
from idprivacy.domain.policy.guards import GUARDS
from idprivacy.domain.policy.registry import PolicyRegistry
from idprivacy.platform.db import TenantContext, tenant_session
from idprivacy.platform.models import PrivacyRequest
from tests.conftest import bearer, bff, make_settings
from tests.test_retention import status_of


def close(
    client: TestClient,
    tenant: uuid.UUID,
    rid: uuid.UUID,
    notifier: communications.MockNotificationProvider,
) -> bool:
    state = client.app.state  # type: ignore[attr-defined]
    with tenant_session(state.app_engine, TenantContext(tenant)) as s:
        return communications.respond_and_close(
            s, request_id=rid, registry=PolicyRegistry(), cipher=state.cipher, notifier=notifier
        )


@pytest.fixture
def closed(client: TestClient, packaged) -> dict[str, Any]:
    notifier = communications.MockNotificationProvider()
    assert close(client, packaged["tenant"], packaged["rid"], notifier) is True
    return {**packaged, "notifier": notifier}


def test_completion_response_is_sent_once_and_case_closes(
    client: TestClient, closed, migrator_engine: Engine
) -> None:
    rid = closed["rid"]
    assert status_of(migrator_engine, rid)[0] == "CLOSED"
    with migrator_engine.connect() as conn:
        text_, channel, closed_at = conn.execute(
            text(
                "SELECT c.public_text, c.channel, r.closed_at FROM communication c JOIN "
                "privacy_request r ON r.id = c.request_id WHERE c.request_id = :r"
            ),
            {"r": rid},
        ).one()
    assert channel == "EMAIL" and closed_at is not None
    assert "2 records were deleted." in text_
    assert "1 record was kept: Retention is required to comply with a law in force." in text_
    assert len(closed["notifier"].sent) == 1
    assert close(client, closed["tenant"], rid, closed["notifier"]) is False  # idempotent
    assert len(closed["notifier"].sent) == 1


def test_completion_text_contains_no_personal_data(closed, migrator_engine: Engine) -> None:
    with migrator_engine.connect() as conn:
        body = (
            conn.execute(
                text("SELECT public_text FROM communication WHERE request_id = :r"),
                {"r": closed["rid"]},
            )
            .scalar_one()
            .lower()
        )
    for needle in ("priya", "sharma", "example.in", "+91", "cust-"):
        assert needle not in body


def test_requester_sees_the_completion_response(
    client: TestClient,
    make_tenant,
    connector_factory,
    provision_user,
    make_token,
    migrator_engine: Engine,
) -> None:
    """The DP tracking session created at verification shows the outcome at the end."""
    from tests.test_approvals import decide
    from tests.test_discovery import discover_all
    from tests.test_fulfilment import run_all
    from tests.test_public_intake import SUBMIT, form
    from tests.test_retention import evaluate_case, override, transition
    from tests.test_verification_evidence import generate, verify

    tenant = make_tenant()
    body = form(
        f"t-{tenant.hex[:12]}", contact={"channel": "EMAIL", "value": "priya.sharma@example.in"}
    )
    r = client.post(SUBMIT, json=body, headers=bff())
    cid = r.json()["challengeId"]
    code = client.app.state.otp_provider.peek(uuid.UUID(cid))  # type: ignore[attr-defined]
    token = client.post(
        f"/v1/public/verifications/{cid}/confirm", json={"code": code}, headers=bff()
    ).json()["sessionToken"]
    with migrator_engine.connect() as conn:
        rid = conn.execute(
            text("SELECT request_id FROM identity_verification WHERE id = :c"), {"c": cid}
        ).scalar_one()
    from tests.test_jurisdiction_pipeline import run

    run(client, tenant, rid)
    discover_all(client, tenant, rid, connector_factory)
    evaluate_case(client, tenant, rid)
    _, a = provision_user(tenant, ["PRIVACY_ANALYST"])
    _, b = provision_user(tenant, ["APPROVER"])
    analyst, approver = bearer(make_token(a)), bearer(make_token(b))
    transition(client, rid, "BEGIN_REVIEW", analyst, migrator_engine)
    override(client, rid, "crm:invoice:i-5001", analyst, migrator_engine)
    transition(client, rid, "SUBMIT_FOR_APPROVAL", analyst, migrator_engine)
    decide(client, rid, approver)
    run_all(client, tenant, rid, connector_factory)
    verify(client, tenant, rid, connector_factory)
    generate(client, tenant, rid)
    close(client, tenant, rid, communications.MockNotificationProvider())

    view = client.get("/v1/public/case", headers=bff(**{"X-DP-Session": token})).json()
    assert view["status"] == "Closed" and view["canCancel"] is False
    assert "2 records were deleted." in view["completionResponse"]


def test_closure_guard_in_the_workflow(client: TestClient, approved) -> None:
    state = client.app.state  # type: ignore[attr-defined]
    with tenant_session(state.app_engine, TenantContext(approved["tenant"])) as s:
        case = s.get(PrivacyRequest, approved["rid"])
        assert case is not None
        result = GUARDS["all_fulfilment_tasks_terminal"](s, case)
    assert result.ok is False and "still running" in result.reason


@pytest.mark.parametrize("role", ["migrator", "app"])
def test_database_refuses_to_close_with_open_tasks(
    approved, migrator_engine: Engine, app_engine: Engine, role: str
) -> None:
    with pytest.raises(DBAPIError, match="non-terminal fulfilment tasks"):
        if role == "migrator":
            with migrator_engine.begin() as conn:
                conn.execute(
                    text("UPDATE privacy_request SET status = 'CLOSED' WHERE id = :r"),
                    {"r": approved["rid"]},
                )
        else:
            with tenant_session(app_engine, TenantContext(approved["tenant"])) as s:
                s.execute(
                    text("UPDATE privacy_request SET status = 'CLOSED' WHERE id = :r"),
                    {"r": approved["rid"]},
                )


def test_mock_notifier_refused_outside_dev() -> None:
    with pytest.raises(ValidationError, match="mock notification provider"):
        make_settings(env="production")
    unsafe = make_settings().model_copy(update={"env": "production"})
    with pytest.raises(RuntimeError):
        communications.build_notifier(unsafe)


def test_dashboard_summary_and_sla_states(
    client: TestClient, closed, provision_user, make_token, make_tenant
) -> None:
    from tests.test_jurisdiction_pipeline import run, verified_case

    tenant = closed["tenant"]
    open_case = verified_case(client, tenant)
    run(client, tenant, open_case)
    _, a = provision_user(tenant, ["AUDITOR"])
    headers = bearer(make_token(a))
    summary = client.get("/v1/dashboard/summary", headers=headers).json()
    assert summary["by_status"].get("CLOSED") == 1
    assert summary["by_sla"].get("DONE", 0) >= 1 and summary["by_sla"].get("UNVALIDATED", 0) >= 1
    states = {
        c["id"]: c["sla_state"] for c in client.get("/v1/cases", headers=headers).json()["items"]
    }
    assert states[str(closed["rid"])] == "DONE"
    assert states[str(open_case)] == "UNVALIDATED"  # DPDP deadlines not legally validated
    _, admin = provision_user(tenant, ["TENANT_ADMIN"])
    assert client.get("/v1/dashboard/summary", headers=bearer(make_token(admin))).status_code == 403
    _, other = provision_user(make_tenant(), ["AUDITOR"])
    other_summary = client.get("/v1/dashboard/summary", headers=bearer(make_token(other))).json()
    assert other_summary["by_status"] == {}


def test_case_audit_timeline(
    client: TestClient, closed, provision_user, make_token, make_tenant
) -> None:
    _, a = provision_user(closed["tenant"], ["AUDITOR"])
    events = client.get(
        f"/v1/cases/{closed['rid']}/audit-events", headers=bearer(make_token(a))
    ).json()
    actions = [e["action"] for e in events]
    for expected in (
        "request.submitted",
        "identity.verified",
        "jurisdiction.decided",
        "retention.evaluated",
        "retention.overridden",
        "approval.approved",
        "fulfilment.action_applied",
        "verification.completed",
        "evidence.package_generated",
        "communication.sent",
    ):
        assert expected in actions, expected
    assert [e["seq"] for e in events] == sorted(e["seq"] for e in events)
    _, other = provision_user(make_tenant(), ["AUDITOR"])
    assert (
        client.get(
            f"/v1/cases/{closed['rid']}/audit-events", headers=bearer(make_token(other))
        ).status_code
        == 404
    )

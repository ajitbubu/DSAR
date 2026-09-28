"""Fulfilment orchestration: idempotent destructive actions (M6; threat model T-12)."""

import uuid
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text
from sqlalchemy.exc import DBAPIError

from idprivacy.domain.fulfilment import service as fulfilment
from idprivacy.domain.policy.registry import PolicyRegistry
from idprivacy.platform.db import TenantContext, tenant_session
from tests.test_retention import status_of

MAX = 5


def tasks(engine: Engine, rid: uuid.UUID) -> dict[str, Any]:
    with engine.connect() as conn:
        rows = (
            conn.execute(
                text(
                    "SELECT m.source_record_ref AS ref, t.* FROM fulfilment_task t "
                    "JOIN data_match m "
                    "ON m.id = t.data_match_id WHERE t.request_id = :r"
                ),
                {"r": rid},
            )
            .mappings()
            .all()
        )
    return {r["ref"]: r for r in rows}


def effects(mock: TestClient, ref: str | None = None) -> list[dict[str, Any]]:
    calls = mock.get("/__test__/calls").json()
    return [c for c in calls if c["op"] == "effect" and (ref is None or c["ref"] == ref)]


def dispatch(
    client: TestClient, tenant: uuid.UUID, task_id: uuid.UUID, factory: Any
) -> fulfilment.DispatchResult:
    return fulfilment.dispatch(
        client.app.state.app_engine,
        tenant_id=tenant,  # type: ignore[attr-defined]
        task_id=task_id,
        factory=factory,
        max_attempts=MAX,
    )


def run_all(client: TestClient, tenant: uuid.UUID, rid: uuid.UUID, factory: Any) -> None:
    engine = client.app.state.app_engine  # type: ignore[attr-defined]
    for _ in range(MAX + 1):
        with tenant_session(engine, TenantContext(tenant)) as s:
            open_ = fulfilment.pending_tasks(s, rid)
        if not open_:
            break
        for task_id in open_:
            dispatch(client, tenant, task_id, factory)
    with tenant_session(engine, TenantContext(tenant)) as s:
        fulfilment.finish_if_complete(s, request_id=rid, registry=PolicyRegistry())


def executions(engine: Engine, task_id: uuid.UUID, op: str = "execute_action") -> list[Any]:
    with engine.connect() as conn:
        return (
            conn.execute(
                text(  # type: ignore[return-value]
                    "SELECT * FROM connector_execution "
                    "WHERE fulfilment_task_id = :t AND operation = :o "
                    "ORDER BY attempt_no"
                ),
                {"t": task_id, "o": op},
            )
            .mappings()
            .all()
        )


def test_approval_plans_one_task_per_decision(
    approved, migrator_engine: Engine, mock_connectors: TestClient
) -> None:
    rid = approved["rid"]
    t = tasks(migrator_engine, rid)
    assert {k: (v["action"], v["status"]) for k, v in t.items()} == {
        "crm:contact:c-1001": ("DELETE", "PENDING"),
        "crm:invoice:i-5001": ("NOOP_RETAIN", "SKIPPED"),
        "docs:file:d-3001": ("DELETE", "PENDING"),
    }
    assert t["crm:invoice:i-5001"]["skip_reason"] == "RETAIN: LEGAL_OBLIGATION"
    assert len({v["idempotency_key"] for v in t.values()}) == 3
    assert status_of(migrator_engine, rid)[0] == "FULFILMENT_IN_PROGRESS"


def test_fulfilment_applies_each_action_once_and_captures_evidence(
    client: TestClient,
    approved,
    connector_factory,
    mock_connectors: TestClient,
    migrator_engine: Engine,
) -> None:
    tenant, rid = approved["tenant"], approved["rid"]
    run_all(client, tenant, rid, connector_factory)
    t = tasks(migrator_engine, rid)
    assert {k: v["status"] for k, v in t.items()} == {
        "crm:contact:c-1001": "SUCCEEDED",
        "crm:invoice:i-5001": "SKIPPED",
        "docs:file:d-3001": "SUCCEEDED",
    }
    assert sorted(e["ref"] for e in effects(mock_connectors)) == [
        "crm:contact:c-1001",
        "docs:file:d-3001",
    ]
    assert not effects(mock_connectors, "crm:invoice:i-5001")  # RETAIN: no connector call
    for ref in ("crm:contact:c-1001", "docs:file:d-3001"):
        (ev,) = executions(migrator_engine, t[ref]["id"], "get_evidence")
        assert ev["outcome"] == "SUCCEEDED" and len(ev["evidence_sha256"]) == 64
        assert ev["evidence"]["receipt_id"] == t[ref]["receipt_id"]
    assert status_of(migrator_engine, rid)[0] == "VERIFICATION_IN_PROGRESS"


def test_five_concurrent_dispatches_apply_once(
    client: TestClient,
    approved,
    connector_factory,
    mock_connectors: TestClient,
    migrator_engine: Engine,
) -> None:
    tenant, rid = approved["tenant"], approved["rid"]
    task_id = tasks(migrator_engine, rid)["crm:contact:c-1001"]["id"]
    with ThreadPoolExecutor(max_workers=5) as pool:
        list(pool.map(lambda _: dispatch(client, tenant, task_id, connector_factory), range(5)))
    for _ in range(3):  # drain any dispatches that found the row locked
        dispatch(client, tenant, task_id, connector_factory)
    assert len(effects(mock_connectors, "crm:contact:c-1001")) == 1
    assert tasks(migrator_engine, rid)["crm:contact:c-1001"]["status"] == "SUCCEEDED"


def test_two_503s_then_success_with_the_same_key(
    client: TestClient,
    approved,
    connector_factory,
    mock_connectors: TestClient,
    migrator_engine: Engine,
) -> None:
    tenant, rid = approved["tenant"], approved["rid"]
    mock_connectors.post(
        "/__test__/faults",
        json={"account": "acme", "system": "docs", "fail_next": 2, "status": 503},
    )
    task = tasks(migrator_engine, rid)["docs:file:d-3001"]
    results = [dispatch(client, tenant, task["id"], connector_factory).status for _ in range(3)]
    assert results == ["FAILED_RETRYABLE", "FAILED_RETRYABLE", "SUCCEEDED"]
    rows = executions(migrator_engine, task["id"])
    assert [(r["attempt_no"], r["outcome"]) for r in rows] == [
        (1, "FAILED_RETRYABLE"),
        (2, "FAILED_RETRYABLE"),
        (3, "SUCCEEDED"),
    ]
    assert {r["idempotency_key"] for r in rows} == {task["idempotency_key"]}
    assert len(effects(mock_connectors, "docs:file:d-3001")) == 1


def test_timeout_after_apply_is_retried_without_a_second_effect(
    client: TestClient,
    approved,
    connector_factory,
    mock_connectors: TestClient,
    migrator_engine: Engine,
) -> None:
    tenant, rid = approved["tenant"], approved["rid"]
    mock_connectors.post(
        "/__test__/faults",
        json={
            "account": "acme",
            "system": "crm",
            "fail_next": 1,
            "status": 504,
            "apply_before_failing": True,
        },
    )
    task = tasks(migrator_engine, rid)["crm:contact:c-1001"]
    assert dispatch(client, tenant, task["id"], connector_factory).status == "FAILED_RETRYABLE"
    assert len(effects(mock_connectors, "crm:contact:c-1001")) == 1  # it did apply
    assert dispatch(client, tenant, task["id"], connector_factory).status == "SUCCEEDED"
    last = executions(migrator_engine, task["id"])[-1]
    assert last["replayed"] is True
    assert len(effects(mock_connectors, "crm:contact:c-1001")) == 1


def test_worker_crash_mid_dispatch_resumes_without_duplication(
    client: TestClient,
    approved,
    connector_factory,
    mock_connectors: TestClient,
    migrator_engine: Engine,
) -> None:
    tenant, rid = approved["tenant"], approved["rid"]

    class DiesAfterCall:
        def __init__(self, inner: Any) -> None:
            self.inner = inner

        def execute_action(self, req: Any) -> Any:
            self.inner.execute_action(req)
            raise SystemExit("worker killed")  # not a ConnectorError: nothing is recorded

    task = tasks(migrator_engine, rid)["docs:file:d-3001"]
    with pytest.raises(SystemExit):
        dispatch(client, tenant, task["id"], lambda cfg: DiesAfterCall(connector_factory(cfg)))
    assert tasks(migrator_engine, rid)["docs:file:d-3001"]["status"] == "DISPATCHED"
    assert dispatch(client, tenant, task["id"], connector_factory).status == "SUCCEEDED"
    assert executions(migrator_engine, task["id"])[-1]["replayed"] is True
    assert len(effects(mock_connectors, "docs:file:d-3001")) == 1


def test_persistent_failures_stop_after_max_attempts(
    client: TestClient,
    approved,
    connector_factory,
    mock_connectors: TestClient,
    migrator_engine: Engine,
) -> None:
    tenant, rid = approved["tenant"], approved["rid"]
    mock_connectors.post(
        "/__test__/faults",
        json={"account": "acme", "system": "docs", "fail_next": 50, "status": 503},
    )
    run_all(client, tenant, rid, connector_factory)
    task = tasks(migrator_engine, rid)["docs:file:d-3001"]
    assert (task["status"], task["attempt_count"]) == ("FAILED_FINAL", MAX)
    assert len(executions(migrator_engine, task["id"])) == MAX
    # FAILED_FINAL is terminal: the case moves on, and M7's independent rescan will find
    # the record still present and send it to reconciliation. It can't close as done.
    assert status_of(migrator_engine, rid)[0] == "VERIFICATION_IN_PROGRESS"


def test_legal_hold_after_approval_skips_the_action(
    client: TestClient,
    approved,
    connector_factory,
    mock_connectors: TestClient,
    migrator_engine: Engine,
) -> None:
    tenant, rid = approved["tenant"], approved["rid"]
    r = client.post(
        "/v1/legal-holds",
        json={
            "scope": "RECORD_TYPE",
            "scope_ref": "docs.file",
            "matter_ref": "LIT-77",
            "reason": "Arrived after approval.",
        },
        headers=approved["analyst"],
    )
    assert r.status_code == 201
    run_all(client, tenant, rid, connector_factory)
    task = tasks(migrator_engine, rid)["docs:file:d-3001"]
    assert (task["status"], task["skip_reason"]) == ("SKIPPED", "LEGAL_HOLD: LIT-77")
    assert not effects(mock_connectors, "docs:file:d-3001")
    assert len(effects(mock_connectors, "crm:contact:c-1001")) == 1


def test_manual_retry_of_a_failed_task(
    client: TestClient,
    approved,
    connector_factory,
    mock_connectors: TestClient,
    provision_user,
    make_token,
    migrator_engine: Engine,
) -> None:
    from tests.conftest import bearer

    tenant, rid = approved["tenant"], approved["rid"]
    mock_connectors.post(
        "/__test__/faults",
        json={"account": "acme", "system": "docs", "fail_next": 1, "status": 400},
    )
    task = tasks(migrator_engine, rid)["docs:file:d-3001"]
    # Only the docs task runs, so the CRM task keeps the case in FULFILMENT_IN_PROGRESS.
    assert dispatch(client, tenant, task["id"], connector_factory).status == "FAILED_FINAL"
    url = f"/v1/cases/{rid}/fulfilment-tasks/{task['id']}/retry"
    _, auditor = provision_user(tenant, ["AUDITOR"])
    assert client.post(url, headers=bearer(make_token(auditor))).status_code == 403
    assert client.post(url, headers=approved["analyst"]).status_code == 202
    run_all(client, tenant, rid, connector_factory)
    t = tasks(migrator_engine, rid)["docs:file:d-3001"]
    assert (t["status"], t["idempotency_key"]) == ("SUCCEEDED", task["idempotency_key"])
    assert client.post(url, headers=approved["analyst"]).status_code == 409
    assert status_of(migrator_engine, rid)[0] == "VERIFICATION_IN_PROGRESS"


def test_fulfilment_view_and_tenancy(
    client: TestClient, approved, connector_factory, make_tenant, provision_user, make_token
) -> None:
    from tests.conftest import bearer

    tenant, rid = approved["tenant"], approved["rid"]
    run_all(client, tenant, rid, connector_factory)
    view = client.get(f"/v1/cases/{rid}/fulfilment-tasks", headers=approved["analyst"]).json()
    assert view["counts"] == {"SUCCEEDED": 2, "SKIPPED": 1}
    deleted = [t for t in view["tasks"] if t["action"] == "DELETE"]
    assert all(t["receipt_id"] and len(t["executions"]) == 2 for t in deleted)
    _, other = provision_user(make_tenant(), ["PRIVACY_ANALYST"])
    assert (
        client.get(
            f"/v1/cases/{rid}/fulfilment-tasks", headers=bearer(make_token(other))
        ).status_code
        == 404
    )


def test_connector_executions_are_append_only(
    client: TestClient, approved, connector_factory, migrator_engine: Engine
) -> None:
    run_all(client, approved["tenant"], approved["rid"], connector_factory)
    with pytest.raises(DBAPIError, match="append-only"):
        with migrator_engine.begin() as conn:
            conn.execute(text("UPDATE connector_execution SET outcome = 'FAILED_FINAL'"))

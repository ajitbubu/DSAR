"""Discovery via the connector SDK against the mock CRM and document store (M3)."""

import uuid
from collections.abc import Callable
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from idprivacy_connector_sdk import HttpConnector
from sqlalchemy import Engine, text

from idprivacy.domain.discovery import service as discovery
from idprivacy.domain.policy.registry import PolicyRegistry
from idprivacy.platform.db import TenantContext, tenant_session
from tests.conftest import bearer
from tests.test_jurisdiction_pipeline import run, verified_case
from tests.test_public_intake import SUBMIT, form

PRIYA = "priya.sharma@example.in"


def discover_all(
    client: TestClient, tenant: uuid.UUID, rid: uuid.UUID, factory: Callable[..., Any]
) -> list[discovery.JobOutcome]:
    state = client.app.state  # type: ignore[attr-defined]
    registry = PolicyRegistry()
    with tenant_session(state.app_engine, TenantContext(tenant)) as s:
        job_ids = discovery.start(s, request_id=rid, registry=registry)
    outcomes = [
        discovery.run_job(
            state.app_engine,
            tenant_id=tenant,
            job_id=j,
            factory=factory,
            registry=registry,
            cipher=state.cipher,
        )
        for j in job_ids
    ]
    with tenant_session(state.app_engine, TenantContext(tenant)) as s:
        discovery.finish_if_complete(s, request_id=rid, registry=registry)
    return outcomes


def case_ready_for_discovery(
    client: TestClient,
    tenant: uuid.UUID,
    *,
    channel: str = "EMAIL",
    value: str = PRIYA,
    customer_id: str = "CUST-2002",
) -> uuid.UUID:
    """A verified erasure case. The typed customer ID belongs to *someone else*."""
    body = form(
        "",
        contact={"channel": channel, "value": value},
        additionalIdentifiers=[{"type": "CUSTOMER_ID", "value": customer_id}],
    )
    rid = _verified_with(client, tenant, body)
    assert run(client, tenant, rid) == "JURISDICTION_DETERMINED"
    return rid


def _verified_with(client: TestClient, tenant: uuid.UUID, body: dict[str, Any]) -> uuid.UUID:
    from tests.conftest import bff, tenant_slug

    body = {**body, "intakeSlug": tenant_slug(tenant)}
    r = client.post(SUBMIT, json=body, headers=bff(ip=f"198.18.{uuid.uuid4().int % 250}.1"))
    assert r.status_code == 202, r.text
    cid = r.json()["challengeId"]
    code = client.app.state.otp_provider.peek(uuid.UUID(cid))  # type: ignore[attr-defined]
    client.post(f"/v1/public/verifications/{cid}/confirm", json={"code": code}, headers=bff())
    with client.app.state.app_engine.begin() as conn:  # type: ignore[attr-defined]
        conn.execute(text("SELECT set_config('app.tenant_id', :t, true)"), {"t": str(tenant)})
        return conn.execute(
            text("SELECT request_id FROM identity_verification WHERE id = :c"), {"c": cid}
        ).scalar_one()  # type: ignore[no-any-return]


def matches(engine: Engine, rid: uuid.UUID) -> dict[str, set[str]]:
    with engine.connect() as conn:
        rows = conn.execute(
            text("SELECT connector_id, source_record_ref FROM data_match WHERE request_id = :r"),
            {"r": rid},
        ).all()
    out: dict[str, set[str]] = {}
    for connector, ref in rows:
        out.setdefault(connector, set()).add(ref)
    return out


def case_status(engine: Engine, rid: uuid.UUID) -> str:
    with engine.connect() as conn:
        return conn.execute(
            text("SELECT status FROM privacy_request WHERE id = :r"),  # type: ignore[no-any-return]
            {"r": rid},
        ).scalar_one()


def test_discovery_finds_source_wise_matches_for_verified_email(
    client: TestClient, make_tenant, connector_factory, migrator_engine: Engine
) -> None:
    tenant = make_tenant()
    rid = case_ready_for_discovery(client, tenant)
    outcomes = discover_all(client, tenant, rid, connector_factory)
    assert [o.status for o in outcomes] == ["SUCCEEDED", "SUCCEEDED"]
    assert matches(migrator_engine, rid) == {
        "mock-crm": {"crm:contact:c-1001", "crm:invoice:i-5001"},
        "mock-docs": {"docs:file:d-3001"},
    }
    assert case_status(migrator_engine, rid) == "DISCOVERY_COMPLETE"


def test_claimed_customer_id_is_never_used_for_discovery(
    client: TestClient, make_tenant, connector_factory, migrator_engine: Engine
) -> None:
    """The requester typed CUST-2002 (someone else's). It must not pull in their record."""
    tenant = make_tenant()
    rid = case_ready_for_discovery(client, tenant, customer_id="CUST-2002")
    discover_all(client, tenant, rid, connector_factory)
    found = set().union(*matches(migrator_engine, rid).values())
    assert "crm:contact:c-2002" not in found


def test_only_verified_identifiers_are_sent_to_connectors(
    client: TestClient, make_tenant, connector_factory
) -> None:
    sent: list[list[tuple[str, str]]] = []

    class Spy:
        def __init__(self, inner: Any) -> None:
            self.inner = inner

        def discover(self, req: Any) -> Any:
            sent.append([(i.type.value, i.value) for i in req.identifiers])
            return self.inner.discover(req)

    tenant = make_tenant()
    rid = case_ready_for_discovery(client, tenant)
    discover_all(client, tenant, rid, lambda cfg: Spy(connector_factory(cfg)))
    assert sent and all(ids == [("EMAIL", PRIYA)] for ids in sent)


def test_sms_verified_case_matches_on_phone(
    client: TestClient, make_tenant, connector_factory, migrator_engine: Engine
) -> None:
    tenant = make_tenant()
    rid = case_ready_for_discovery(client, tenant, channel="SMS", value="+919876543210")
    discover_all(client, tenant, rid, connector_factory)
    assert matches(migrator_engine, rid) == {
        "mock-crm": {"crm:contact:c-1001", "crm:ticket:t-7001"},
        "mock-docs": {"docs:file:d-3002"},
    }


def test_matches_store_pointers_not_personal_data(
    client: TestClient, make_tenant, connector_factory, migrator_engine: Engine
) -> None:
    tenant = make_tenant()
    rid = case_ready_for_discovery(client, tenant)
    discover_all(client, tenant, rid, connector_factory)
    with migrator_engine.connect() as conn:
        dump = " ".join(
            conn.execute(
                text("SELECT row_to_json(m)::text FROM data_match m WHERE request_id = :r"),
                {"r": rid},
            ).scalars()
        ).lower()
    for needle in ("priya", "sharma", "example.in", "+91", "pune", "complaint", "4999"):
        assert needle not in dump, needle


def test_accounts_stay_separate(
    client: TestClient, make_tenant, connector_factory, migrator_engine: Engine
) -> None:
    acme, globex = make_tenant(account="acme"), make_tenant(account="globex")
    rid_a = case_ready_for_discovery(client, acme)
    rid_g = case_ready_for_discovery(client, globex)
    discover_all(client, acme, rid_a, connector_factory)
    discover_all(client, globex, rid_g, connector_factory)
    assert matches(migrator_engine, rid_g) == {
        "mock-crm": {"crm:contact:g-1001"},
        "mock-docs": {"docs:file:g-3001"},
    }
    assert (
        set()
        .union(*matches(migrator_engine, rid_a).values())
        .isdisjoint(set().union(*matches(migrator_engine, rid_g).values()))
    )


def test_rerunning_discovery_is_idempotent(
    client: TestClient, make_tenant, connector_factory, migrator_engine: Engine
) -> None:
    tenant = make_tenant()
    rid = case_ready_for_discovery(client, tenant)
    discover_all(client, tenant, rid, connector_factory)
    state = client.app.state  # type: ignore[attr-defined]
    with tenant_session(state.app_engine, TenantContext(tenant)) as s:
        assert discovery.start(s, request_id=rid, registry=PolicyRegistry()) == []
    with migrator_engine.connect() as conn:
        jobs, rows = conn.execute(
            text(
                "SELECT (SELECT count(*) FROM discovery_job WHERE request_id = :r), "
                "(SELECT count(*) FROM data_match WHERE request_id = :r)"
            ),
            {"r": rid},
        ).one()
    assert (jobs, rows) == (2, 3)


def test_retryable_failure_then_success(
    client: TestClient,
    make_tenant,
    connector_factory,
    mock_connectors: TestClient,
    migrator_engine: Engine,
) -> None:
    tenant = make_tenant()
    rid = case_ready_for_discovery(client, tenant)
    mock_connectors.post(
        "/__test__/faults",
        json={"account": "acme", "system": "docs", "fail_next": 1, "status": 503},
    )
    outcomes = discover_all(client, tenant, rid, connector_factory)
    assert sorted((o.status, o.error_code, o.retryable) for o in outcomes) == [
        ("FAILED", "http_503", True),
        ("SUCCEEDED", None, False),
    ]
    assert case_status(migrator_engine, rid) == "DISCOVERY_IN_PROGRESS"  # not finished

    with tenant_session(client.app.state.app_engine, TenantContext(tenant)) as s:  # type: ignore[attr-defined]
        assert discovery.retry_failed(s, request_id=rid) == 1
    outcomes = discover_all(client, tenant, rid, connector_factory)
    assert [o.status for o in outcomes] == ["SUCCEEDED"]  # only the failed source reran
    assert case_status(migrator_engine, rid) == "DISCOVERY_COMPLETE"


def test_automatic_retries_stop_at_the_attempt_cap_and_the_failure_stays_visible(
    client: TestClient,
    make_tenant,
    connector_factory,
    mock_connectors: TestClient,
    migrator_engine: Engine,
) -> None:
    # Regression: retry_failed reset every FAILED job to PENDING before each automatic
    # retry, so once Celery gave up the job showed "pending" with no error, forever.
    # Found by /engineering:testing-strategy on 2026-10-02.
    tenant = make_tenant()
    rid = case_ready_for_discovery(client, tenant)
    mock_connectors.post(
        "/__test__/faults",
        json={"account": "acme", "system": "docs", "fail_next": 10, "status": 503},
    )
    app_engine = client.app.state.app_engine  # type: ignore[attr-defined]
    for attempt in range(1, 4):
        discover_all(client, tenant, rid, connector_factory)
        with tenant_session(app_engine, TenantContext(tenant)) as s:
            reset = discovery.retry_failed(s, request_id=rid, max_attempts=3)
        assert reset == (1 if attempt < 3 else 0), attempt

    status, code, attempts = (
        migrator_engine.connect()
        .execute(
            text(
                "SELECT j.status, j.error_code, j.attempts FROM discovery_job j "
                "JOIN connector_config c ON c.id = j.connector_config_id "
                "WHERE j.request_id = :r AND c.connector_id = 'mock-docs'"
            ),
            {"r": rid},
        )
        .one()
    )
    assert (status, code, attempts) == ("FAILED", "http_503", 3)  # staff can see why
    assert case_status(migrator_engine, rid) == "DISCOVERY_IN_PROGRESS"

    # A staff retry is a deliberate override: it is not capped.
    with tenant_session(app_engine, TenantContext(tenant)) as s:
        assert discovery.retry_failed(s, request_id=rid) == 1


def _hostile(payload: bytes, status: int = 200) -> Callable[..., Any]:
    transport = httpx.MockTransport(lambda _r: httpx.Response(status, content=payload))
    return lambda cfg: HttpConnector(cfg.base_url, "tok", client=httpx.Client(transport=transport))


@pytest.mark.parametrize(
    "payload, code",
    [
        (b'{"matches": [{"source_record_ref": "x"}]}', "invalid_response"),
        (b'{"matches": [], "extra": "field"}', "invalid_response"),
        (b"not json", "invalid_response"),
        (b'{"matches": [' + b'{"a":1},' * 40_000 + b'{"a":1}]}', "response_too_large"),
        (
            b'{"matches": [{"source_record_ref": "crm:1", "record_type": "crm.contact",'
            b'"data_categories": ["contact"], "matched_on": ["EMAIL"],'
            b'"content_fingerprint": "' + b"a" * 64 + b'",'
            b'"attributes": {"note": "priya.sharma@example.in"}}]}',
            "invalid_response",
        ),
    ],
)
def test_malformed_or_hostile_connector_responses_are_rejected(
    client: TestClient, make_tenant, migrator_engine: Engine, payload: bytes, code: str
) -> None:
    tenant = make_tenant()
    rid = case_ready_for_discovery(client, tenant)
    outcomes = discover_all(client, tenant, rid, _hostile(payload))
    assert {(o.status, o.error_code, o.retryable) for o in outcomes} == {("FAILED", code, False)}
    assert matches(migrator_engine, rid) == {}  # nothing partial stored


# ---------- Staff APIs ---------------------------------------------------------------


@pytest.fixture
def discovered(client: TestClient, make_tenant, connector_factory) -> tuple[uuid.UUID, uuid.UUID]:
    tenant = make_tenant()
    rid = case_ready_for_discovery(client, tenant)
    discover_all(client, tenant, rid, connector_factory)
    return tenant, rid


def test_discovery_view_is_source_wise(
    client: TestClient, discovered, provision_user, make_token
) -> None:
    tenant, rid = discovered
    _, sub = provision_user(tenant, ["PRIVACY_ANALYST"])
    r = client.get(f"/v1/cases/{rid}/discovery", headers=bearer(make_token(sub)))
    assert r.status_code == 200
    body = r.json()
    assert body["case_status"] == "DISCOVERY_COMPLETE" and body["total_matches"] == 3
    by_source = {
        s["connector_id"]: [m["source_record_ref"] for m in s["matches"]] for s in body["sources"]
    }
    assert by_source == {
        "mock-crm": ["crm:contact:c-1001", "crm:invoice:i-5001"],
        "mock-docs": ["docs:file:d-3001"],
    }
    invoice = next(
        m for s in body["sources"] for m in s["matches"] if m["record_type"] == "crm.invoice"
    )
    assert invoice["data_categories"] == ["financial"]
    assert invoice["attributes"]["has_open_invoice"] is True


def test_case_detail_masks_identifiers(
    client: TestClient, discovered, provision_user, make_token
) -> None:
    tenant, rid = discovered
    _, sub = provision_user(tenant, ["AUDITOR"])
    r = client.get(f"/v1/cases/{rid}", headers=bearer(make_token(sub)))
    assert r.status_code == 200
    body = r.json()
    assert "priya" not in r.text.lower()
    assert {(i["type"], i["assurance"], i["masked"]) for i in body["identifiers"]} == {
        ("EMAIL", "VERIFIED", "p•••@e•••.in"),
        ("CUSTOMER_ID", "CLAIMED", "•••••••02"),
    }
    assert body["policy_pack"] == "DPDP@1.0.0"
    assert body["jurisdiction"]["outcome"] == "APPLICABLE"


def test_case_reads_are_audited(
    client: TestClient, discovered, provision_user, make_token, migrator_engine: Engine
) -> None:
    tenant, rid = discovered
    user, sub = provision_user(tenant, ["PRIVACY_ANALYST"])
    client.get(f"/v1/cases/{rid}/discovery", headers=bearer(make_token(sub)))
    with migrator_engine.connect() as conn:
        actor = conn.execute(
            text(
                "SELECT actor_ref FROM audit_event WHERE object_id = :r AND action = 'case.viewed'"
            ),
            {"r": rid},
        ).scalar_one()
    assert actor == str(user)


@pytest.mark.parametrize("path", ["", "/discovery"])
def test_case_apis_block_other_tenants_and_admins(
    client: TestClient, discovered, make_tenant, provision_user, make_token, path: str
) -> None:
    tenant, rid = discovered
    _, other = provision_user(make_tenant(), ["PRIVACY_ANALYST"])
    _, admin = provision_user(tenant, ["TENANT_ADMIN"])
    url = f"/v1/cases/{rid}{path}"
    assert client.get(url).status_code == 401
    assert client.get(url, headers=bearer(make_token(other))).status_code == 404  # not 403
    assert client.get(url, headers=bearer(make_token(admin))).status_code == 403
    assert (
        client.get(f"/v1/cases/{uuid.uuid4()}{path}", headers=bearer(make_token(other))).status_code
        == 404
    )


def test_case_list_is_tenant_scoped_and_paginated(
    client: TestClient, make_tenant, provision_user, make_token
) -> None:
    tenant = make_tenant()
    ids = {str(verified_case(client, tenant)) for _ in range(3)}
    other = make_tenant()
    verified_case(client, other)
    _, sub = provision_user(tenant, ["APPROVER"])
    token = make_token(sub)
    first = client.get("/v1/cases", params={"limit": 2}, headers=bearer(token)).json()
    assert len(first["items"]) == 2 and first["next_cursor"]
    second = client.get(
        "/v1/cases", params={"limit": 2, "cursor": first["next_cursor"]}, headers=bearer(token)
    ).json()
    seen = {c["id"] for c in first["items"] + second["items"]}
    assert seen == ids and second["next_cursor"] is None
    assert (
        client.get("/v1/cases", params={"cursor": "garbage!"}, headers=bearer(token)).status_code
        == 422
    )
    assert client.get("/v1/cases", params={"limit": 1000}, headers=bearer(token)).status_code == 422


def test_retry_requires_failed_sources_and_reviewer(
    client: TestClient, discovered, provision_user, make_token
) -> None:
    tenant, rid = discovered
    _, analyst = provision_user(tenant, ["PRIVACY_ANALYST"])
    _, auditor = provision_user(tenant, ["AUDITOR"])
    url = f"/v1/cases/{rid}/discovery/retry"
    assert client.post(url, headers=bearer(make_token(auditor))).status_code == 403
    assert client.post(url, headers=bearer(make_token(analyst))).status_code == 409

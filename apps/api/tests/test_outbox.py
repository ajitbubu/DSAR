"""Transactional outbox (ADR-0005)."""

import uuid

import pytest
from sqlalchemy import Engine, text
from sqlalchemy.exc import DBAPIError

from idprivacy.platform.db import TenantContext, tenant_session
from idprivacy.platform.outbox import Envelope, UnsafePayloadError, enqueue, relay_once


@pytest.mark.parametrize(
    "payload",
    [
        {"email": "priya@example.in"},
        {"request_id": "priya@example.in"},
        {"request_id": {"nested": "x"}},
        {"request_id": True},
        {f"k{i}_id": str(uuid.uuid4()) for i in range(17)},
    ],
)
def test_enqueue_rejects_non_identifier_payloads(app_engine: Engine, make_tenant, payload) -> None:
    tenant = make_tenant()
    with pytest.raises(UnsafePayloadError):
        with tenant_session(app_engine, TenantContext(tenant)) as s:
            enqueue(s, tenant_id=tenant, topic="system.noop", payload=payload)


def test_rolled_back_transaction_leaves_no_message(
    app_engine: Engine, relay_engine: Engine, make_tenant
) -> None:
    tenant = make_tenant()
    with pytest.raises(RuntimeError):
        with tenant_session(app_engine, TenantContext(tenant)) as s:
            enqueue(s, tenant_id=tenant, topic="system.noop", payload={"request_id": uuid.uuid4()})
            raise RuntimeError("domain failure after enqueue")
    published: list[Envelope] = []
    relay_once(relay_engine, published.append, batch=10_000)
    assert all(e.tenant_id != tenant for e in published)


def test_relay_publishes_across_tenants_exactly_once(
    app_engine: Engine, relay_engine: Engine, make_tenant
) -> None:
    ids = {}
    for tenant in (make_tenant(), make_tenant()):
        with tenant_session(app_engine, TenantContext(tenant)) as s:
            ids[
                enqueue(
                    s,
                    tenant_id=tenant,
                    topic="system.noop",
                    payload={"request_id": uuid.uuid4(), "attempt": 1},
                )
            ] = tenant

    published: list[Envelope] = []
    relay_once(relay_engine, published.append, batch=10_000)
    mine = {e.id: e for e in published if e.id in ids}
    assert set(mine) == set(ids)
    assert all(mine[i].tenant_id == ids[i] for i in ids)

    again: list[Envelope] = []
    relay_once(relay_engine, again.append, batch=10_000)
    assert not any(e.id in ids for e in again)


def test_publish_failure_leaves_messages_for_retry(
    app_engine: Engine, relay_engine: Engine, make_tenant
) -> None:
    tenant = make_tenant()
    with tenant_session(app_engine, TenantContext(tenant)) as s:
        msg_id = enqueue(
            s, tenant_id=tenant, topic="system.noop", payload={"request_id": uuid.uuid4()}
        )

    def broken(_: Envelope) -> None:
        raise ConnectionError("broker down")

    with pytest.raises(ConnectionError):
        relay_once(relay_engine, broken, batch=10_000)
    retried: list[Envelope] = []
    relay_once(relay_engine, retried.append, batch=10_000)
    assert msg_id in {e.id for e in retried}


def test_app_role_cannot_mark_published_and_relay_cannot_read_audit(
    app_engine: Engine, relay_engine: Engine, make_tenant
) -> None:
    tenant = make_tenant()
    with pytest.raises(DBAPIError, match="permission denied"):
        with tenant_session(app_engine, TenantContext(tenant)) as s:
            s.execute(text("UPDATE outbox SET published_at = now()"))
    with pytest.raises(DBAPIError, match="permission denied"):
        with relay_engine.begin() as conn:
            conn.execute(text("SELECT count(*) FROM audit_event"))
    with pytest.raises(DBAPIError, match="permission denied"):
        with relay_engine.begin() as conn:
            conn.execute(text("UPDATE outbox SET payload = '{}'"))

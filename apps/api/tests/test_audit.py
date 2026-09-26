"""Append-only, hash-chained audit log (ADR-0004, threat T-16)."""

import pytest
from sqlalchemy import Engine, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from idprivacy.domain.audit import service as audit
from idprivacy.platform.db import TenantContext, tenant_session
from tests.conftest import bearer


def _append_n(app_engine: Engine, tenant, n: int) -> None:
    with tenant_session(app_engine, TenantContext(tenant)) as s:
        for i in range(n):
            audit.append(
                s,
                tenant_id=tenant,
                actor_type="SYSTEM",
                actor_ref="system:test",
                action="test.event",
                object_type="tenant",
                object_id=tenant,
                details={"i": i},
            )


def test_chain_links_each_event_to_previous(app_engine: Engine, make_tenant) -> None:
    tenant = make_tenant()
    _append_n(app_engine, tenant, 3)
    with tenant_session(app_engine, TenantContext(tenant)) as s:
        rows = s.execute(text("SELECT seq, prev_hash, hash FROM audit_event ORDER BY seq")).all()
        assert [r.seq for r in rows] == [1, 2, 3]
        assert rows[0].prev_hash == audit.GENESIS_HASH
        assert rows[1].prev_hash == rows[0].hash and rows[2].prev_hash == rows[1].hash
        assert audit.verify_chain(s, tenant).ok


def test_details_are_redacted_before_storage(app_engine: Engine, make_tenant) -> None:
    tenant = make_tenant()
    with tenant_session(app_engine, TenantContext(tenant)) as s:
        ev = audit.append(
            s,
            tenant_id=tenant,
            actor_type="SYSTEM",
            actor_ref="system:test",
            action="test.event",
            object_type="tenant",
            details={"email": "a@b.example", "note": "call +919876543210"},
        )
        assert ev.details == {"email": "[REDACTED]", "note": "call [REDACTED]"}


@pytest.mark.parametrize(
    "stmt",
    [
        "UPDATE audit_event SET action = 'tampered'",
        "DELETE FROM audit_event",
        "TRUNCATE audit_event",
    ],
)
def test_app_role_cannot_mutate_audit_events(app_engine: Engine, make_tenant, stmt: str) -> None:
    tenant = make_tenant()
    _append_n(app_engine, tenant, 1)
    with pytest.raises(DBAPIError, match="permission denied"):
        with tenant_session(app_engine, TenantContext(tenant)) as s:
            s.execute(text(stmt))


@pytest.mark.parametrize(
    "stmt",
    [
        "UPDATE audit_event SET action = 'tampered' WHERE tenant_id = :t",
        "DELETE FROM audit_event WHERE tenant_id = :t",
    ],
)
def test_trigger_blocks_mutation_even_for_table_owner(
    migrator_engine: Engine, app_engine: Engine, make_tenant, stmt: str
) -> None:
    tenant = make_tenant()
    _append_n(app_engine, tenant, 1)
    with pytest.raises(DBAPIError, match="append-only"):
        with migrator_engine.begin() as conn:
            conn.execute(text(stmt), {"t": tenant})


def test_trigger_blocks_truncate_for_table_owner(migrator_engine: Engine) -> None:
    with pytest.raises(DBAPIError, match="append-only"):
        with migrator_engine.begin() as conn:
            conn.execute(text("TRUNCATE audit_event"))


def _tamper(migrator_engine: Engine, tenant, sql: str) -> None:
    """Simulate a privileged attacker who disables the trigger to rewrite history."""
    with migrator_engine.begin() as conn:
        conn.execute(text("ALTER TABLE audit_event DISABLE TRIGGER audit_event_no_update_delete"))
        conn.execute(text(sql), {"t": tenant})
        conn.execute(text("ALTER TABLE audit_event ENABLE TRIGGER audit_event_no_update_delete"))


@pytest.mark.parametrize(
    "sql, broken_seq",
    [
        ("UPDATE audit_event SET details = '{\"i\": 99}' WHERE tenant_id = :t AND seq = 2", 2),
        ("DELETE FROM audit_event WHERE tenant_id = :t AND seq = 2", 3),
        ("DELETE FROM audit_event WHERE tenant_id = :t AND seq = 3", 3),
    ],
)
def test_verification_detects_tampering(
    migrator_engine: Engine, app_engine: Engine, make_tenant, sql: str, broken_seq: int
) -> None:
    tenant = make_tenant()
    _append_n(app_engine, tenant, 3)
    _tamper(migrator_engine, tenant, sql)
    with tenant_session(app_engine, TenantContext(tenant)) as s:
        result = audit.verify_chain(s, tenant)
    assert result.ok is False
    assert result.first_broken_seq == broken_seq


def test_verify_endpoint_reports_tampering_and_is_itself_audited(
    client, migrator_engine: Engine, app_engine: Engine, make_tenant, provision_user, make_token
) -> None:
    tenant = make_tenant()
    _append_n(app_engine, tenant, 2)
    _, subject = provision_user(tenant, ["AUDITOR"])
    token = make_token(subject)

    assert client.post("/v1/audit/verify", headers=bearer(token)).json()["ok"] is True
    _tamper(
        migrator_engine,
        tenant,
        "UPDATE audit_event SET actor_ref = 'someone-else' WHERE tenant_id = :t AND seq = 1",
    )
    body = client.post("/v1/audit/verify", headers=bearer(token)).json()
    assert body == {"ok": False, "events_checked": 0, "first_broken_seq": 1}

    with Session(migrator_engine) as s:
        actions = (
            s.execute(
                text("SELECT action FROM audit_event WHERE tenant_id = :t ORDER BY seq"),
                {"t": tenant},
            )
            .scalars()
            .all()
        )
    assert actions.count("audit.chain_verified") == 2


def test_concurrent_appends_keep_chain_contiguous(app_engine: Engine, make_tenant) -> None:
    from concurrent.futures import ThreadPoolExecutor

    tenant = make_tenant()
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(lambda _: _append_n(app_engine, tenant, 5), range(8)))
    with tenant_session(app_engine, TenantContext(tenant)) as s:
        result = audit.verify_chain(s, tenant)
    assert result.ok and result.events_checked == 40

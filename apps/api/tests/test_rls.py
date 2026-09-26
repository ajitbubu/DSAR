"""Row-level security is a second, independent control (ADR-0002, threat T-09).

These tests use raw SQL with no tenant filter, simulating an application bug.
"""

import uuid

import pytest
from sqlalchemy import Engine, text
from sqlalchemy.exc import DBAPIError, IntegrityError, ProgrammingError
from sqlalchemy.orm import Session

from idprivacy.platform.db import TenantContext, tenant_session


def test_unfiltered_query_only_sees_current_tenant(
    app_engine: Engine, make_tenant, provision_user
) -> None:
    tenant_a, tenant_b = make_tenant(), make_tenant()
    provision_user(tenant_a, ["PRIVACY_ANALYST"])
    user_b, _ = provision_user(tenant_b, ["PRIVACY_ANALYST"])

    with tenant_session(app_engine, TenantContext(tenant_a)) as s:
        tenants_seen = {r[0] for r in s.execute(text("SELECT tenant_id FROM app_user"))}
        assert tenants_seen == {tenant_a}
        assert (
            s.execute(
                text("SELECT count(*) FROM app_user WHERE id = :id"), {"id": user_b}
            ).scalar_one()
            == 0
        )
        assert {r[0] for r in s.execute(text("SELECT id FROM tenant"))} == {tenant_a}


def test_no_tenant_context_sees_nothing(app_engine: Engine, make_tenant, provision_user) -> None:
    provision_user(make_tenant(), ["AUDITOR"])
    with Session(app_engine) as s:
        for table in ("tenant", "app_user", "role", "user_role", "audit_event", "outbox"):
            assert s.execute(text(f"SELECT count(*) FROM {table}")).scalar_one() == 0, table


def test_cannot_write_rows_into_another_tenant(app_engine: Engine, make_tenant) -> None:
    tenant_a, tenant_b = make_tenant(), make_tenant()
    with pytest.raises(ProgrammingError, match="row-level security"):
        with tenant_session(app_engine, TenantContext(tenant_a)) as s:
            s.execute(
                text("INSERT INTO role (id, tenant_id, code) VALUES (:id, :t, 'AUDITOR')"),
                {"id": uuid.uuid4(), "t": tenant_b},
            )


def test_cannot_move_row_to_another_tenant(app_engine: Engine, make_tenant, provision_user) -> None:
    tenant_a, tenant_b = make_tenant(), make_tenant()
    user_a, _ = provision_user(tenant_a, [])
    with pytest.raises(ProgrammingError, match="row-level security"):
        with tenant_session(app_engine, TenantContext(tenant_a)) as s:
            s.execute(
                text("UPDATE app_user SET tenant_id = :b WHERE id = :u"),
                {"b": tenant_b, "u": user_a},
            )


def test_tenant_context_does_not_leak_across_pooled_transactions(
    app_engine: Engine, make_tenant
) -> None:
    tenant = make_tenant()
    with tenant_session(app_engine, TenantContext(tenant)):
        pass
    with app_engine.connect() as conn:  # likely the same pooled connection
        assert conn.execute(text("SELECT app_current_tenant()")).scalar_one() is None


def test_composite_fk_blocks_cross_tenant_reference(
    migrator_engine: Engine, make_tenant, provision_user
) -> None:
    """Even the RLS-exempt owner can't link a tenant-A user to a tenant-B role."""
    tenant_a, tenant_b = make_tenant(), make_tenant()
    user_a, _ = provision_user(tenant_a, [])
    with pytest.raises(IntegrityError):
        with migrator_engine.begin() as conn:
            role_b = uuid.uuid4()
            conn.execute(
                text("INSERT INTO role (id, tenant_id, code) VALUES (:r, :t, 'APPROVER')"),
                {"r": role_b, "t": tenant_b},
            )
            conn.execute(
                text("INSERT INTO user_role (tenant_id, user_id, role_id) VALUES (:t, :u, :r)"),
                {"t": tenant_a, "u": user_a, "r": role_b},
            )


def test_app_role_is_not_privileged(app_engine: Engine) -> None:
    with app_engine.connect() as conn:
        row = conn.execute(
            text(
                "SELECT rolsuper, rolbypassrls, rolcreaterole "
                "FROM pg_roles WHERE rolname = current_user"
            )
        ).one()
    assert tuple(row) == (False, False, False)


def test_app_role_cannot_create_tenants_or_ddl(app_engine: Engine) -> None:
    with pytest.raises(DBAPIError, match="permission denied"):
        with app_engine.begin() as conn:
            conn.execute(
                text("SELECT set_config('app.tenant_id', :t, true)"), {"t": str(uuid.uuid4())}
            )
            conn.execute(
                text(
                    "INSERT INTO tenant (id, slug, name, status) "
                    "VALUES (app_current_tenant(), 'evil-tenant', 'x', 'ACTIVE')"
                )
            )
    with pytest.raises(DBAPIError, match="permission denied|must be owner"):
        with app_engine.begin() as conn:
            conn.execute(text("ALTER TABLE audit_event DISABLE TRIGGER ALL"))

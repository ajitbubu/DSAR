"""M0 baseline: tenancy, staff identity, append-only audit, outbox, RLS.

Revision ID: 0001_baseline
Revises:
Requires roles idp_app and idp_relay (created by infra/compose/postgres/init/01-roles.sh).
The migrator role owns every table and isn't subject to RLS. The app and relay roles
aren't owners, don't have BYPASSRLS, and always are subject to RLS.
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision = "0001_baseline"
down_revision = None
branch_labels = None
depends_on = None

TENANT_TABLES = ("role", "app_user", "user_role", "tenant_audit_head", "audit_event", "outbox")


def _ts(name: str = "created_at", nullable: bool = False) -> sa.Column:  # type: ignore[type-arg]
    return sa.Column(
        name,
        sa.DateTime(timezone=True),
        nullable=nullable,
        server_default=sa.func.now() if not nullable else None,
    )


def upgrade() -> None:
    op.create_table(
        "tenant",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("slug", sa.String(40), nullable=False),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("data_region", sa.String(32)),
        _ts(),
        sa.UniqueConstraint("slug", name="uq_tenant_slug"),
        sa.CheckConstraint("slug ~ '^[a-z0-9-]{3,40}$'", name="ck_tenant_slug_format"),
        sa.CheckConstraint("status IN ('ACTIVE','SUSPENDED')", name="ck_tenant_status"),
    )
    op.create_table(
        "role",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", UUID(as_uuid=True), sa.ForeignKey("tenant.id"), nullable=False),
        sa.Column("code", sa.String(32), nullable=False),
        _ts(),
        sa.UniqueConstraint("tenant_id", "code", name="uq_role_tenant_id"),
        sa.UniqueConstraint("tenant_id", "id", name="uq_role_tenant_id_id"),
        sa.CheckConstraint(
            "code IN ('TENANT_ADMIN','PRIVACY_ANALYST','APPROVER','AUDITOR')", name="ck_role_code"
        ),
    )
    op.create_table(
        "app_user",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", UUID(as_uuid=True), sa.ForeignKey("tenant.id"), nullable=False),
        sa.Column("idp_issuer", sa.String(255), nullable=False),
        sa.Column("idp_subject", sa.String(255), nullable=False),
        sa.Column("enc_email", sa.Text),
        sa.Column("display_name", sa.String(200)),
        sa.Column("status", sa.String(20), nullable=False),
        _ts(),
        sa.UniqueConstraint("idp_issuer", "idp_subject", name="uq_app_user_idp_identity"),
        sa.UniqueConstraint("tenant_id", "id", name="uq_app_user_tenant_id_id"),
        sa.CheckConstraint("status IN ('ACTIVE','DISABLED')", name="ck_app_user_status"),
    )
    op.create_table(
        "user_role",
        sa.Column("tenant_id", UUID(as_uuid=True), sa.ForeignKey("tenant.id"), primary_key=True),
        sa.Column("user_id", UUID(as_uuid=True), primary_key=True),
        sa.Column("role_id", UUID(as_uuid=True), primary_key=True),
        sa.ForeignKeyConstraint(
            ["tenant_id", "user_id"],
            ["app_user.tenant_id", "app_user.id"],
            name="fk_user_role_user",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "role_id"], ["role.tenant_id", "role.id"], name="fk_user_role_role"
        ),
    )
    op.create_table(
        "tenant_audit_head",
        sa.Column("tenant_id", UUID(as_uuid=True), sa.ForeignKey("tenant.id"), primary_key=True),
        sa.Column("last_seq", sa.BigInteger, nullable=False),
        sa.Column("last_hash", sa.String(64), nullable=False),
    )
    op.create_table(
        "audit_event",
        sa.Column("tenant_id", UUID(as_uuid=True), sa.ForeignKey("tenant.id"), primary_key=True),
        sa.Column("seq", sa.BigInteger, primary_key=True),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("actor_type", sa.String(20), nullable=False),
        sa.Column("actor_ref", sa.String(128), nullable=False),
        sa.Column("action", sa.String(64), nullable=False),
        sa.Column("object_type", sa.String(64), nullable=False),
        sa.Column("object_id", UUID(as_uuid=True)),
        sa.Column("details", JSONB, nullable=False),
        sa.Column("prev_hash", sa.String(64), nullable=False),
        sa.Column("hash", sa.String(64), nullable=False),
        sa.CheckConstraint(
            "actor_type IN ('USER','DATA_PRINCIPAL','SYSTEM','CONNECTOR')",
            name="ck_audit_event_actor_type",
        ),
    )
    op.create_table(
        "outbox",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", UUID(as_uuid=True), sa.ForeignKey("tenant.id"), nullable=False),
        sa.Column("topic", sa.String(64), nullable=False),
        sa.Column("payload", JSONB, nullable=False),
        _ts(),
        _ts("published_at", nullable=True),
    )
    op.create_index("ix_role_tenant_id", "role", ["tenant_id"])
    op.create_index("ix_app_user_tenant_id", "app_user", ["tenant_id"])
    op.create_index("ix_outbox_tenant_id", "outbox", ["tenant_id"])
    op.create_index(
        "ix_outbox_unpublished",
        "outbox",
        ["created_at"],
        postgresql_where=sa.text("published_at IS NULL"),
    )

    # --- Tenant context helper -------------------------------------------------------
    op.execute("""
        CREATE FUNCTION app_current_tenant() RETURNS uuid
        LANGUAGE sql STABLE AS
        $$ SELECT NULLIF(current_setting('app.tenant_id', true), '')::uuid $$
    """)

    # --- Row-level security ----------------------------------------------------------
    op.execute("ALTER TABLE tenant ENABLE ROW LEVEL SECURITY")
    op.execute("CREATE POLICY tenant_isolation ON tenant USING (id = app_current_tenant())")
    for table in TENANT_TABLES:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY tenant_isolation ON {table} "
            "USING (tenant_id = app_current_tenant()) "
            "WITH CHECK (tenant_id = app_current_tenant())"
        )
    # The relay publishes across tenants, but only on the outbox, and only SELECT/UPDATE.
    op.execute("CREATE POLICY relay_all ON outbox FOR ALL TO idp_relay USING (true)")

    # --- Grants ----------------------------------------------------------------------
    op.execute("GRANT USAGE ON SCHEMA public TO idp_app, idp_relay")
    op.execute("GRANT SELECT ON tenant TO idp_app")
    op.execute("GRANT SELECT, INSERT, UPDATE ON role, app_user TO idp_app")
    op.execute("GRANT SELECT, INSERT, DELETE ON user_role TO idp_app")
    op.execute("GRANT SELECT, INSERT, UPDATE ON tenant_audit_head TO idp_app")
    op.execute("GRANT SELECT, INSERT ON audit_event TO idp_app")
    op.execute("GRANT SELECT, INSERT ON outbox TO idp_app")
    op.execute("GRANT SELECT, UPDATE (published_at) ON outbox TO idp_relay")

    # --- Append-only audit (ADR-0004) -------------------------------------------------
    op.execute("""
        CREATE FUNCTION audit_event_reject_mutation() RETURNS trigger
        LANGUAGE plpgsql AS
        $$ BEGIN RAISE EXCEPTION 'audit_event is append-only (% rejected)', TG_OP; END $$
    """)
    op.execute("""
        CREATE TRIGGER audit_event_no_update_delete BEFORE UPDATE OR DELETE ON audit_event
        FOR EACH ROW EXECUTE FUNCTION audit_event_reject_mutation()
    """)
    op.execute("""
        CREATE TRIGGER audit_event_no_truncate BEFORE TRUNCATE ON audit_event
        FOR EACH STATEMENT EXECUTE FUNCTION audit_event_reject_mutation()
    """)

    # --- Staff principal resolution (ADR-0003) -----------------------------------------
    # Runs as the owner (RLS-exempt) so a verified (issuer, subject) can be mapped to its
    # tenant before any tenant context exists. It exposes only ids and role codes.
    op.execute("""
        CREATE FUNCTION resolve_staff_principal(p_issuer text, p_subject text)
        RETURNS TABLE (tenant_id uuid, user_id uuid, roles text[])
        LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS
        $$
          SELECT u.tenant_id, u.id,
                 COALESCE(array_agg(r.code ORDER BY r.code) FILTER (WHERE r.code IS NOT NULL),
                          '{}')
          FROM app_user u
          JOIN tenant t ON t.id = u.tenant_id AND t.status = 'ACTIVE'
          LEFT JOIN user_role ur ON ur.tenant_id = u.tenant_id AND ur.user_id = u.id
          LEFT JOIN role r ON r.tenant_id = ur.tenant_id AND r.id = ur.role_id
          WHERE u.idp_issuer = p_issuer AND u.idp_subject = p_subject AND u.status = 'ACTIVE'
          GROUP BY u.tenant_id, u.id
        $$
    """)
    op.execute("REVOKE ALL ON FUNCTION resolve_staff_principal(text, text) FROM PUBLIC")
    op.execute("GRANT EXECUTE ON FUNCTION resolve_staff_principal(text, text) TO idp_app")


def downgrade() -> None:
    op.execute("DROP FUNCTION IF EXISTS resolve_staff_principal(text, text)")
    for table in (
        "outbox",
        "audit_event",
        "tenant_audit_head",
        "user_role",
        "app_user",
        "role",
        "tenant",
    ):
        op.drop_table(table)
    op.execute("DROP FUNCTION IF EXISTS audit_event_reject_mutation()")
    op.execute("DROP FUNCTION IF EXISTS app_current_tenant()")

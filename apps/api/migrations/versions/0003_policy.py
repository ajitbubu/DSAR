"""M2: policy packs, tenant pack enablement, jurisdiction decisions, identity resolution.

Revision ID: 0003_policy
Revises: 0002_intake

``policy_pack`` is a global catalogue (not tenant-owned), so it has no tenant_id or RLS.
The app can only read it. A trigger keeps published content immutable (T-22): only the
status may change.
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision = "0003_policy"
down_revision = "0002_intake"
branch_labels = None
depends_on = None

TENANT_TABLES = ("tenant_policy_pack", "jurisdiction_decision", "request_identifier")


def _tenant_col(primary_key: bool = False) -> sa.Column:  # type: ignore[type-arg]
    return sa.Column(
        "tenant_id",
        UUID(as_uuid=True),
        sa.ForeignKey("tenant.id"),
        nullable=False,
        primary_key=primary_key,
    )


def upgrade() -> None:
    op.create_table(
        "policy_pack",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("code", sa.String(32), nullable=False),
        sa.Column("version", sa.String(32), nullable=False),
        sa.Column("content_sha256", sa.String(64), nullable=False),
        sa.Column("content", JSONB, nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("code", "version", name="uq_policy_pack_code_version"),
        sa.CheckConstraint("status IN ('PUBLISHED','RETIRED')", name="ck_policy_pack_status"),
        sa.CheckConstraint("version ~ '^[0-9]+\\.[0-9]+\\.[0-9]+$'", name="ck_policy_pack_version"),
    )
    op.execute("""
        CREATE FUNCTION policy_pack_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          IF TG_OP = 'DELETE' THEN
            RAISE EXCEPTION 'policy_pack rows cannot be deleted';
          END IF;
          IF NEW.code IS DISTINCT FROM OLD.code OR NEW.version IS DISTINCT FROM OLD.version
             OR NEW.content IS DISTINCT FROM OLD.content
             OR NEW.content_sha256 IS DISTINCT FROM OLD.content_sha256 THEN
            RAISE EXCEPTION 'published policy packs are immutable';
          END IF;
          RETURN NEW;
        END $$
    """)
    op.execute("""
        CREATE TRIGGER policy_pack_immutable BEFORE UPDATE OR DELETE ON policy_pack
        FOR EACH ROW EXECUTE FUNCTION policy_pack_immutable()
    """)

    op.create_table(
        "tenant_policy_pack",
        _tenant_col(primary_key=True),
        sa.Column("pack_code", sa.String(32), primary_key=True),
        sa.Column("pack_version", sa.String(32), nullable=False),
        sa.Column("priority", sa.Integer, nullable=False),
        sa.Column("enabled", sa.Boolean, nullable=False),
        sa.ForeignKeyConstraint(
            ["pack_code", "pack_version"],
            ["policy_pack.code", "policy_pack.version"],
            name="fk_tenant_policy_pack_pack",
        ),
    )

    op.create_table(
        "jurisdiction_decision",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        _tenant_col(),
        sa.Column("request_id", UUID(as_uuid=True), nullable=False),
        sa.Column("outcome", sa.String(32), nullable=False),
        sa.Column("policy_pack_id", UUID(as_uuid=True), sa.ForeignKey("policy_pack.id")),
        sa.Column("regulation", sa.String(32)),
        sa.Column("policy_pack_version", sa.String(32)),
        sa.Column("inputs", JSONB, nullable=False),
        sa.Column("rationale", sa.Text, nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.UniqueConstraint("tenant_id", "request_id", name="uq_jurisdiction_decision_request"),
        sa.ForeignKeyConstraint(
            ["tenant_id", "request_id"],
            ["privacy_request.tenant_id", "privacy_request.id"],
            name="fk_jurisdiction_decision_request",
        ),
        sa.CheckConstraint(
            "outcome IN ('APPLICABLE','NO_APPLICABLE_PACK')",
            name="ck_jurisdiction_decision_outcome",
        ),
        sa.CheckConstraint(
            "(outcome = 'APPLICABLE') = (policy_pack_id IS NOT NULL)",
            name="ck_jurisdiction_decision_pack",
        ),
    )
    op.create_index("ix_jurisdiction_decision_tenant_id", "jurisdiction_decision", ["tenant_id"])

    op.create_table(
        "request_identifier",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        _tenant_col(),
        sa.Column("request_id", UUID(as_uuid=True), nullable=False),
        sa.Column("type", sa.String(16), nullable=False),
        sa.Column("bidx", sa.String(64), nullable=False),
        sa.Column("enc_value", sa.Text, nullable=False),
        sa.Column("assurance", sa.String(16), nullable=False),
        sa.Column("source", sa.String(16), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.UniqueConstraint(
            "tenant_id", "request_id", "type", "bidx", name="uq_request_identifier_value"
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "request_id"],
            ["privacy_request.tenant_id", "privacy_request.id"],
            name="fk_request_identifier_request",
        ),
        sa.CheckConstraint(
            "type IN ('EMAIL','PHONE','CUSTOMER_ID')", name="ck_request_identifier_type"
        ),
        sa.CheckConstraint(
            "assurance IN ('VERIFIED','CLAIMED')", name="ck_request_identifier_assurance"
        ),
        sa.CheckConstraint("source IN ('OTP','FORM')", name="ck_request_identifier_source"),
    )
    op.create_index("ix_request_identifier_tenant_id", "request_identifier", ["tenant_id"])
    op.create_index("ix_request_identifier_request_id", "request_identifier", ["request_id"])

    op.add_column(
        "privacy_request",
        sa.Column(
            "policy_pack_id",
            UUID(as_uuid=True),
            sa.ForeignKey("policy_pack.id", name="fk_privacy_request_policy_pack"),
        ),
    )
    op.add_column("privacy_request", sa.Column("workflow_code", sa.String(32)))

    for table in TENANT_TABLES:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY tenant_isolation ON {table} "
            "USING (tenant_id = app_current_tenant()) "
            "WITH CHECK (tenant_id = app_current_tenant())"
        )
    op.execute("GRANT SELECT ON policy_pack TO idp_app")
    op.execute("GRANT SELECT ON tenant_policy_pack TO idp_app")
    op.execute("GRANT SELECT, INSERT ON jurisdiction_decision, request_identifier TO idp_app")


def downgrade() -> None:
    op.drop_column("privacy_request", "workflow_code")
    op.drop_column("privacy_request", "policy_pack_id")
    for table in ("request_identifier", "jurisdiction_decision", "tenant_policy_pack"):
        op.drop_table(table)
    op.drop_table("policy_pack")
    op.execute("DROP FUNCTION IF EXISTS policy_pack_immutable()")

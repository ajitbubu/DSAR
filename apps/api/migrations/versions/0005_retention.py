"""M4: legal holds and append-only retention decisions.

Revision ID: 0005_retention
Revises: 0004_discovery

Exactly one *current* decision per match is guaranteed structurally:
- at most one root (supersedes_id IS NULL) per match (partial unique index), and
- each decision can be superseded at most once (unique supersedes_id),
so every match has a single linear chain whose head is the current decision.
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import UUID

revision = "0005_retention"
down_revision = "0004_discovery"
branch_labels = None
depends_on = None

DECISIONS = "'DELETE','RETAIN','RESTRICT','ANONYMIZE','MANUAL_REVIEW'"


def _tenant_col() -> sa.Column:  # type: ignore[type-arg]
    return sa.Column("tenant_id", UUID(as_uuid=True), sa.ForeignKey("tenant.id"), nullable=False)


def upgrade() -> None:
    op.create_table(
        "legal_hold",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        _tenant_col(),
        sa.Column("scope", sa.String(20), nullable=False),
        sa.Column("scope_ref", sa.String(128), nullable=False),
        sa.Column("matter_ref", sa.String(64), nullable=False),
        sa.Column("reason", sa.Text, nullable=False),
        sa.Column("created_by", UUID(as_uuid=True), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column("released_at", sa.DateTime(timezone=True)),
        sa.Column("released_by", UUID(as_uuid=True)),
        sa.UniqueConstraint("tenant_id", "id", name="uq_legal_hold_tenant_id_id"),
        sa.CheckConstraint(
            "scope IN ('CASE','DATA_PRINCIPAL','CONNECTOR','RECORD_TYPE')",
            name="ck_legal_hold_scope",
        ),
        sa.CheckConstraint("length(reason) BETWEEN 10 AND 2000", name="ck_legal_hold_reason"),
        sa.CheckConstraint(
            "(released_at IS NULL) = (released_by IS NULL)", name="ck_legal_hold_release"
        ),
    )
    op.create_index("ix_legal_hold_tenant_id", "legal_hold", ["tenant_id"])
    op.create_index(
        "ix_legal_hold_active",
        "legal_hold",
        ["tenant_id", "scope", "scope_ref"],
        postgresql_where=sa.text("released_at IS NULL"),
    )

    op.create_table(
        "retention_decision",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        _tenant_col(),
        sa.Column("request_id", UUID(as_uuid=True), nullable=False),
        sa.Column("data_match_id", UUID(as_uuid=True), nullable=False),
        sa.Column("decision", sa.String(16), nullable=False),
        sa.Column("source", sa.String(20), nullable=False),
        sa.Column("rule_id", sa.String(64)),
        sa.Column("exception_code", sa.String(32)),
        sa.Column("exception_reason", sa.Text),
        sa.Column("legal_hold_id", UUID(as_uuid=True)),
        sa.Column("decided_by", UUID(as_uuid=True)),
        sa.Column("supersedes_id", UUID(as_uuid=True)),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.UniqueConstraint("tenant_id", "id", name="uq_retention_decision_tenant_id_id"),
        sa.UniqueConstraint("supersedes_id", name="uq_retention_decision_supersedes"),
        sa.ForeignKeyConstraint(
            ["tenant_id", "data_match_id"],
            ["data_match.tenant_id", "data_match.id"],
            name="fk_retention_decision_match",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "supersedes_id"],
            ["retention_decision.tenant_id", "retention_decision.id"],
            name="fk_retention_decision_supersedes",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "legal_hold_id"],
            ["legal_hold.tenant_id", "legal_hold.id"],
            name="fk_retention_decision_hold",
        ),
        sa.CheckConstraint(f"decision IN ({DECISIONS})", name="ck_retention_decision_decision"),
        sa.CheckConstraint(
            "source IN ('ENGINE','ANALYST_OVERRIDE')", name="ck_retention_decision_source"
        ),
        sa.CheckConstraint(
            "decision <> 'RETAIN' OR exception_code IS NOT NULL",
            name="ck_retention_decision_retain_needs_exception",
        ),
        sa.CheckConstraint(
            "source <> 'ANALYST_OVERRIDE' OR (exception_code IS NOT NULL AND "
            "length(exception_reason) >= 10 AND decided_by IS NOT NULL AND "
            "supersedes_id IS NOT NULL)",
            name="ck_retention_decision_override_documented",
        ),
        sa.CheckConstraint(
            "source <> 'ENGINE' OR decided_by IS NULL",
            name="ck_retention_decision_engine_unattributed",
        ),
        sa.CheckConstraint(
            "exception_reason IS NULL OR length(exception_reason) <= 2000",
            name="ck_retention_decision_reason_length",
        ),
    )
    op.create_index("ix_retention_decision_tenant_id", "retention_decision", ["tenant_id"])
    op.create_index("ix_retention_decision_request_id", "retention_decision", ["request_id"])
    op.create_index(
        "uq_retention_decision_root",
        "retention_decision",
        ["tenant_id", "data_match_id"],
        unique=True,
        postgresql_where=sa.text("supersedes_id IS NULL"),
    )

    op.execute("""
        CREATE FUNCTION reject_mutation() RETURNS trigger LANGUAGE plpgsql AS
        $$ BEGIN RAISE EXCEPTION '% is append-only (% rejected)', TG_TABLE_NAME, TG_OP; END $$
    """)
    op.execute("""
        CREATE TRIGGER retention_decision_append_only BEFORE UPDATE OR DELETE
        ON retention_decision FOR EACH ROW EXECUTE FUNCTION reject_mutation()
    """)

    for table in ("legal_hold", "retention_decision"):
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY tenant_isolation ON {table} "
            "USING (tenant_id = app_current_tenant()) "
            "WITH CHECK (tenant_id = app_current_tenant())"
        )
    op.execute("GRANT SELECT, INSERT ON legal_hold, retention_decision TO idp_app")
    op.execute("GRANT UPDATE (released_at, released_by) ON legal_hold TO idp_app")


def downgrade() -> None:
    op.drop_table("retention_decision")
    op.drop_table("legal_hold")
    op.execute("DROP FUNCTION IF EXISTS reject_mutation()")

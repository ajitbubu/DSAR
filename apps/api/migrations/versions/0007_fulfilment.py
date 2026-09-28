"""M6: fulfilment tasks and append-only connector executions.

Revision ID: 0007_fulfilment
Revises: 0006_approval
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision = "0007_fulfilment"
down_revision = "0006_approval"
branch_labels = None
depends_on = None

TASK_STATUSES = (
    "'PENDING','DISPATCHED','SUCCEEDED','FAILED_RETRYABLE','FAILED_FINAL','SKIPPED','CANCELLED'"
)


def _tenant_col() -> sa.Column:  # type: ignore[type-arg]
    return sa.Column("tenant_id", UUID(as_uuid=True), sa.ForeignKey("tenant.id"), nullable=False)


def upgrade() -> None:
    op.create_table(
        "fulfilment_task",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        _tenant_col(),
        sa.Column("request_id", UUID(as_uuid=True), nullable=False),
        sa.Column("data_match_id", UUID(as_uuid=True), nullable=False),
        sa.Column("retention_decision_id", UUID(as_uuid=True), nullable=False),
        sa.Column("approval_id", UUID(as_uuid=True), nullable=False),
        sa.Column("connector_config_id", UUID(as_uuid=True), nullable=False),
        sa.Column("action", sa.String(16), nullable=False),
        sa.Column("idempotency_key", sa.String(64), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("attempt_count", sa.Integer, nullable=False),
        sa.Column("skip_reason", sa.String(200)),
        sa.Column("receipt_id", sa.String(64)),
        sa.Column("outcome", sa.String(20)),
        sa.Column("last_error_code", sa.String(40)),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.UniqueConstraint("tenant_id", "idempotency_key", name="uq_fulfilment_task_key"),
        sa.UniqueConstraint(
            "tenant_id", "data_match_id", "approval_id", name="uq_fulfilment_task_per_approval"
        ),
        sa.UniqueConstraint("tenant_id", "id", name="uq_fulfilment_task_tenant_id_id"),
        sa.ForeignKeyConstraint(
            ["tenant_id", "request_id"],
            ["privacy_request.tenant_id", "privacy_request.id"],
            name="fk_fulfilment_task_request",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "data_match_id"],
            ["data_match.tenant_id", "data_match.id"],
            name="fk_fulfilment_task_match",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "retention_decision_id"],
            ["retention_decision.tenant_id", "retention_decision.id"],
            name="fk_fulfilment_task_decision",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "approval_id"],
            ["approval.tenant_id", "approval.id"],
            name="fk_fulfilment_task_approval",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "connector_config_id"],
            ["connector_config.tenant_id", "connector_config.id"],
            name="fk_fulfilment_task_connector",
        ),
        sa.CheckConstraint(
            "action IN ('DELETE','ANONYMIZE','RESTRICT','NOOP_RETAIN')",
            name="ck_fulfilment_task_action",
        ),
        sa.CheckConstraint(f"status IN ({TASK_STATUSES})", name="ck_fulfilment_task_status"),
        sa.CheckConstraint("idempotency_key ~ '^[a-f0-9]{64}$'", name="ck_fulfilment_task_key"),
        sa.CheckConstraint(
            "(status = 'SKIPPED') = (skip_reason IS NOT NULL)",
            name="ck_fulfilment_task_skip_reason",
        ),
        sa.CheckConstraint(
            "action <> 'NOOP_RETAIN' OR status = 'SKIPPED'",
            name="ck_fulfilment_task_retain_skipped",
        ),
    )
    op.create_index("ix_fulfilment_task_request_id", "fulfilment_task", ["request_id"])
    op.create_index("ix_fulfilment_task_tenant_id", "fulfilment_task", ["tenant_id"])

    op.create_table(
        "connector_execution",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        _tenant_col(),
        sa.Column("fulfilment_task_id", UUID(as_uuid=True), nullable=False),
        sa.Column("idempotency_key", sa.String(64), nullable=False),
        sa.Column("operation", sa.String(20), nullable=False),
        sa.Column("attempt_no", sa.Integer, nullable=False),
        sa.Column("outcome", sa.String(20), nullable=False),
        sa.Column("error_code", sa.String(40)),
        sa.Column("receipt_id", sa.String(64)),
        sa.Column("replayed", sa.Boolean),
        sa.Column("evidence", JSONB),
        sa.Column("evidence_sha256", sa.String(64)),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint(
            "tenant_id",
            "fulfilment_task_id",
            "operation",
            "attempt_no",
            name="uq_connector_execution_attempt",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "fulfilment_task_id"],
            ["fulfilment_task.tenant_id", "fulfilment_task.id"],
            name="fk_connector_execution_task",
        ),
        sa.CheckConstraint(
            "operation IN ('execute_action','get_evidence','verify_action')",
            name="ck_connector_execution_operation",
        ),
        sa.CheckConstraint(
            "outcome IN ('SUCCEEDED','FAILED_RETRYABLE','FAILED_FINAL')",
            name="ck_connector_execution_outcome",
        ),
    )
    op.create_index("ix_connector_execution_task", "connector_execution", ["fulfilment_task_id"])
    op.create_index("ix_connector_execution_tenant_id", "connector_execution", ["tenant_id"])
    op.execute(
        "CREATE TRIGGER connector_execution_append_only BEFORE UPDATE OR DELETE ON "
        "connector_execution FOR EACH ROW EXECUTE FUNCTION reject_mutation()"
    )

    for table in ("fulfilment_task", "connector_execution"):
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY tenant_isolation ON {table} "
            "USING (tenant_id = app_current_tenant()) "
            "WITH CHECK (tenant_id = app_current_tenant())"
        )
    op.execute("GRANT SELECT, INSERT ON fulfilment_task, connector_execution TO idp_app")
    op.execute(
        "GRANT UPDATE (status, attempt_count, skip_reason, receipt_id, outcome, "
        "last_error_code, updated_at) ON fulfilment_task TO idp_app"
    )


def downgrade() -> None:
    op.drop_table("connector_execution")
    op.drop_table("fulfilment_task")

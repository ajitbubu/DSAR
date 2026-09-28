"""M5: approval submissions and maker-checker approvals.

Revision ID: 0006_approval
Revises: 0005_retention
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision = "0006_approval"
down_revision = "0005_retention"
branch_labels = None
depends_on = None


def _tenant_col() -> sa.Column:  # type: ignore[type-arg]
    return sa.Column("tenant_id", UUID(as_uuid=True), sa.ForeignKey("tenant.id"), nullable=False)


def _created() -> sa.Column:  # type: ignore[type-arg]
    return sa.Column(
        "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )


def upgrade() -> None:
    op.create_table(
        "approval_submission",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        _tenant_col(),
        sa.Column("request_id", UUID(as_uuid=True), nullable=False),
        sa.Column("submitted_by", UUID(as_uuid=True), nullable=False),
        sa.Column("case_version", sa.Integer, nullable=False),
        sa.Column("decision_set_sha256", sa.String(64), nullable=False),
        _created(),
        sa.UniqueConstraint("tenant_id", "id", name="uq_approval_submission_tenant_id_id"),
        sa.ForeignKeyConstraint(
            ["tenant_id", "request_id"],
            ["privacy_request.tenant_id", "privacy_request.id"],
            name="fk_approval_submission_request",
        ),
        sa.CheckConstraint(
            "decision_set_sha256 ~ '^[a-f0-9]{64}$'", name="ck_approval_submission_hash"
        ),
    )
    op.create_index("ix_approval_submission_request_id", "approval_submission", ["request_id"])
    op.create_index("ix_approval_submission_tenant_id", "approval_submission", ["tenant_id"])

    op.create_table(
        "approval",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        _tenant_col(),
        sa.Column("request_id", UUID(as_uuid=True), nullable=False),
        sa.Column("submission_id", UUID(as_uuid=True), nullable=False),
        sa.Column("case_version", sa.Integer, nullable=False),
        sa.Column("decision_set_sha256", sa.String(64), nullable=False),
        sa.Column("submitted_by", UUID(as_uuid=True), nullable=False),
        sa.Column("approved_by", UUID(as_uuid=True), nullable=False),
        sa.Column("outcome", sa.String(16), nullable=False),
        sa.Column("comment", sa.Text),
        sa.Column("idempotency_key", sa.String(128), nullable=False),
        sa.Column("response", JSONB, nullable=False),
        _created(),
        sa.UniqueConstraint("tenant_id", "idempotency_key", name="uq_approval_idempotency_key"),
        sa.UniqueConstraint("tenant_id", "id", name="uq_approval_tenant_id_id"),
        # One decision per submission: a second approver can't decide it again.
        sa.UniqueConstraint("tenant_id", "submission_id", name="uq_approval_per_submission"),
        sa.ForeignKeyConstraint(
            ["tenant_id", "submission_id"],
            ["approval_submission.tenant_id", "approval_submission.id"],
            name="fk_approval_submission",
        ),
        sa.CheckConstraint("approved_by <> submitted_by", name="ck_approval_maker_checker"),
        sa.CheckConstraint("outcome IN ('APPROVED','REJECTED')", name="ck_approval_outcome"),
        sa.CheckConstraint(
            "outcome <> 'REJECTED' OR length(comment) >= 10", name="ck_approval_reject_reason"
        ),
        sa.CheckConstraint(
            "comment IS NULL OR length(comment) <= 2000", name="ck_approval_comment_length"
        ),
    )
    op.create_index("ix_approval_request_id", "approval", ["request_id"])
    op.create_index("ix_approval_tenant_id", "approval", ["tenant_id"])

    for table in ("approval_submission", "approval"):
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY tenant_isolation ON {table} "
            "USING (tenant_id = app_current_tenant()) "
            "WITH CHECK (tenant_id = app_current_tenant())"
        )
        op.execute(
            f"CREATE TRIGGER {table}_append_only BEFORE UPDATE OR DELETE ON {table} "
            "FOR EACH ROW EXECUTE FUNCTION reject_mutation()"
        )
        op.execute(f"GRANT SELECT, INSERT ON {table} TO idp_app")


def downgrade() -> None:
    op.drop_table("approval")
    op.drop_table("approval_submission")

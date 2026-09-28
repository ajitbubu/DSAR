"""M7: verification results, evidence artifacts, fulfilment rounds for reconciliation.

Revision ID: 0008_verification_evidence
Revises: 0007_fulfilment
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import UUID

revision = "0008_verification_evidence"
down_revision = "0007_fulfilment"
branch_labels = None
depends_on = None


def _tenant_col() -> sa.Column:  # type: ignore[type-arg]
    return sa.Column("tenant_id", UUID(as_uuid=True), sa.ForeignKey("tenant.id"), nullable=False)


def _created() -> sa.Column:  # type: ignore[type-arg]
    return sa.Column(
        "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )


def upgrade() -> None:
    # Reconciliation re-executes failed records as a new round with a new key.
    op.add_column(
        "fulfilment_task", sa.Column("round", sa.Integer, nullable=False, server_default="1")
    )
    op.drop_constraint("uq_fulfilment_task_per_approval", "fulfilment_task", type_="unique")
    op.create_unique_constraint(
        "uq_fulfilment_task_per_round",
        "fulfilment_task",
        ["tenant_id", "data_match_id", "approval_id", "round"],
    )
    op.create_check_constraint("ck_fulfilment_task_round", "fulfilment_task", "round >= 1")

    op.create_table(
        "verification_result",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        _tenant_col(),
        sa.Column("request_id", UUID(as_uuid=True), nullable=False),
        sa.Column("fulfilment_task_id", UUID(as_uuid=True), nullable=False),
        sa.Column("data_match_id", UUID(as_uuid=True), nullable=False),
        sa.Column("round", sa.Integer, nullable=False),
        sa.Column("expected", sa.String(16), nullable=False),
        sa.Column("observed_verify", sa.String(16)),
        sa.Column("observed_rescan", sa.String(16)),
        sa.Column("outcome", sa.String(8), nullable=False),
        sa.Column("note", sa.String(200)),
        _created(),
        sa.UniqueConstraint(
            "tenant_id", "fulfilment_task_id", "round", name="uq_verification_result_task_round"
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "fulfilment_task_id"],
            ["fulfilment_task.tenant_id", "fulfilment_task.id"],
            name="fk_verification_result_task",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "data_match_id"],
            ["data_match.tenant_id", "data_match.id"],
            name="fk_verification_result_match",
        ),
        sa.CheckConstraint(
            "expected IN ('ABSENT','ANONYMIZED','RESTRICTED','PRESENT')",
            name="ck_verification_result_expected",
        ),
        sa.CheckConstraint("outcome IN ('PASS','FAIL')", name="ck_verification_result_outcome"),
    )
    op.create_index("ix_verification_result_request_id", "verification_result", ["request_id"])
    op.create_index("ix_verification_result_tenant_id", "verification_result", ["tenant_id"])

    op.create_table(
        "evidence_artifact",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        _tenant_col(),
        sa.Column("request_id", UUID(as_uuid=True), nullable=False),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("object_key", sa.String(300), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("manifest_sha256", sa.String(64)),
        sa.Column("size_bytes", sa.BigInteger, nullable=False),
        sa.Column("media_type", sa.String(100), nullable=False),
        sa.Column("file_ext", sa.String(8), nullable=False),
        sa.Column("created_by", sa.String(128), nullable=False),
        sa.Column("retain_until", sa.DateTime(timezone=True)),
        _created(),
        sa.UniqueConstraint("object_key", name="uq_evidence_artifact_object_key"),
        sa.ForeignKeyConstraint(
            ["tenant_id", "request_id"],
            ["privacy_request.tenant_id", "privacy_request.id"],
            name="fk_evidence_artifact_request",
        ),
        sa.CheckConstraint("kind IN ('PACKAGE','UPLOAD')", name="ck_evidence_artifact_kind"),
        sa.CheckConstraint(
            "file_ext IN ('zip','pdf','png','jpg')", name="ck_evidence_artifact_ext"
        ),
        sa.CheckConstraint(
            "object_key ~ '^tenants/[0-9a-f-]{36}/requests/[0-9a-f-]{36}/"
            "[0-9a-f-]{36}\\.(zip|pdf|png|jpg)$'",
            name="ck_evidence_artifact_key",
        ),
        sa.CheckConstraint(
            "(kind = 'PACKAGE') = (manifest_sha256 IS NOT NULL)",
            name="ck_evidence_artifact_manifest",
        ),
    )
    op.create_index("ix_evidence_artifact_request_id", "evidence_artifact", ["request_id"])
    op.create_index("ix_evidence_artifact_tenant_id", "evidence_artifact", ["tenant_id"])

    for table in ("verification_result", "evidence_artifact"):
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
    rounds = (
        op.get_bind()
        .execute(sa.text("SELECT count(*) FROM fulfilment_task WHERE round > 1"))
        .scalar_one()
    )
    if rounds:
        raise RuntimeError("reconciliation rounds exist; this downgrade would lose them")
    op.drop_table("evidence_artifact")
    op.drop_table("verification_result")
    op.drop_constraint("ck_fulfilment_task_round", "fulfilment_task", type_="check")
    op.drop_constraint("uq_fulfilment_task_per_round", "fulfilment_task", type_="unique")
    op.create_unique_constraint(
        "uq_fulfilment_task_per_approval",
        "fulfilment_task",
        ["tenant_id", "data_match_id", "approval_id"],
    )
    op.drop_column("fulfilment_task", "round")

"""Access A3: the requester's access report, and returning sign-in challenges.

Revision ID: 0011_access_report
Revises: 0010_disclosure
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import UUID

revision = "0011_access_report"
down_revision = "0010_disclosure"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "access_report",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", UUID(as_uuid=True), sa.ForeignKey("tenant.id"), nullable=False),
        sa.Column("request_id", UUID(as_uuid=True), nullable=False),
        sa.Column("export_id", UUID(as_uuid=True), nullable=False),
        sa.Column("approval_id", UUID(as_uuid=True), nullable=False),
        sa.Column("json_key", sa.String(300), nullable=False),
        sa.Column("html_key", sa.String(300), nullable=False),
        sa.Column("json_sha256", sa.String(64), nullable=False),
        sa.Column("html_sha256", sa.String(64), nullable=False),
        sa.Column("record_count", sa.Integer, nullable=False),
        sa.Column("withheld_records", sa.Integer, nullable=False),
        sa.Column("withheld_fields", sa.Integer, nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),  # D-25
        sa.Column("max_downloads", sa.Integer, nullable=False),  # D-25
        sa.Column("download_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("purged_at", sa.DateTime(timezone=True)),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.UniqueConstraint("tenant_id", "approval_id", name="uq_access_report_approval"),
        sa.ForeignKeyConstraint(
            ["tenant_id", "request_id"],
            ["privacy_request.tenant_id", "privacy_request.id"],
            name="fk_access_report_request",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "export_id"],
            ["disclosure_export.tenant_id", "disclosure_export.id"],
            name="fk_access_report_export",
        ),
        sa.CheckConstraint(
            "download_count >= 0 AND download_count <= max_downloads",
            name="ck_access_report_downloads",
        ),
    )
    op.create_index("ix_access_report_request_id", "access_report", ["request_id"])
    op.create_index("ix_access_report_tenant_id", "access_report", ["tenant_id"])
    op.execute("ALTER TABLE access_report ENABLE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY tenant_isolation ON access_report "
        "USING (tenant_id = app_current_tenant()) "
        "WITH CHECK (tenant_id = app_current_tenant())"
    )
    # Only the download counter and the purge marker may change after insert.
    op.execute("GRANT SELECT, INSERT ON access_report TO idp_app")
    op.execute("GRANT UPDATE (download_count, purged_at) ON access_report TO idp_app")

    op.add_column(
        "identity_verification",
        sa.Column("purpose", sa.String(16), nullable=False, server_default="INTAKE"),
    )
    op.create_check_constraint(
        "ck_identity_verification_purpose",
        "identity_verification",
        "purpose IN ('INTAKE','SIGN_IN')",
    )


def downgrade() -> None:
    op.drop_constraint("ck_identity_verification_purpose", "identity_verification")
    op.drop_column("identity_verification", "purpose")
    op.drop_table("access_report")

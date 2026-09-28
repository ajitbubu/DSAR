"""Access A2: disclosure exports, exclusions and the processing register.

Revision ID: 0010_disclosure
Revises: 0009_communication_closure
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision = "0010_disclosure"
down_revision = "0009_communication_closure"
branch_labels = None
depends_on = None


def _tenant_table(name: str, append_only: bool) -> None:
    op.create_index(f"ix_{name}_tenant_id", name, ["tenant_id"])
    op.execute(f"ALTER TABLE {name} ENABLE ROW LEVEL SECURITY")
    op.execute(
        f"CREATE POLICY tenant_isolation ON {name} "
        "USING (tenant_id = app_current_tenant()) "
        "WITH CHECK (tenant_id = app_current_tenant())"
    )
    if append_only:
        op.execute(
            f"CREATE TRIGGER {name}_append_only BEFORE UPDATE OR DELETE ON "
            f"{name} FOR EACH ROW EXECUTE FUNCTION reject_mutation()"
        )
        op.execute(f"GRANT SELECT, INSERT ON {name} TO idp_app")
    else:
        op.execute(f"GRANT SELECT, INSERT, UPDATE ON {name} TO idp_app")


def upgrade() -> None:
    # One row per export round. The content itself is only ever in the encrypted blob.
    op.create_table(
        "disclosure_export",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", UUID(as_uuid=True), sa.ForeignKey("tenant.id"), nullable=False),
        sa.Column("request_id", UUID(as_uuid=True), nullable=False),
        sa.Column("round", sa.Integer, nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("attempts", sa.Integer, nullable=False, server_default="0"),
        sa.Column("object_key", sa.String(300)),
        sa.Column("content_sha256", sa.String(64)),
        sa.Column("record_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("field_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("missing_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("error_code", sa.String(40)),
        sa.Column("requested_by", UUID(as_uuid=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True)),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.UniqueConstraint("tenant_id", "id", name="uq_disclosure_export_tenant_id_id"),
        sa.UniqueConstraint("tenant_id", "request_id", "round", name="uq_disclosure_export_round"),
        sa.ForeignKeyConstraint(
            ["tenant_id", "request_id"],
            ["privacy_request.tenant_id", "privacy_request.id"],
            name="fk_disclosure_export_request",
        ),
        sa.CheckConstraint(
            "status IN ('PENDING','RUNNING','READY','FAILED')", name="ck_disclosure_export_status"
        ),
        sa.CheckConstraint(
            "status <> 'READY' OR (object_key IS NOT NULL AND content_sha256 IS NOT NULL)",
            name="ck_disclosure_export_ready",
        ),
    )
    op.create_index("ix_disclosure_export_request_id", "disclosure_export", ["request_id"])
    _tenant_table("disclosure_export", append_only=False)

    # Append-only. The latest row per (export, record, field) wins; field NULL = whole record.
    op.create_table(
        "disclosure_exclusion",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", UUID(as_uuid=True), sa.ForeignKey("tenant.id"), nullable=False),
        sa.Column("request_id", UUID(as_uuid=True), nullable=False),
        sa.Column("export_id", UUID(as_uuid=True), nullable=False),
        sa.Column("data_match_id", UUID(as_uuid=True), nullable=False),
        sa.Column("field_name", sa.String(64)),
        sa.Column("action", sa.String(8), nullable=False),
        sa.Column("reason_code", sa.String(40)),
        sa.Column("created_by", UUID(as_uuid=True), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "export_id"],
            ["disclosure_export.tenant_id", "disclosure_export.id"],
            name="fk_disclosure_exclusion_export",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "data_match_id"],
            ["data_match.tenant_id", "data_match.id"],
            name="fk_disclosure_exclusion_match",
        ),
        sa.CheckConstraint(
            "action IN ('EXCLUDE','INCLUDE')", name="ck_disclosure_exclusion_action"
        ),
        sa.CheckConstraint(
            "(action = 'EXCLUDE') = (reason_code IS NOT NULL)",
            name="ck_disclosure_exclusion_reason",
        ),
    )
    op.create_index("ix_disclosure_exclusion_export_id", "disclosure_exclusion", ["export_id"])
    _tenant_table("disclosure_exclusion", append_only=True)

    # Append-only versions; the latest row per connector is current (decision D-27).
    op.create_table(
        "processing_register_entry",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", UUID(as_uuid=True), sa.ForeignKey("tenant.id"), nullable=False),
        sa.Column("connector_id", sa.String(40), nullable=False),
        sa.Column("purposes", JSONB, nullable=False),
        sa.Column("recipients", JSONB, nullable=False),
        sa.Column("updated_by", UUID(as_uuid=True)),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
    )
    op.create_index(
        "ix_processing_register_entry_connector",
        "processing_register_entry",
        ["tenant_id", "connector_id", "created_at"],
    )
    _tenant_table("processing_register_entry", append_only=True)


def downgrade() -> None:
    for name in ("processing_register_entry", "disclosure_exclusion", "disclosure_export"):
        op.drop_table(name)

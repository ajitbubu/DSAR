"""M3: connector configuration, discovery jobs, data matches.

Revision ID: 0004_discovery
Revises: 0003_policy
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision = "0004_discovery"
down_revision = "0003_policy"
branch_labels = None
depends_on = None

TABLES = ("connector_config", "discovery_job", "data_match")


def _tenant_col() -> sa.Column:  # type: ignore[type-arg]
    return sa.Column("tenant_id", UUID(as_uuid=True), sa.ForeignKey("tenant.id"), nullable=False)


def _ts(name: str, nullable: bool = True, default: bool = False) -> sa.Column:  # type: ignore[type-arg]
    return sa.Column(
        name,
        sa.DateTime(timezone=True),
        nullable=nullable,
        server_default=sa.func.now() if default else None,
    )


def upgrade() -> None:
    op.create_table(
        "connector_config",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        _tenant_col(),
        sa.Column("connector_id", sa.String(40), nullable=False),
        sa.Column("display_name", sa.String(100), nullable=False),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("base_url", sa.String(500), nullable=False),
        sa.Column("credential_ref", sa.String(200), nullable=False),
        sa.Column("enabled", sa.Boolean, nullable=False),
        _ts("created_at", nullable=False, default=True),
        sa.UniqueConstraint("tenant_id", "connector_id", name="uq_connector_config_connector"),
        sa.UniqueConstraint("tenant_id", "id", name="uq_connector_config_tenant_id_id"),
        sa.CheckConstraint("kind IN ('http_v1')", name="ck_connector_config_kind"),
        sa.CheckConstraint(
            "connector_id ~ '^[a-z][a-z0-9-]{1,39}$'", name="ck_connector_config_connector_id"
        ),
        sa.CheckConstraint("base_url ~ '^https?://'", name="ck_connector_config_base_url"),
        sa.CheckConstraint(
            "credential_ref ~ '^[a-z]+:[A-Za-z0-9_./-]{1,190}$'",
            name="ck_connector_config_credential_ref",
        ),
    )
    op.create_index("ix_connector_config_tenant_id", "connector_config", ["tenant_id"])

    op.create_table(
        "discovery_job",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        _tenant_col(),
        sa.Column("request_id", UUID(as_uuid=True), nullable=False),
        sa.Column("connector_config_id", UUID(as_uuid=True), nullable=False),
        sa.Column("purpose", sa.String(24), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("attempts", sa.Integer, nullable=False),
        sa.Column("match_count", sa.Integer, nullable=False),
        sa.Column("error_code", sa.String(40)),
        _ts("started_at"),
        _ts("finished_at"),
        _ts("created_at", nullable=False, default=True),
        sa.UniqueConstraint(
            "tenant_id",
            "request_id",
            "connector_config_id",
            "purpose",
            name="uq_discovery_job_per_connector",
        ),
        sa.UniqueConstraint("tenant_id", "id", name="uq_discovery_job_tenant_id_id"),
        sa.ForeignKeyConstraint(
            ["tenant_id", "request_id"],
            ["privacy_request.tenant_id", "privacy_request.id"],
            name="fk_discovery_job_request",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "connector_config_id"],
            ["connector_config.tenant_id", "connector_config.id"],
            name="fk_discovery_job_connector",
        ),
        sa.CheckConstraint(
            "purpose IN ('INITIAL','VERIFICATION_RESCAN')", name="ck_discovery_job_purpose"
        ),
        sa.CheckConstraint(
            "status IN ('PENDING','RUNNING','SUCCEEDED','FAILED')", name="ck_discovery_job_status"
        ),
    )
    op.create_index("ix_discovery_job_tenant_id", "discovery_job", ["tenant_id"])
    op.create_index("ix_discovery_job_request_id", "discovery_job", ["request_id"])

    op.create_table(
        "data_match",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        _tenant_col(),
        sa.Column("discovery_job_id", UUID(as_uuid=True), nullable=False),
        sa.Column("request_id", UUID(as_uuid=True), nullable=False),
        sa.Column("connector_id", sa.String(40), nullable=False),
        sa.Column("source_record_ref", sa.String(128), nullable=False),
        sa.Column("record_type", sa.String(64), nullable=False),
        sa.Column("data_categories", JSONB, nullable=False),
        sa.Column("matched_on", JSONB, nullable=False),
        sa.Column("content_fingerprint", sa.String(64), nullable=False),
        sa.Column("attributes", JSONB, nullable=False),
        _ts("created_at", nullable=False, default=True),
        sa.UniqueConstraint(
            "tenant_id", "discovery_job_id", "source_record_ref", name="uq_data_match_per_job"
        ),
        sa.UniqueConstraint("tenant_id", "id", name="uq_data_match_tenant_id_id"),
        sa.ForeignKeyConstraint(
            ["tenant_id", "discovery_job_id"],
            ["discovery_job.tenant_id", "discovery_job.id"],
            name="fk_data_match_job",
        ),
    )
    op.create_index("ix_data_match_tenant_id", "data_match", ["tenant_id"])
    op.create_index("ix_data_match_discovery_job_id", "data_match", ["discovery_job_id"])
    op.create_index("ix_data_match_request_id", "data_match", ["request_id"])

    for table in TABLES:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY tenant_isolation ON {table} "
            "USING (tenant_id = app_current_tenant()) "
            "WITH CHECK (tenant_id = app_current_tenant())"
        )
    op.execute("GRANT SELECT ON connector_config TO idp_app")
    op.execute("GRANT SELECT, INSERT, UPDATE ON discovery_job TO idp_app")
    # Matches are evidence of what was found: insert-only for the app.
    op.execute("GRANT SELECT, INSERT ON data_match TO idp_app")


def downgrade() -> None:
    for table in reversed(TABLES):
        op.drop_table(table)

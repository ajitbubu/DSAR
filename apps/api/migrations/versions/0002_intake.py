"""M1: Data Principal intake, identity verification, DP tracking sessions.

Revision ID: 0002_intake
Revises: 0001_baseline

Public (unauthenticated) flows have no staff principal to derive a tenant from. Three
narrow SECURITY DEFINER functions map an opaque handle to its tenant so the request
can then run under normal RLS:
  - resolve_intake_tenant(slug)          → public intake form
  - resolve_verification_tenant(uuid)    → OTP confirm/resend
  - resolve_dp_session(token_sha256)     → tracking session
Each returns identifiers only, and only for active tenants and live objects.
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import UUID

revision = "0002_intake"
down_revision = "0001_baseline"
branch_labels = None
depends_on = None

TABLES = (
    "data_principal",
    "privacy_request",
    "request_right",
    "identity_verification",
    "dp_session",
)

CASE_STATUSES = (
    "SUBMITTED",
    "PENDING_VERIFICATION",
    "VERIFICATION_FAILED",
    "VERIFIED",
    "JURISDICTION_DETERMINED",
    "DISCOVERY_IN_PROGRESS",
    "DISCOVERY_COMPLETE",
    "RETENTION_EVALUATED",
    "UNDER_REVIEW",
    "PENDING_APPROVAL",
    "APPROVED",
    "REJECTED",
    "FULFILMENT_IN_PROGRESS",
    "VERIFICATION_IN_PROGRESS",
    "RECONCILIATION_REQUIRED",
    "VERIFIED_COMPLETE",
    "EVIDENCE_GENERATED",
    "RESPONDED",
    "CLOSED",
    "ON_HOLD",
    "CANCELLED",
    "PENDING_MANUAL_HANDLING",
)
RIGHT_CODES = ("ERASURE", "ACCESS", "CORRECTION", "CONSENT_WITHDRAWAL", "GRIEVANCE", "NOMINATION")


def _in(values: tuple[str, ...]) -> str:
    return ", ".join(f"'{v}'" for v in values)


def _tenant_col() -> sa.Column:  # type: ignore[type-arg]
    return sa.Column("tenant_id", UUID(as_uuid=True), sa.ForeignKey("tenant.id"), nullable=False)


def _ts(name: str, nullable: bool = False, default: bool = False) -> sa.Column:  # type: ignore[type-arg]
    return sa.Column(
        name,
        sa.DateTime(timezone=True),
        nullable=nullable,
        server_default=sa.func.now() if default else None,
    )


def upgrade() -> None:
    op.create_table(
        "data_principal",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        _tenant_col(),
        sa.Column("enc_identifiers", sa.Text, nullable=False),
        sa.Column("bidx_email", sa.String(64)),
        sa.Column("bidx_phone", sa.String(64)),
        _ts("created_at", default=True),
        sa.UniqueConstraint("tenant_id", "id", name="uq_data_principal_tenant_id_id"),
        sa.CheckConstraint(
            "bidx_email IS NOT NULL OR bidx_phone IS NOT NULL",
            name="ck_data_principal_has_identifier",
        ),
    )
    op.create_index("ix_data_principal_tenant_id", "data_principal", ["tenant_id"])
    op.create_index("ix_data_principal_bidx_email", "data_principal", ["tenant_id", "bidx_email"])
    op.create_index("ix_data_principal_bidx_phone", "data_principal", ["tenant_id", "bidx_phone"])

    op.create_table(
        "privacy_request",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        _tenant_col(),
        sa.Column("display_id", sa.String(20), nullable=False),
        sa.Column("data_principal_id", UUID(as_uuid=True), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("channel", sa.String(16), nullable=False),
        sa.Column("version", sa.Integer, nullable=False),
        sa.Column("enc_full_name", sa.Text, nullable=False),
        sa.Column("enc_submitted_identifiers", sa.Text, nullable=False),
        sa.Column("residency_claim", sa.String(16), nullable=False),
        _ts("submitted_at", default=True),
        _ts("due_at", nullable=True),
        _ts("closed_at", nullable=True),
        sa.UniqueConstraint("tenant_id", "display_id", name="uq_privacy_request_display_id"),
        sa.UniqueConstraint("tenant_id", "id", name="uq_privacy_request_tenant_id_id"),
        sa.ForeignKeyConstraint(
            ["tenant_id", "data_principal_id"],
            ["data_principal.tenant_id", "data_principal.id"],
            name="fk_privacy_request_data_principal",
        ),
        sa.CheckConstraint(f"status IN ({_in(CASE_STATUSES)})", name="ck_privacy_request_status"),
        sa.CheckConstraint(
            "display_id ~ '^DPR-[0-9]{4}-[0-9A-HJKMNP-TV-Z]{6}$'",
            name="ck_privacy_request_display_id",
        ),
        sa.CheckConstraint("channel IN ('WEB')", name="ck_privacy_request_channel"),
        sa.CheckConstraint(
            "residency_claim IN ('IN','OTHER','UNKNOWN')", name="ck_privacy_request_residency"
        ),
        sa.CheckConstraint("version >= 1", name="ck_privacy_request_version"),
    )
    op.create_index("ix_privacy_request_tenant_id", "privacy_request", ["tenant_id"])
    op.create_index("ix_privacy_request_status", "privacy_request", ["tenant_id", "status"])

    op.create_table(
        "request_right",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        _tenant_col(),
        sa.Column("request_id", UUID(as_uuid=True), nullable=False),
        sa.Column("right_code", sa.String(32), nullable=False),
        sa.Column("enc_details", sa.Text),
        sa.ForeignKeyConstraint(
            ["tenant_id", "request_id"],
            ["privacy_request.tenant_id", "privacy_request.id"],
            name="fk_request_right_request",
        ),
        sa.CheckConstraint(f"right_code IN ({_in(RIGHT_CODES)})", name="ck_request_right_code"),
    )
    op.create_index("ix_request_right_tenant_id", "request_right", ["tenant_id"])
    op.create_index("ix_request_right_request_id", "request_right", ["request_id"])

    op.create_table(
        "identity_verification",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        _tenant_col(),
        sa.Column("request_id", UUID(as_uuid=True), nullable=False),
        sa.Column("method", sa.String(16), nullable=False),
        sa.Column("provider", sa.String(32), nullable=False),
        sa.Column("challenge_hash", sa.String(64), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("attempts", sa.Integer, nullable=False),
        sa.Column("max_attempts", sa.Integer, nullable=False),
        sa.Column("resend_count", sa.Integer, nullable=False),
        _ts("last_sent_at"),
        _ts("expires_at"),
        _ts("verified_at", nullable=True),
        _ts("created_at", default=True),
        sa.ForeignKeyConstraint(
            ["tenant_id", "request_id"],
            ["privacy_request.tenant_id", "privacy_request.id"],
            name="fk_identity_verification_request",
        ),
        sa.CheckConstraint(
            "method IN ('OTP_EMAIL','OTP_SMS')", name="ck_identity_verification_method"
        ),
        sa.CheckConstraint(
            "status IN ('PENDING','VERIFIED','FAILED','EXPIRED')",
            name="ck_identity_verification_status",
        ),
        sa.CheckConstraint(
            "attempts >= 0 AND attempts <= max_attempts", name="ck_identity_verification_attempts"
        ),
        sa.CheckConstraint(
            "(status = 'VERIFIED') = (verified_at IS NOT NULL)",
            name="ck_identity_verification_verified_at",
        ),
    )
    op.create_index("ix_identity_verification_tenant_id", "identity_verification", ["tenant_id"])
    op.create_index("ix_identity_verification_request_id", "identity_verification", ["request_id"])

    op.create_table(
        "dp_session",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        _tenant_col(),
        sa.Column("request_id", UUID(as_uuid=True), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False),
        _ts("created_at", default=True),
        _ts("idle_expires_at"),
        _ts("absolute_expires_at"),
        _ts("revoked_at", nullable=True),
        sa.UniqueConstraint("token_hash", name="uq_dp_session_token_hash"),
        sa.ForeignKeyConstraint(
            ["tenant_id", "request_id"],
            ["privacy_request.tenant_id", "privacy_request.id"],
            name="fk_dp_session_request",
        ),
    )
    op.create_index("ix_dp_session_tenant_id", "dp_session", ["tenant_id"])
    op.create_index("ix_dp_session_request_id", "dp_session", ["request_id"])

    for table in TABLES:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY tenant_isolation ON {table} "
            "USING (tenant_id = app_current_tenant()) "
            "WITH CHECK (tenant_id = app_current_tenant())"
        )

    op.execute(
        "GRANT SELECT, INSERT, UPDATE ON data_principal, privacy_request, "
        "identity_verification, dp_session TO idp_app"
    )
    op.execute("GRANT SELECT, INSERT ON request_right TO idp_app")

    op.execute("""
        CREATE FUNCTION resolve_intake_tenant(p_slug text) RETURNS uuid
        LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS
        $$ SELECT id FROM tenant WHERE slug = p_slug AND status = 'ACTIVE' $$
    """)
    op.execute("""
        CREATE FUNCTION resolve_verification_tenant(p_challenge uuid) RETURNS uuid
        LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS
        $$ SELECT v.tenant_id FROM identity_verification v
           JOIN tenant t ON t.id = v.tenant_id AND t.status = 'ACTIVE'
           WHERE v.id = p_challenge $$
    """)
    op.execute("""
        CREATE FUNCTION resolve_dp_session(p_token_hash text)
        RETURNS TABLE (tenant_id uuid, request_id uuid, session_id uuid)
        LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS
        $$ SELECT s.tenant_id, s.request_id, s.id FROM dp_session s
           JOIN tenant t ON t.id = s.tenant_id AND t.status = 'ACTIVE'
           WHERE s.token_hash = p_token_hash AND s.revoked_at IS NULL
             AND s.idle_expires_at > now() AND s.absolute_expires_at > now() $$
    """)
    for fn in (
        "resolve_intake_tenant(text)",
        "resolve_verification_tenant(uuid)",
        "resolve_dp_session(text)",
    ):
        op.execute(f"REVOKE ALL ON FUNCTION {fn} FROM PUBLIC")
        op.execute(f"GRANT EXECUTE ON FUNCTION {fn} TO idp_app")


def downgrade() -> None:
    for fn in (
        "resolve_dp_session(text)",
        "resolve_verification_tenant(uuid)",
        "resolve_intake_tenant(text)",
    ):
        op.execute(f"DROP FUNCTION IF EXISTS {fn}")
    for table in reversed(TABLES):
        op.drop_table(table)

"""M8: communications and the database closure guard.

Revision ID: 0009_communication_closure
Revises: 0008_verification_evidence
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import UUID

revision = "0009_communication_closure"
down_revision = "0008_verification_evidence"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "communication",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("tenant_id", UUID(as_uuid=True), sa.ForeignKey("tenant.id"), nullable=False),
        sa.Column("request_id", UUID(as_uuid=True), nullable=False),
        sa.Column("template_code", sa.String(64), nullable=False),
        sa.Column("channel", sa.String(16), nullable=False),
        sa.Column("provider", sa.String(32), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("public_text", sa.Text, nullable=False),
        sa.Column("body_sha256", sa.String(64), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.UniqueConstraint(
            "tenant_id", "request_id", "template_code", name="uq_communication_once_per_template"
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id", "request_id"],
            ["privacy_request.tenant_id", "privacy_request.id"],
            name="fk_communication_request",
        ),
        sa.CheckConstraint("status IN ('SENT','FAILED')", name="ck_communication_status"),
        sa.CheckConstraint("channel IN ('EMAIL','SMS')", name="ck_communication_channel"),
        sa.CheckConstraint("length(public_text) <= 2000", name="ck_communication_text"),
    )
    op.create_index("ix_communication_request_id", "communication", ["request_id"])
    op.create_index("ix_communication_tenant_id", "communication", ["tenant_id"])
    op.execute("ALTER TABLE communication ENABLE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY tenant_isolation ON communication "
        "USING (tenant_id = app_current_tenant()) "
        "WITH CHECK (tenant_id = app_current_tenant())"
    )
    op.execute(
        "CREATE TRIGGER communication_append_only BEFORE UPDATE OR DELETE ON "
        "communication FOR EACH ROW EXECUTE FUNCTION reject_mutation()"
    )
    op.execute("GRANT SELECT, INSERT ON communication TO idp_app")

    # Defence in depth for "close only when all tasks are terminal". SECURITY DEFINER so
    # RLS can never hide an open task from the check.
    op.execute("""
        CREATE FUNCTION privacy_request_closure_guard() RETURNS trigger
        LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
        BEGIN
          IF NEW.status = 'CLOSED' AND OLD.status IS DISTINCT FROM 'CLOSED' AND EXISTS (
              SELECT 1 FROM fulfilment_task t
              WHERE t.tenant_id = NEW.tenant_id AND t.request_id = NEW.id
                AND t.status NOT IN ('SUCCEEDED','FAILED_FINAL','SKIPPED','CANCELLED')) THEN
            RAISE EXCEPTION 'case % has non-terminal fulfilment tasks', NEW.id;
          END IF;
          RETURN NEW;
        END $$
    """)
    op.execute("""
        CREATE TRIGGER privacy_request_closure_guard BEFORE UPDATE OF status
        ON privacy_request FOR EACH ROW EXECUTE FUNCTION privacy_request_closure_guard()
    """)


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS privacy_request_closure_guard ON privacy_request")
    op.execute("DROP FUNCTION IF EXISTS privacy_request_closure_guard()")
    op.drop_table("communication")

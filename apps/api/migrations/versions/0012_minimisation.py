"""D-12: shred a closed case's requester identifiers after the pack's grace period.

Revision ID: 0012_minimisation
Revises: 0011_access_report
"""

import sqlalchemy as sa
from alembic import op

revision = "0012_minimisation"
down_revision = "0011_access_report"
branch_labels = None
depends_on = None

SHREDDED = {
    "data_principal": ["enc_identifiers"],
    "privacy_request": ["enc_full_name", "enc_submitted_identifiers"],
}
# A principal must have a blind index to be found, until it is minimised.
HAS_IDENTIFIER = "ck_data_principal_ck_data_principal_has_identifier"


def upgrade() -> None:
    for table, columns in SHREDDED.items():
        op.add_column(table, sa.Column("minimised_at", sa.DateTime(timezone=True)))
        for column in columns:
            op.alter_column(table, column, nullable=True)
    op.execute(f"ALTER TABLE data_principal DROP CONSTRAINT {HAS_IDENTIFIER}")
    op.execute(
        f"ALTER TABLE data_principal ADD CONSTRAINT {HAS_IDENTIFIER} CHECK "
        "(minimised_at IS NOT NULL OR bidx_email IS NOT NULL OR bidx_phone IS NOT NULL)"
    )
    op.add_column("disclosure_export", sa.Column("purged_at", sa.DateTime(timezone=True)))
    op.execute("GRANT UPDATE (enc_details) ON request_right TO idp_app")
    op.execute("GRANT DELETE ON request_identifier TO idp_app")


def downgrade() -> None:
    op.execute("REVOKE DELETE ON request_identifier FROM idp_app")
    op.execute("REVOKE UPDATE (enc_details) ON request_right FROM idp_app")
    op.drop_column("disclosure_export", "purged_at")
    op.execute(f"ALTER TABLE data_principal DROP CONSTRAINT {HAS_IDENTIFIER}")
    op.execute(
        f"ALTER TABLE data_principal ADD CONSTRAINT {HAS_IDENTIFIER} CHECK "
        "(bidx_email IS NOT NULL OR bidx_phone IS NOT NULL)"
    )
    for table, columns in SHREDDED.items():
        for column in columns:
            op.alter_column(table, column, nullable=False)
        op.drop_column(table, "minimised_at")

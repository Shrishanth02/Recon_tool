"""P1: cross-scanner correlation fields on findings.

Adds the columns that let a finding be linked to other scanner results that
refer to the same underlying security issue, without merging them:

    findings.correlation_id  (str, indexed, nullable)  — group id, NULL if alone
    findings.related         (JSON list)                default []  — [{id,source,name}]

Additive with a safe server default, so existing rows upgrade cleanly.

Revision ID: 0013_finding_correlation
Revises: 0012_finding_evidence
"""
from alembic import op
import sqlalchemy as sa

revision = "0013_finding_correlation"
down_revision = "0012_finding_evidence"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "findings",
        sa.Column("correlation_id", sa.String(length=64), nullable=True),
    )
    op.add_column(
        "findings",
        sa.Column("related", sa.JSON(), nullable=False, server_default="[]"),
    )
    op.create_index("ix_findings_correlation_id", "findings", ["correlation_id"])


def downgrade() -> None:
    op.drop_index("ix_findings_correlation_id", table_name="findings")
    op.drop_column("findings", "related")
    op.drop_column("findings", "correlation_id")

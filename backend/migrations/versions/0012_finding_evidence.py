"""P0: finding evidence, validation tier, kind, confidence & dedup.

Adds the columns that let a Finding distinguish a raw scanner SIGNAL from a
safely-VALIDATED result, carry structured evidence, hold a confidence score,
be classified as vuln/hardening/recon/info, and be deduplicated across repeated
scans:

    findings.detection_tier  (signal | validated | exploited)  default 'signal'
    findings.kind            (vuln | hardening | recon | info)  default 'vuln'
    findings.confidence      (0-100 int)                        default 50
    findings.evidence        (JSON)                             default {}
    findings.dedupe_key      (str, indexed, nullable)
    findings.seen_count      (int)                              default 1

All are additive with safe server defaults, so existing rows upgrade cleanly and
the pre-P0 behaviour is preserved for legacy findings.

Revision ID: 0012_finding_evidence
Revises: 0011_p6_run_process
"""
from alembic import op
import sqlalchemy as sa

revision = "0012_finding_evidence"
down_revision = "0011_p6_run_process"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "findings",
        sa.Column(
            "detection_tier", sa.String(length=12), nullable=False,
            server_default="signal",
        ),
    )
    op.add_column(
        "findings",
        sa.Column("kind", sa.String(length=12), nullable=False, server_default="vuln"),
    )
    op.add_column(
        "findings",
        sa.Column("confidence", sa.Integer(), nullable=False, server_default="50"),
    )
    op.add_column(
        "findings",
        sa.Column("evidence", sa.JSON(), nullable=False, server_default="{}"),
    )
    op.add_column(
        "findings",
        sa.Column("dedupe_key", sa.String(length=64), nullable=True),
    )
    op.add_column(
        "findings",
        sa.Column("seen_count", sa.Integer(), nullable=False, server_default="1"),
    )
    op.create_index("ix_findings_dedupe_key", "findings", ["dedupe_key"])


def downgrade() -> None:
    op.drop_index("ix_findings_dedupe_key", table_name="findings")
    op.drop_column("findings", "seen_count")
    op.drop_column("findings", "dedupe_key")
    op.drop_column("findings", "evidence")
    op.drop_column("findings", "confidence")
    op.drop_column("findings", "kind")
    op.drop_column("findings", "detection_tier")

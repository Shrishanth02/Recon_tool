"""P3 purple-team: detection connectors + correlated detection results (BLUE side).

Adds the two tables that back the detection-validation flow:

* ``detection_connectors`` — one row per org-scoped SIEM/EDR integration
  (``ctype`` selects the implementation; ``config`` holds its — possibly secret —
  settings; the API schema masks secrets on the way out).
* ``detection_results``    — one row per emulated technique correlated against a
  connector (detected/count/source/evidence), a child of ``emulation_runs``.

The change is purely additive — two new tables, no changes to existing ones — so
it is safe to run against a live database. ``detection_results`` cascade on
delete of their parent ``emulation_runs`` row; their ``connector_id`` FK is
``ON DELETE SET NULL`` so historical results survive connector deletion (matching
the ORM relationships).

Revision ID: 0008_p3_detection
Revises: 0007_p2_emulation
Create Date: 2026-08-13

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0008_p3_detection"
down_revision: Union[str, None] = "0007_p2_emulation"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "detection_connectors",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "org_id",
            sa.Integer(),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column(
            "ctype", sa.String(length=20), nullable=False, server_default="mock"
        ),
        sa.Column("config", sa.JSON(), nullable=False),
        sa.Column(
            "enabled", sa.Boolean(), nullable=False, server_default=sa.true()
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.create_index(
        "ix_detection_connectors_org_id", "detection_connectors", ["org_id"]
    )

    op.create_table(
        "detection_results",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "emulation_run_id",
            sa.Integer(),
            sa.ForeignKey("emulation_runs.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "connector_id",
            sa.Integer(),
            sa.ForeignKey("detection_connectors.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("technique_id", sa.String(length=20), nullable=False),
        sa.Column(
            "technique_name", sa.String(length=200), nullable=False, server_default=""
        ),
        sa.Column("tactic", sa.String(length=40), nullable=False, server_default=""),
        sa.Column(
            "detected", sa.Boolean(), nullable=False, server_default=sa.false()
        ),
        sa.Column("count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("source", sa.String(length=40), nullable=False, server_default=""),
        sa.Column("evidence", sa.Text(), nullable=False, server_default=""),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.create_index(
        "ix_detection_results_emulation_run_id",
        "detection_results",
        ["emulation_run_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_detection_results_emulation_run_id", table_name="detection_results"
    )
    op.drop_table("detection_results")
    op.drop_index(
        "ix_detection_connectors_org_id", table_name="detection_connectors"
    )
    op.drop_table("detection_connectors")

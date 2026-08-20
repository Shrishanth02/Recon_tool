"""P2 purple-team: SAFE ATT&CK emulation runs + per-technique results.

Adds the two tables that persist the SAFE emulation engine's output:

* ``emulation_runs``     — one row per :func:`app.emulation.run_emulation`
  invocation (target, status, aggregate executed/blocked/failed tallies, and the
  verbatim engine ``summary``).
* ``technique_results``  — one row per emulated ATT&CK technique within a run
  (technique id/name/tactic, status, evidence, detail).

The change is purely additive — two new tables, no changes to existing ones — so
it is safe to run against a live database. Child ``technique_results`` cascade
on delete of their parent ``emulation_runs`` row, which in turn cascades from the
owning workspace (matching the ORM relationships).

Revision ID: 0007_p2_emulation
Revises: 0006_p1_attack
Create Date: 2026-08-13

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0007_p2_emulation"
down_revision: Union[str, None] = "0006_p1_attack"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "emulation_runs",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "workspace_id",
            sa.Integer(),
            sa.ForeignKey("workspaces.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "created_by",
            sa.Integer(),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("target", sa.String(length=500), nullable=False),
        sa.Column(
            "status", sa.String(length=20), nullable=False, server_default="running"
        ),
        sa.Column("executed", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("blocked", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("failed", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("summary", sa.JSON(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.create_index(
        "ix_emulation_runs_workspace_id", "emulation_runs", ["workspace_id"]
    )

    op.create_table(
        "technique_results",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "emulation_run_id",
            sa.Integer(),
            sa.ForeignKey("emulation_runs.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("technique_id", sa.String(length=20), nullable=False),
        sa.Column(
            "technique_name", sa.String(length=200), nullable=False, server_default=""
        ),
        sa.Column("tactic", sa.String(length=40), nullable=False, server_default=""),
        sa.Column(
            "status", sa.String(length=20), nullable=False, server_default="failed"
        ),
        sa.Column("evidence", sa.Text(), nullable=False, server_default=""),
        sa.Column("detail", sa.Text(), nullable=False, server_default=""),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.create_index(
        "ix_technique_results_emulation_run_id",
        "technique_results",
        ["emulation_run_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_technique_results_emulation_run_id", table_name="technique_results"
    )
    op.drop_table("technique_results")
    op.drop_index("ix_emulation_runs_workspace_id", table_name="emulation_runs")
    op.drop_table("emulation_runs")

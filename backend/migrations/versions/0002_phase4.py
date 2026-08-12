"""Phase 4 intelligence core: schedules, notification channels, triage results.

Adds three additive tables on top of the Phase 0-2 schema. Nothing existing is
altered, so the migration is safe to run against a live database.

Revision ID: 0002_phase4
Revises: 0001_initial
Create Date: 2026-07-16

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0002_phase4"
down_revision: Union[str, None] = "0001_initial"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "schedules",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("workspace_id", sa.Integer(), nullable=False),
        sa.Column("tool", sa.String(length=50), nullable=False),
        sa.Column("target", sa.String(length=500), nullable=False),
        sa.Column("options", sa.JSON(), nullable=False),
        sa.Column("cron", sa.String(length=120), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["workspace_id"], ["workspaces.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"], ondelete="SET NULL"),
    )
    op.create_index("ix_schedules_workspace_id", "schedules", ["workspace_id"])

    op.create_table(
        "notification_channels",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("org_id", sa.Integer(), nullable=False),
        sa.Column("ctype", sa.String(length=20), nullable=False, server_default="webhook"),
        sa.Column("config", sa.JSON(), nullable=False),
        sa.Column("events", sa.JSON(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"], ondelete="CASCADE"),
    )
    op.create_index(
        "ix_notification_channels_org_id", "notification_channels", ["org_id"]
    )

    op.create_table(
        "triage_results",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("workspace_id", sa.Integer(), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False, server_default=""),
        sa.Column("risk_narrative", sa.Text(), nullable=False, server_default=""),
        sa.Column("data", sa.JSON(), nullable=False),
        sa.Column("model", sa.String(length=100), nullable=False, server_default=""),
        sa.Column("created_by", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["workspace_id"], ["workspaces.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"], ondelete="SET NULL"),
    )
    op.create_index("ix_triage_results_workspace_id", "triage_results", ["workspace_id"])


def downgrade() -> None:
    op.drop_table("triage_results")
    op.drop_table("notification_channels")
    op.drop_table("schedules")

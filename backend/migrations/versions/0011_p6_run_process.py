"""P6: store the full auto-pentest process on the run.

Adds pentest_runs.process (JSON) so a completed run can be replayed from the
Purple Team history with its stage-by-stage output.

Revision ID: 0011_p6_run_process
Revises: 0010_p5_exploit
"""
from alembic import op
import sqlalchemy as sa

revision = "0011_p6_run_process"
down_revision = "0010_p5_exploit"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "pentest_runs",
        sa.Column("process", sa.JSON(), nullable=False, server_default="{}"),
    )


def downgrade() -> None:
    op.drop_column("pentest_runs", "process")

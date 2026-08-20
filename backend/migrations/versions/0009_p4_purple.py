"""P4 purple-team: continuous-purple config on schedules.

Adds a single nullable-defaulted ``config`` JSON column to ``schedules`` so a
schedule whose ``tool`` is ``"purple"`` can carry the purple-loop settings the
scanner ``options`` blob can't express (the detection ``connector_id`` to
validate against and an optional ``techniques`` subset). Ordinary scanner
schedules simply store an empty object, so the change is fully backward
compatible and safe to run against a live database.

Revision ID: 0009_p4_purple
Revises: 0008_p3_detection
Create Date: 2026-08-13

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0009_p4_purple"
down_revision: Union[str, None] = "0008_p3_detection"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ``server_default='{}'`` backfills existing rows with an empty JSON object so
    # the NOT NULL constraint holds without a data-migration step; the ORM keeps
    # writing an explicit ``{}`` for new rows.
    op.add_column(
        "schedules",
        sa.Column(
            "config",
            sa.JSON(),
            nullable=False,
            server_default="{}",
        ),
    )


def downgrade() -> None:
    op.drop_column("schedules", "config")

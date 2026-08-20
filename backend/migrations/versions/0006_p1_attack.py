"""P1 purple-team: MITRE ATT&CK mapping columns on findings.

Adds two nullable columns to the ``findings`` table so every finding can be
tagged with the MITRE ATT&CK technique + tactic its producing tool represents:

* ``technique_id`` — the ATT&CK technique id (e.g. ``"T1046"``).
* ``tactic``       — the ATT&CK tactic id (e.g. ``"discovery"``).

Both are nullable: a NULL means the finding's tool has no sensible ATT&CK
mapping, and pre-P1 rows keep NULLs (no backfill is required — they render as
"unmapped" until the finding is re-derived). The change is purely additive, so
it is safe to run against a live database.

Revision ID: 0006_p1_attack
Revises: 0005_p0_pentestrun
Create Date: 2026-08-13

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0006_p1_attack"
down_revision: Union[str, None] = "0005_p0_pentestrun"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "findings",
        sa.Column("technique_id", sa.String(length=20), nullable=True),
    )
    op.add_column(
        "findings",
        sa.Column("tactic", sa.String(length=40), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("findings", "tactic")
    op.drop_column("findings", "technique_id")

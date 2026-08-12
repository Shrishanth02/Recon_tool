"""Phase 3 billing core: subscriptions and licenses.

Adds two additive tables on top of the Phase 0-2/4 schema for monetization
(Stripe subscriptions in cloud mode, offline signed licenses in self-hosted
mode). Nothing existing is altered, so the migration is safe to run against a
live database and is a pure no-op for the "none" billing mode.

Revision ID: 0003_phase3
Revises: 0002_phase4
Create Date: 2026-07-16

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0003_phase3"
down_revision: Union[str, None] = "0002_phase4"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "subscriptions",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("org_id", sa.Integer(), nullable=False),
        sa.Column("provider", sa.String(length=30), nullable=False, server_default="stripe"),
        sa.Column("customer_id", sa.String(length=255), nullable=True),
        sa.Column("subscription_id", sa.String(length=255), nullable=True),
        sa.Column("plan", sa.String(length=50), nullable=False, server_default="free"),
        sa.Column("status", sa.String(length=30), nullable=False, server_default="inactive"),
        sa.Column("current_period_end", sa.DateTime(timezone=True), nullable=True),
        sa.Column("seats", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.UniqueConstraint("org_id", name="uq_subscriptions_org_id"),
    )
    op.create_index("ix_subscriptions_org_id", "subscriptions", ["org_id"])
    op.create_index("ix_subscriptions_customer_id", "subscriptions", ["customer_id"])

    op.create_table(
        "licenses",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("org_id", sa.Integer(), nullable=True),
        sa.Column("key_id", sa.String(length=128), nullable=False),
        sa.Column("tier", sa.String(length=50), nullable=False, server_default="free"),
        sa.Column("entitlements", sa.JSON(), nullable=False),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"], ondelete="SET NULL"),
        sa.UniqueConstraint("key_id", name="uq_licenses_key_id"),
    )
    op.create_index("ix_licenses_org_id", "licenses", ["org_id"])
    op.create_index("ix_licenses_key_id", "licenses", ["key_id"])


def downgrade() -> None:
    op.drop_table("licenses")
    op.drop_table("subscriptions")

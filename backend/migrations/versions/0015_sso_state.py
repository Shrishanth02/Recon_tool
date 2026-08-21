"""OIDC state/nonce hardening: single-use SSO login-transaction store.

Adds the ``sso_states`` table backing :class:`app.models.SsoState` — one row per
in-flight OIDC login, minted at the browser redirect and consumed exactly once by
the callback. It binds each authorization round-trip to an org + nonce and makes
``state`` unguessable, short-lived, single-use and replay-proof (CSRF + replay
guard). New table only, so it is safe against existing data.

Revision ID: 0015_sso_state
Revises: 0014_refresh_tokens
"""
import sqlalchemy as sa
from alembic import op

revision = "0015_sso_state"
down_revision = "0014_refresh_tokens"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "sso_states",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("state_id", sa.String(length=64), nullable=False),
        sa.Column("org_id", sa.Integer(), nullable=False),
        sa.Column("nonce", sa.String(length=64), nullable=False),
        sa.Column("consumed", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True),
            server_default=sa.func.now(), nullable=False,
        ),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"], ondelete="CASCADE"),
    )
    op.create_index("ix_sso_states_state_id", "sso_states", ["state_id"], unique=True)
    op.create_index("ix_sso_states_org_id", "sso_states", ["org_id"])


def downgrade() -> None:
    op.drop_index("ix_sso_states_org_id", table_name="sso_states")
    op.drop_index("ix_sso_states_state_id", table_name="sso_states")
    op.drop_table("sso_states")

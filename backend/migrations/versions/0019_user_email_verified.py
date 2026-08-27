"""Add users.email_verified to close SSO account pre-hijacking.

A password account is created for ANY well-formed email with no ownership proof,
and SSO JIT provisioning adopts a pre-existing account matched by raw email —
so an attacker who pre-registers ``victim@corp.com`` is silently merged onto when
the real owner later signs in via the org's SSO. There was no state that told a
proven-owner account apart from a planted one.

This adds a single boolean ``email_verified`` (default False). Password
registration leaves it False; login is NOT gated on it. The first SSO adoption
of an unverified account neutralizes any pre-set password and revokes its
sessions (see ``app.sso.provision_sso_user``), then marks it verified so repeat
SSO logins are untouched.

Existing rows backfill to False via the server_default; a password-only user who
never uses SSO is never affected, and a legitimate password-first user's first
SSO login performs the one-time, intended eviction (SSO still succeeds).

Revision ID: 0019_user_email_verified
Revises: 0018_exploit_approval_binding
"""
import sqlalchemy as sa
from alembic import op

revision = "0019_user_email_verified"
down_revision = "0018_exploit_approval_binding"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("users") as batch:
        batch.add_column(
            sa.Column("email_verified", sa.Boolean(), nullable=False,
                      server_default=sa.false())
        )


def downgrade() -> None:
    with op.batch_alter_table("users") as batch:
        batch.drop_column("email_verified")

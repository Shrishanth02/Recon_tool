"""Widen users.mfa_secret to hold the TOTP secret encrypted at rest.

The MFA secret is now stored encrypted (``app.secretbox``: ``enc:v1:`` + a Fernet
token) instead of as a bare base32 string. Fernet ciphertext is far longer than
the original ``String(64)`` column, so the column is widened to ``String(255)``.

This is a widening ALTER only — existing rows (bare-plaintext legacy secrets)
remain valid and are read back verbatim by ``secretbox.decrypt_value`` (which
passes any value lacking the ``enc:v1:`` prefix straight through); they become
ciphertext the next time the user re-enrolls. No data is transformed here.

Revision ID: 0016_mfa_secret_encrypted
Revises: 0015_sso_state
"""
import sqlalchemy as sa
from alembic import op

revision = "0016_mfa_secret_encrypted"
down_revision = "0015_sso_state"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # batch mode so the ALTER is portable: a direct ALTER on PostgreSQL, a
    # table-recreate on SQLite (which has no ALTER COLUMN). Data is preserved.
    with op.batch_alter_table("users") as batch:
        batch.alter_column(
            "mfa_secret",
            existing_type=sa.String(length=64),
            type_=sa.String(length=255),
            existing_nullable=True,
        )


def downgrade() -> None:
    # Narrowing back can truncate encrypted secrets that exceed 64 chars; kept for
    # completeness. Operators should disable/re-enroll MFA before downgrading.
    with op.batch_alter_table("users") as batch:
        batch.alter_column(
            "mfa_secret",
            existing_type=sa.String(length=255),
            type_=sa.String(length=64),
            existing_nullable=True,
        )

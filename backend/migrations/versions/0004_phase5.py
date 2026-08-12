"""Phase 5 enterprise core: branding, token revocation, and SSO config.

Additive schema changes layered on top of Phase 0-4:

* ``organizations`` gains white-label branding columns and an ``sso_default_role``.
* ``users`` gains a ``token_version`` counter for session/token revocation.
* a new ``sso_configs`` table holds per-org OIDC/SAML configuration.

All new columns are nullable or carry a server default, so SQLite's
``ALTER TABLE ... ADD COLUMN`` is sufficient and the migration is safe to run
against a live database without touching existing rows.

Revision ID: 0004_phase5
Revises: 0003_phase3
Create Date: 2026-07-16

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0004_phase5"
down_revision: Union[str, None] = "0003_phase3"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # --- Organization: white-label branding + SSO default role ------------- #
    op.add_column(
        "organizations", sa.Column("brand_name", sa.String(length=200), nullable=True)
    )
    op.add_column(
        "organizations",
        sa.Column("brand_primary_color", sa.String(length=32), nullable=True),
    )
    op.add_column(
        "organizations",
        sa.Column("brand_logo_url", sa.String(length=1000), nullable=True),
    )
    op.add_column(
        "organizations", sa.Column("report_footer", sa.Text(), nullable=True)
    )
    op.add_column(
        "organizations",
        sa.Column(
            "sso_default_role",
            sa.String(length=20),
            nullable=False,
            server_default="viewer",
        ),
    )

    # --- User: token revocation counter ------------------------------------ #
    op.add_column(
        "users",
        sa.Column(
            "token_version",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
    )

    # --- New table: sso_configs -------------------------------------------- #
    op.create_table(
        "sso_configs",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("org_id", sa.Integer(), nullable=False),
        sa.Column("provider", sa.String(length=20), nullable=False, server_default="oidc"),
        sa.Column("issuer", sa.String(length=500), nullable=True),
        sa.Column("discovery_url", sa.String(length=500), nullable=True),
        sa.Column("client_id", sa.String(length=500), nullable=True),
        sa.Column("client_secret", sa.String(length=500), nullable=True),
        sa.Column("saml_metadata", sa.Text(), nullable=True),
        sa.Column("x509_cert", sa.Text(), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.UniqueConstraint("org_id", name="uq_sso_configs_org_id"),
    )
    op.create_index("ix_sso_configs_org_id", "sso_configs", ["org_id"])


def downgrade() -> None:
    op.drop_index("ix_sso_configs_org_id", table_name="sso_configs")
    op.drop_table("sso_configs")
    op.drop_column("users", "token_version")
    op.drop_column("organizations", "sso_default_role")
    op.drop_column("organizations", "report_footer")
    op.drop_column("organizations", "brand_logo_url")
    op.drop_column("organizations", "brand_primary_color")
    op.drop_column("organizations", "brand_name")

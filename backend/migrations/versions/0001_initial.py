"""Initial schema: full multi-tenant RECON-X data model.

Creates organizations, users, memberships, workspaces, api_keys, assets, scans,
findings, and audit_logs with the appropriate foreign keys and cascade rules.

Revision ID: 0001_initial
Revises:
Create Date: 2026-07-16

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0001_initial"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "organizations",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("slug", sa.String(length=200), nullable=False),
        sa.Column("plan", sa.String(length=50), nullable=False, server_default="free"),
        sa.Column("license_tier", sa.String(length=50), nullable=False, server_default="cloud"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_organizations_slug", "organizations", ["slug"], unique=True)

    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("email", sa.String(length=320), nullable=False),
        sa.Column("password_hash", sa.String(length=255), nullable=False),
        sa.Column("full_name", sa.String(length=200), nullable=False, server_default=""),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("mfa_secret", sa.String(length=64), nullable=True),
        sa.Column("mfa_enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_users_email", "users", ["email"], unique=True)

    op.create_table(
        "memberships",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("org_id", sa.Integer(), nullable=False),
        sa.Column("role", sa.String(length=20), nullable=False, server_default="viewer"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"], ondelete="CASCADE"),
    )
    op.create_index("ix_memberships_user_id", "memberships", ["user_id"])
    op.create_index("ix_memberships_org_id", "memberships", ["org_id"])

    op.create_table(
        "workspaces",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("org_id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("slug", sa.String(length=200), nullable=False),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("scope", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"], ondelete="CASCADE"),
    )
    op.create_index("ix_workspaces_org_id", "workspaces", ["org_id"])
    op.create_index("ix_workspaces_slug", "workspaces", ["slug"])

    op.create_table(
        "api_keys",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("org_id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("prefix", sa.String(length=32), nullable=False),
        sa.Column("key_hash", sa.String(length=255), nullable=False),
        sa.Column("created_by", sa.Integer(), nullable=True),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"], ondelete="SET NULL"),
    )
    op.create_index("ix_api_keys_org_id", "api_keys", ["org_id"])
    op.create_index("ix_api_keys_prefix", "api_keys", ["prefix"])

    op.create_table(
        "assets",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("workspace_id", sa.Integer(), nullable=False),
        sa.Column("value", sa.String(length=255), nullable=False),
        sa.Column("atype", sa.String(length=20), nullable=False, server_default="domain"),
        sa.Column("verified", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("verification_method", sa.String(length=30), nullable=False, server_default="dns-txt"),
        sa.Column("verification_token", sa.String(length=64), nullable=False),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["workspace_id"], ["workspaces.id"], ondelete="CASCADE"),
    )
    op.create_index("ix_assets_workspace_id", "assets", ["workspace_id"])
    op.create_index("ix_assets_value", "assets", ["value"])

    op.create_table(
        "scans",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("workspace_id", sa.Integer(), nullable=False),
        sa.Column("created_by", sa.Integer(), nullable=True),
        sa.Column("tool", sa.String(length=50), nullable=False),
        sa.Column("target", sa.String(length=500), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False, server_default="done"),
        sa.Column("options", sa.JSON(), nullable=False),
        sa.Column("logs", sa.JSON(), nullable=False),
        sa.Column("result", sa.JSON(), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("duration", sa.Float(), nullable=False, server_default="0"),
        sa.ForeignKeyConstraint(["workspace_id"], ["workspaces.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["created_by"], ["users.id"], ondelete="SET NULL"),
    )
    op.create_index("ix_scans_workspace_id", "scans", ["workspace_id"])

    op.create_table(
        "findings",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("scan_id", sa.Integer(), nullable=False),
        sa.Column("workspace_id", sa.Integer(), nullable=False),
        sa.Column("source", sa.String(length=50), nullable=False, server_default=""),
        sa.Column("severity", sa.String(length=20), nullable=False, server_default="info"),
        sa.Column("name", sa.String(length=500), nullable=False),
        sa.Column("location", sa.String(length=1000), nullable=False, server_default=""),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("cve", sa.JSON(), nullable=False),
        sa.Column("cwe", sa.JSON(), nullable=False),
        sa.Column("cvss", sa.Float(), nullable=True),
        sa.Column("status", sa.String(length=20), nullable=False, server_default="open"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["workspace_id"], ["workspaces.id"], ondelete="CASCADE"),
    )
    op.create_index("ix_findings_scan_id", "findings", ["scan_id"])
    op.create_index("ix_findings_workspace_id", "findings", ["workspace_id"])

    op.create_table(
        "audit_logs",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("org_id", sa.Integer(), nullable=True),
        sa.Column("user_id", sa.Integer(), nullable=True),
        sa.Column("action", sa.String(length=100), nullable=False),
        sa.Column("detail", sa.Text(), nullable=False, server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="SET NULL"),
    )
    op.create_index("ix_audit_logs_org_id", "audit_logs", ["org_id"])
    op.create_index("ix_audit_logs_user_id", "audit_logs", ["user_id"])


def downgrade() -> None:
    op.drop_table("audit_logs")
    op.drop_table("findings")
    op.drop_table("scans")
    op.drop_table("assets")
    op.drop_table("api_keys")
    op.drop_table("workspaces")
    op.drop_table("memberships")
    op.drop_table("users")
    op.drop_table("organizations")

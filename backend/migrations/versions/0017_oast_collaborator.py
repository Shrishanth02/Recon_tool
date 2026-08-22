"""OAST out-of-band collaborator: probe + interaction tables.

Backs :class:`app.models.OastProbe` (a workspace-bound, short-lived callback
token planted in OOB payloads) and :class:`app.models.OastInteraction` (a recorded
hit proving the target reached our collaborator). New tables only — safe against
existing data. Tenant isolation is structural: an interaction FKs its probe, and a
probe FKs its workspace, so a callback is correlatable only by the owning scan.

Revision ID: 0017_oast_collaborator
Revises: 0016_mfa_secret_encrypted
"""
import sqlalchemy as sa
from alembic import op

revision = "0017_oast_collaborator"
down_revision = "0016_mfa_secret_encrypted"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "oast_probes",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("workspace_id", sa.Integer(), nullable=False),
        sa.Column("token", sa.String(length=64), nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=False, server_default="ssrf"),
        sa.Column(
            "created_at", sa.DateTime(timezone=True),
            server_default=sa.func.now(), nullable=False,
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["workspace_id"], ["workspaces.id"], ondelete="CASCADE"),
    )
    op.create_index("ix_oast_probes_token", "oast_probes", ["token"], unique=True)
    op.create_index("ix_oast_probes_workspace_id", "oast_probes", ["workspace_id"])

    op.create_table(
        "oast_interactions",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("probe_id", sa.Integer(), nullable=False),
        sa.Column("source_ip", sa.String(length=64), nullable=False, server_default=""),
        sa.Column("method", sa.String(length=10), nullable=False, server_default=""),
        sa.Column("path", sa.String(length=512), nullable=False, server_default=""),
        sa.Column(
            "at", sa.DateTime(timezone=True),
            server_default=sa.func.now(), nullable=False,
        ),
        sa.ForeignKeyConstraint(["probe_id"], ["oast_probes.id"], ondelete="CASCADE"),
    )
    op.create_index("ix_oast_interactions_probe_id", "oast_interactions", ["probe_id"])


def downgrade() -> None:
    op.drop_index("ix_oast_interactions_probe_id", table_name="oast_interactions")
    op.drop_table("oast_interactions")
    op.drop_index("ix_oast_probes_workspace_id", table_name="oast_probes")
    op.drop_index("ix_oast_probes_token", table_name="oast_probes")
    op.drop_table("oast_probes")

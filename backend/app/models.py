"""SQLAlchemy 2.0 ORM models for the multi-tenant RECON-X platform.

The tenancy hierarchy is::

    Organization
      ├── Membership (User ⇄ Organization, carries a role)
      ├── ApiKey     (org-scoped service principal)
      └── Workspace  (the client/engagement container; carries scope)
            ├── Asset    (ownership-verification foundation)
            ├── Scan
            │     └── Finding
            └── Finding

All primary keys are autoincrementing integers. Timestamps are stored as
timezone-aware ``DateTime`` columns with a server-side ``now()`` default and are
serialized to ISO-8601 strings in the pydantic schemas. String-valued enums
(role, severity, status, ...) are validated in the schema layer, not the DB.
"""

from datetime import datetime

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


class Organization(Base):
    """A tenant. Owns memberships, API keys, and workspaces."""

    __tablename__ = "organizations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    slug: Mapped[str] = mapped_column(String(200), unique=True, nullable=False, index=True)
    plan: Mapped[str] = mapped_column(String(50), nullable=False, default="free")
    license_tier: Mapped[str] = mapped_column(String(50), nullable=False, default="cloud")

    # --- Phase 5: white-label branding (all optional/nullable) ------------- #
    # When set, these drive the branded engagement report (see app.report). A
    # NULL value means "fall back to the RECON-X default", so pre-Phase-5 rows
    # render exactly as before.
    brand_name: Mapped[str | None] = mapped_column(String(200), nullable=True)
    brand_primary_color: Mapped[str | None] = mapped_column(String(32), nullable=True)
    brand_logo_url: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    report_footer: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Default role assigned to JIT-provisioned SSO users in this org.
    sso_default_role: Mapped[str] = mapped_column(
        String(20), nullable=False, default="viewer"
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    memberships: Mapped[list["Membership"]] = relationship(
        back_populates="organization",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    workspaces: Mapped[list["Workspace"]] = relationship(
        back_populates="organization",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    api_keys: Mapped[list["ApiKey"]] = relationship(
        back_populates="organization",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )


class User(Base):
    """A human account. May belong to many organizations via memberships."""

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    email: Mapped[str] = mapped_column(String(320), unique=True, nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    full_name: Mapped[str] = mapped_column(String(200), nullable=False, default="")
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    mfa_secret: Mapped[str | None] = mapped_column(String(64), nullable=True)
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # --- Phase 5: token revocation counter ---------------------------------- #
    # Incremented to invalidate all previously issued tokens that carry a "ver"
    # claim. Tokens minted before Phase 5 (no "ver" claim) skip the check, so
    # this is fully backward-compatible.
    token_version: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    memberships: Mapped[list["Membership"]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )


class Membership(Base):
    """Links a user to an organization with a role."""

    __tablename__ = "memberships"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    org_id: Mapped[int] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    role: Mapped[str] = mapped_column(String(20), nullable=False, default="viewer")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    user: Mapped["User"] = relationship(back_populates="memberships")
    organization: Mapped["Organization"] = relationship(back_populates="memberships")


class Workspace(Base):
    """The client/engagement container. Carries the authorized ``scope``."""

    __tablename__ = "workspaces"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    org_id: Mapped[int] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    slug: Mapped[str] = mapped_column(String(200), nullable=False, index=True)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    scope: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    organization: Mapped["Organization"] = relationship(back_populates="workspaces")
    assets: Mapped[list["Asset"]] = relationship(
        back_populates="workspace",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    scans: Mapped[list["Scan"]] = relationship(
        back_populates="workspace",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    findings: Mapped[list["Finding"]] = relationship(
        back_populates="workspace",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )


class ApiKey(Base):
    """An org-scoped service credential. Only the hash is ever stored."""

    __tablename__ = "api_keys"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    org_id: Mapped[int] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    prefix: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    key_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    created_by: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    last_used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    revoked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    organization: Mapped["Organization"] = relationship(back_populates="api_keys")


class Asset(Base):
    """A domain/IP owned by a workspace. Ownership verification is the moat."""

    __tablename__ = "assets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    workspace_id: Mapped[int] = mapped_column(
        ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False, index=True
    )
    value: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    atype: Mapped[str] = mapped_column(String(20), nullable=False, default="domain")
    verified: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    verification_method: Mapped[str] = mapped_column(
        String(30), nullable=False, default="dns-txt"
    )
    verification_token: Mapped[str] = mapped_column(String(64), nullable=False)
    verified_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    workspace: Mapped["Workspace"] = relationship(back_populates="assets")


class Scan(Base):
    """One execution of a scanner against a target within a workspace."""

    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    workspace_id: Mapped[int] = mapped_column(
        ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False, index=True
    )
    created_by: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    tool: Mapped[str] = mapped_column(String(50), nullable=False)
    target: Mapped[str] = mapped_column(String(500), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="done")
    options: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    logs: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    result: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    finished_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    duration: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)

    workspace: Mapped["Workspace"] = relationship(back_populates="scans")
    findings: Mapped[list["Finding"]] = relationship(
        back_populates="scan",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )


class Finding(Base):
    """A normalized finding derived from a scan result."""

    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[int] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    workspace_id: Mapped[int] = mapped_column(
        ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False, index=True
    )
    source: Mapped[str] = mapped_column(String(50), nullable=False, default="")
    severity: Mapped[str] = mapped_column(String(20), nullable=False, default="info")
    name: Mapped[str] = mapped_column(String(500), nullable=False)
    location: Mapped[str] = mapped_column(String(1000), nullable=False, default="")
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    cve: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    cwe: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    cvss: Mapped[float | None] = mapped_column(Float, nullable=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="open")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    scan: Mapped["Scan"] = relationship(back_populates="findings")
    workspace: Mapped["Workspace"] = relationship(back_populates="findings")


class Schedule(Base):
    """A recurring scan definition owned by a workspace (Phase 4).

    The ``cron`` field stores a standard 5-field crontab expression (e.g.
    ``"0 3 * * *"``). ``next_run_at``/``last_run_at`` are maintained by the
    scheduler worker; when ``next_run_at`` is ``NULL`` the worker treats the
    schedule as immediately due and recomputes the next occurrence.
    """

    __tablename__ = "schedules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    workspace_id: Mapped[int] = mapped_column(
        ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False, index=True
    )
    tool: Mapped[str] = mapped_column(String(50), nullable=False)
    target: Mapped[str] = mapped_column(String(500), nullable=False)
    options: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    cron: Mapped[str] = mapped_column(String(120), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    last_run_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    next_run_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_by: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class NotificationChannel(Base):
    """An org-scoped alert sink (Slack, generic webhook, or email) (Phase 4).

    ``config`` carries the delivery target (e.g. ``{"url": "..."}`` for
    slack/webhook or ``{"email": "..."}`` for email). ``events`` is the list of
    event types the channel subscribes to; ``"*"`` matches every event.
    """

    __tablename__ = "notification_channels"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    org_id: Mapped[int] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    ctype: Mapped[str] = mapped_column(String(20), nullable=False, default="webhook")
    config: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    events: Mapped[list] = mapped_column(
        JSON, nullable=False, default=lambda: ["new_finding"]
    )
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class TriageResult(Base):
    """A persisted AI-triage run over a workspace's findings (Phase 4).

    ``data`` stores the full structured :class:`~app.ai.TriageOut` payload; the
    ``summary``/``risk_narrative`` columns duplicate the headline fields for
    cheap listing without deserializing the JSON blob.
    """

    __tablename__ = "triage_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    workspace_id: Mapped[int] = mapped_column(
        ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False, index=True
    )
    summary: Mapped[str] = mapped_column(Text, nullable=False, default="")
    risk_narrative: Mapped[str] = mapped_column(Text, nullable=False, default="")
    data: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    model: Mapped[str] = mapped_column(String(100), nullable=False, default="")
    created_by: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class Subscription(Base):
    """An org's billing subscription (Phase 3, cloud/Stripe mode).

    One row per organization. In SaaS mode the ``plan``/``status`` fields are
    driven by Stripe webhooks; ``customer_id``/``subscription_id`` link back to
    the Stripe objects. ``status`` follows Stripe's vocabulary (``active``,
    ``trialing``, ``past_due``, ``canceled``, ...); only ``active``/``trialing``
    grant the paid plan (see :func:`app.billing.effective_plan`).
    """

    __tablename__ = "subscriptions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    org_id: Mapped[int] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
        index=True,
    )
    provider: Mapped[str] = mapped_column(String(30), nullable=False, default="stripe")
    customer_id: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    subscription_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    plan: Mapped[str] = mapped_column(String(50), nullable=False, default="free")
    status: Mapped[str] = mapped_column(String(30), nullable=False, default="inactive")
    current_period_end: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    seats: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )


class License(Base):
    """A record of an installed/issued offline license token (Phase 3).

    Self-hosted deployments verify a signed token at runtime (see
    :mod:`app.licensing`); this table persists the decoded entitlements for
    auditing and revocation. ``org_id`` is nullable (a license may be recorded
    before it is bound to an org). ``key_id`` mirrors the token's ``jti``.
    """

    __tablename__ = "licenses"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    org_id: Mapped[int | None] = mapped_column(
        ForeignKey("organizations.id", ondelete="SET NULL"), nullable=True, index=True
    )
    key_id: Mapped[str] = mapped_column(String(128), unique=True, nullable=False, index=True)
    tier: Mapped[str] = mapped_column(String(50), nullable=False, default="free")
    entitlements: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    issued_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    revoked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class AuditLog(Base):
    """An append-only record of security-relevant actions."""

    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    org_id: Mapped[int | None] = mapped_column(
        ForeignKey("organizations.id", ondelete="SET NULL"), nullable=True, index=True
    )
    user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    detail: Mapped[str] = mapped_column(Text, nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class SsoConfig(Base):
    """Per-organization single sign-on configuration (Phase 5).

    One row per org (enforced by a unique ``org_id``). ``provider`` selects the
    protocol: ``"oidc"`` uses the discovery/client fields; ``"saml"`` uses the
    metadata/certificate fields. Secrets (``client_secret``/``x509_cert``) are
    persisted but never echoed back through the API — the schema layer masks
    them. ``enabled`` gates whether this org may actually initiate an SSO login,
    on top of the global :attr:`app.config.Settings.SSO_ENABLED` master switch.
    """

    __tablename__ = "sso_configs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    org_id: Mapped[int] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
        index=True,
    )
    provider: Mapped[str] = mapped_column(String(20), nullable=False, default="oidc")
    # OIDC fields.
    issuer: Mapped[str | None] = mapped_column(String(500), nullable=True)
    discovery_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    client_id: Mapped[str | None] = mapped_column(String(500), nullable=True)
    client_secret: Mapped[str | None] = mapped_column(String(500), nullable=True)
    # SAML fields.
    saml_metadata: Mapped[str | None] = mapped_column(Text, nullable=True)
    x509_cert: Mapped[str | None] = mapped_column(Text, nullable=True)

    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

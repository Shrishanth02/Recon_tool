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
    # Holds the TOTP secret ENCRYPTED at rest (app.secretbox, "enc:v1:" + Fernet
    # token) — widened from 64 to fit ciphertext. Legacy rows may still hold a
    # bare base32 plaintext secret; secretbox.decrypt_value passes those through.
    mfa_secret: Mapped[str | None] = mapped_column(String(255), nullable=True)
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
    # --- Purple-Team P1: MITRE ATT&CK mapping (both nullable) --------------- #
    # ``technique_id`` is the ATT&CK technique (e.g. "T1046"); ``tactic`` is the
    # tactic id (e.g. "discovery"). NULL means the finding's tool has no sensible
    # ATT&CK mapping; pre-P1 rows are NULL and render as "unmapped".
    technique_id: Mapped[str | None] = mapped_column(String(20), nullable=True)
    tactic: Mapped[str | None] = mapped_column(String(40), nullable=True)
    # --- P0: detection tier, classification, confidence & evidence ---------- #
    # ``detection_tier`` encodes trust and is the SIGNAL / VALIDATED / EXPLOITED
    # distinction the product cares about:
    #   * "signal"    — a scanner reported a possible issue (no verification);
    #   * "validated" — the platform performed a SAFE check and holds evidence;
    #   * "exploited" — set ONLY by the human-approved P5 exploit path. The
    #                   automated Auto-Pentest pipeline must never set this.
    detection_tier: Mapped[str] = mapped_column(
        String(12), nullable=False, default="signal", server_default="signal"
    )
    # ``kind`` separates genuine vulnerabilities from informational/recon/
    # hardening signal so the latter never inflate the vulnerability risk score:
    # "vuln" | "hardening" | "recon" | "info".
    kind: Mapped[str] = mapped_column(
        String(12), nullable=False, default="vuln", server_default="vuln"
    )
    # 0-100 confidence that the finding is real and correctly rated. Weighted
    # into the risk score so low-confidence signals count for less than
    # high-confidence validated findings.
    confidence: Mapped[int] = mapped_column(
        Integer, nullable=False, default=50, server_default="50"
    )
    # Structured, source-specific supporting evidence (request/response, AXFR
    # records, matched parameter, secret preview, …). Never invented — only what
    # the scanner actually observed.
    evidence: Mapped[dict] = mapped_column(
        JSON, nullable=False, default=dict, server_default="{}"
    )
    # Stable identity used to deduplicate repeated scans; NULL on legacy rows.
    dedupe_key: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    # How many times this finding has been re-observed (incremented on a dedup
    # hit instead of inserting a duplicate row).
    seen_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=1, server_default="1"
    )
    # --- P1: cross-scanner correlation ------------------------------------- #
    # ``correlation_id`` groups findings that refer to the SAME underlying issue
    # across different scanners (NULL when a finding stands alone). ``related``
    # lists the other findings in that group as ``{id, source, name}`` so a
    # finding can show exactly which other scanner results support it — without
    # merging them (each keeps its own source + evidence).
    correlation_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    related: Mapped[list] = mapped_column(JSON, nullable=False, default=list, server_default="[]")
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
    # --- Purple-Team P4: continuous-purple config (nullable/defaulted) ------ #
    # For a ``tool == "purple"`` schedule this carries the purple-loop settings
    # the scanner ``options`` blob can't express — e.g. ``{"connector_id": 3,
    # "techniques": ["E1", "E4"]}``. It is an empty dict for ordinary scanner
    # schedules, so pre-P4 rows are unaffected.
    config: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
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


class PentestRun(Base):
    """One execution of the automated end-to-end pentest pipeline (P0).

    A ``PentestRun`` records a single ``run_pipeline`` invocation so that
    auto-pentest results are first-class alongside the manual ``Scan`` history.
    The individual per-stage tool outputs are still persisted as ordinary
    ``Scan`` rows (feeding Findings/risk/diff/AI/report); this row is the
    top-level envelope that ties them together and stores the aggregate risk.

    ``summary`` holds the ``pipeline_done`` summary dict verbatim. ``status`` is
    ``"running"`` while the pipeline streams and becomes ``"done"`` (or an error
    state) once it finishes. ``created_by`` is nullable and set NULL if the user
    is later deleted, mirroring :class:`Scan`.
    """

    __tablename__ = "pentest_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    workspace_id: Mapped[int] = mapped_column(
        ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False, index=True
    )
    created_by: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    target: Mapped[str] = mapped_column(String(500), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="running")
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    risk_label: Mapped[str] = mapped_column(String(20), nullable=False, default="")
    summary: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    # Full stage-by-stage process (name, status, trimmed logs, result per stage)
    # so a completed run can be replayed from the Purple Team history exactly as
    # it streamed live. Empty {} for older runs captured before this existed.
    process: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    finished_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
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


class RefreshToken(Base):
    """A single issued refresh token, tracked for rotation + reuse detection.

    Each successful login mints one row with a fresh ``jti`` and a new
    ``family_id`` (the rotation lineage). ``/auth/refresh`` marks the presented
    token ``consumed_at`` and mints its successor in the same family. Presenting
    an already-consumed token (``consumed_at`` set) is REPLAY: the whole family is
    revoked (``revoked=True``) so a stolen token cannot outlive its rotation. This
    is per-session, not per-account, so it never causes an account-wide lockout.
    """

    __tablename__ = "refresh_tokens"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    jti: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    family_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    consumed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    revoked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class SsoState(Base):
    """A single in-flight OIDC login transaction (CSRF + replay guard).

    One row is minted by ``/auth/sso/{slug}/login`` at the moment the browser is
    redirected to the identity provider, and consumed exactly once by the OIDC
    callback. It binds the round-trip to:

    * a specific **org** (``org_id``) — a state minted for org A can never
      authenticate into org B;
    * the OIDC **nonce** returned in the provider's id_token — replay of a
      captured id_token is rejected;
    * a short **lifetime** (``expires_at``) and **single use** (``consumed``) —
      once the callback claims the row it is dead, so the same ``state`` value
      can never be redeemed twice.

    ``state_id`` is an unguessable random token that travels as the OIDC ``state``
    parameter *and* is set as a browser-scoped httpOnly cookie; the callback
    requires the two to match, which binds the flow to the browser that started
    it (defeats login-CSRF). The row is the single source of truth for the org +
    nonce, so neither is trusted from the tamperable ``state`` string itself.
    """

    __tablename__ = "sso_states"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    state_id: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    org_id: Mapped[int] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    nonce: Mapped[str] = mapped_column(String(64), nullable=False)
    consumed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class EmulationRun(Base):
    """One execution of the SAFE ATT&CK emulation engine (Purple-Team P2).

    An ``EmulationRun`` records a single :func:`app.emulation.run_emulation`
    invocation against one authorized target. The individual per-technique
    outcomes are stored as child :class:`TechniqueResult` rows; this envelope
    carries the aggregate tallies (``executed``/``blocked``/``failed``) and the
    verbatim engine summary.

    Every emulation is scope + SSRF (netguard) + billing gated by its router
    before this row is created, and every technique is non-destructive by design.
    ``created_by`` is nullable and set NULL if the user is later deleted,
    mirroring :class:`Scan` / :class:`PentestRun`.
    """

    __tablename__ = "emulation_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    workspace_id: Mapped[int] = mapped_column(
        ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False, index=True
    )
    created_by: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    target: Mapped[str] = mapped_column(String(500), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="running")
    executed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    blocked: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    failed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    summary: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    finished_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    technique_results: Mapped[list["TechniqueResult"]] = relationship(
        back_populates="emulation_run",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="TechniqueResult.id",
    )


class TechniqueResult(Base):
    """The outcome of one SAFE emulated ATT&CK technique (Purple-Team P2).

    A child of :class:`EmulationRun`. ``status`` is one of ``executed`` (the
    benign action reached the target and produced telemetry), ``blocked`` (the
    target/WAF refused it — itself a useful detection signal), ``failed`` (the
    probe errored), or ``skipped`` (not run, e.g. the run was canceled).
    ``evidence`` is a short human string (``"HTTP 403"``); ``detail`` is longer
    free-form context.
    """

    __tablename__ = "technique_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    emulation_run_id: Mapped[int] = mapped_column(
        ForeignKey("emulation_runs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    technique_id: Mapped[str] = mapped_column(String(20), nullable=False)
    technique_name: Mapped[str] = mapped_column(String(200), nullable=False, default="")
    tactic: Mapped[str] = mapped_column(String(40), nullable=False, default="")
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="failed")
    evidence: Mapped[str] = mapped_column(Text, nullable=False, default="")
    detail: Mapped[str] = mapped_column(Text, nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    emulation_run: Mapped["EmulationRun"] = relationship(
        back_populates="technique_results"
    )


class DetectionConnector(Base):
    """An org-scoped integration to a defender SIEM/EDR (Purple-Team P3).

    A ``DetectionConnector`` is what the BLUE side of the platform queries to ask
    "did you detect this technique?" (see :mod:`app.connectors` /
    :mod:`app.detection`). ``ctype`` selects the implementation (``"mock"``,
    ``"http"``, ``"splunk"``, ``"elastic"``); ``config`` carries the
    type-specific settings.

    WARNING: ``config`` may hold secrets (API tokens, Splunk bearer tokens,
    Elastic API keys, HTTP auth). It is persisted as-is so the connector can run,
    but the API schema (:class:`app.schemas.DetectionConnectorOut`) **masks** it —
    the raw secret values are never echoed back over the API.
    """

    __tablename__ = "detection_connectors"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    org_id: Mapped[int] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    ctype: Mapped[str] = mapped_column(String(20), nullable=False, default="mock")
    config: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class DetectionResult(Base):
    """The verdict of one technique correlated against a connector (P3).

    A child of an :class:`EmulationRun`: for each emulated technique that
    produced telemetry, :func:`app.detection.validate_emulation` asks the
    connector whether it was detected and persists the answer here. ``detected``
    is the headline verdict; ``count`` is how many matching events the SIEM
    returned; ``source`` is the connector type that answered; ``evidence`` is a
    short human string explaining the verdict (or the error, when the SIEM query
    failed — connectors degrade to ``detected=False`` rather than raising).

    ``connector_id`` is nullable and set NULL if the connector is later deleted,
    so historical detection results survive connector churn (mirroring the
    ``created_by`` SET NULL pattern used elsewhere).
    """

    __tablename__ = "detection_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    emulation_run_id: Mapped[int] = mapped_column(
        ForeignKey("emulation_runs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    connector_id: Mapped[int | None] = mapped_column(
        ForeignKey("detection_connectors.id", ondelete="SET NULL"), nullable=True
    )
    technique_id: Mapped[str] = mapped_column(String(20), nullable=False)
    technique_name: Mapped[str] = mapped_column(String(200), nullable=False, default="")
    tactic: Mapped[str] = mapped_column(String(40), nullable=False, default="")
    detected: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    source: Mapped[str] = mapped_column(String(40), nullable=False, default="")
    evidence: Mapped[str] = mapped_column(Text, nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


# --------------------------------------------------------------------------- #
# Purple-Team P5: human-gated, non-destructive exploitation proposals
# --------------------------------------------------------------------------- #
class ExploitProposal(Base):
    """A proposed, human-gated, NON-DESTRUCTIVE validation probe (Purple-Team P5).

    An ``ExploitProposal`` is the platform's honest market boundary between
    *automated reconnaissance/validation* and *actual exploitation*. The engine
    (:mod:`app.exploit`) automatically **proposes** which findings warrant a SAFE
    reachability/validation probe, but it will never execute one on its own: a
    proposal must be moved to ``status == "approved"`` by a privileged human
    (admin+) before :func:`app.exploit.execute` will act, and even then the probe
    is a benign, read-only check (the same philosophy as :mod:`app.emulation` —
    TCP connect / benign HTTP with an ``X-RECONX-EXPLOIT-CHECK`` marker), never a
    destructive payload, shell, or data-exfiltration.

    Lifecycle of ``status``::

        proposed --approve--> approved --execute--> executed
                \\--reject--> rejected            \\--> failed (guarded error)

    ``result`` holds the recorded probe evidence (a ``{probe, evidence,
    non_destructive, executed_at}`` dict) once executed. This is a NEW table and
    is created at runtime by ``Base.metadata.create_all``; migration
    ``0010_p5_exploit`` mirrors it for Alembic parity.
    """

    __tablename__ = "exploit_proposals"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    workspace_id: Mapped[int] = mapped_column(
        ForeignKey("workspaces.id", ondelete="CASCADE"), nullable=False, index=True
    )
    finding_id: Mapped[int | None] = mapped_column(
        ForeignKey("findings.id", ondelete="SET NULL"), nullable=True, index=True
    )
    technique_id: Mapped[str | None] = mapped_column(String(20), nullable=True)
    title: Mapped[str] = mapped_column(String(500), nullable=False, default="")
    rationale: Mapped[str] = mapped_column(Text, nullable=False, default="")
    #: proposed | approved | rejected | executed | failed
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="proposed")
    created_by: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    approved_by: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    result: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

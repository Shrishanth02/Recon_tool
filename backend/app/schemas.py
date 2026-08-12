"""Pydantic v2 request/response models for the RECON-X API.

Response models set ``from_attributes=True`` so they can be built directly from
SQLAlchemy ORM instances. Timezone-aware ``datetime`` fields serialize to
ISO-8601 strings automatically. String enums are validated here rather than in
the database.
"""

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field

Role = Literal["owner", "admin", "analyst", "viewer"]
Severity = Literal["critical", "high", "medium", "low", "info"]
FindingStatus = Literal["open", "triaged", "false_positive", "resolved"]


class ORMModel(BaseModel):
    """Base for all response models read straight off ORM objects."""

    model_config = ConfigDict(from_attributes=True)


# --------------------------------------------------------------------------- #
# Auth
# --------------------------------------------------------------------------- #
class RegisterIn(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=200)
    full_name: str = Field(default="", max_length=200)
    org_name: str | None = Field(default=None, max_length=200)


class LoginIn(BaseModel):
    email: EmailStr
    password: str
    mfa_code: str | None = None


class RefreshIn(BaseModel):
    refresh_token: str


class TokenOut(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class UserOut(ORMModel):
    id: int
    email: str
    full_name: str
    is_active: bool
    mfa_enabled: bool
    created_at: datetime


class OrgOut(ORMModel):
    id: int
    name: str
    slug: str
    plan: str
    license_tier: str
    created_at: datetime


class MembershipOut(ORMModel):
    id: int
    org_id: int
    user_id: int
    role: Role
    created_at: datetime


class WorkspaceOut(ORMModel):
    id: int
    org_id: int
    name: str
    slug: str
    description: str
    scope: list[str]
    created_at: datetime
    scan_count: int = 0
    finding_count: int = 0
    severity_counts: dict[str, int] = Field(default_factory=dict)


class RegisterOut(BaseModel):
    """The full payload returned from register/login-with-org convenience."""

    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    user: UserOut
    org: OrgOut
    workspace: WorkspaceOut


class MeOut(BaseModel):
    user: UserOut
    memberships: list[MembershipOut]
    orgs: list[OrgOut]


class MfaEnrollOut(BaseModel):
    secret: str
    otpauth_uri: str


class MfaVerifyIn(BaseModel):
    code: str


# --------------------------------------------------------------------------- #
# Organizations / members / API keys
# --------------------------------------------------------------------------- #
class OrgIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)


class MemberIn(BaseModel):
    email: EmailStr
    role: Role = "viewer"


class MemberRoleIn(BaseModel):
    role: Role


class MemberOut(ORMModel):
    id: int                 # membership id
    user_id: int
    org_id: int
    role: Role
    email: str = ""
    full_name: str = ""
    created_at: datetime


class ApiKeyIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)


class ApiKeyOut(ORMModel):
    id: int
    org_id: int
    name: str
    prefix: str
    revoked: bool
    created_by: int | None = None
    last_used_at: datetime | None = None
    created_at: datetime
    # Present only on creation.
    key: str | None = None


# --------------------------------------------------------------------------- #
# Workspaces / scope / assets
# --------------------------------------------------------------------------- #
class WorkspaceIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=2000)
    scope: list[str] = Field(default_factory=list)


class ScopeIn(BaseModel):
    scope: list[str] = Field(default_factory=list)


class AssetIn(BaseModel):
    value: str = Field(min_length=1, max_length=255)
    atype: Literal["domain", "ip"] = "domain"


class AssetOut(ORMModel):
    id: int
    workspace_id: int
    value: str
    atype: str
    verified: bool
    verification_method: str
    verification_token: str
    verified_at: datetime | None = None
    created_at: datetime
    # Populated by the create endpoint to guide the user.
    dns_record_name: str | None = None
    dns_record_value: str | None = None
    instructions: str | None = None


# --------------------------------------------------------------------------- #
# Scans / findings
# --------------------------------------------------------------------------- #
class ScanSummaryOut(ORMModel):
    id: int
    workspace_id: int
    tool: str
    target: str
    status: str
    started_at: datetime | None = None
    duration: float = 0.0


class ScanOut(ORMModel):
    id: int
    workspace_id: int
    created_by: int | None = None
    tool: str
    target: str
    status: str
    options: dict[str, Any] = Field(default_factory=dict)
    logs: list[Any] = Field(default_factory=list)
    result: dict[str, Any] | None = None
    error: str | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None
    duration: float = 0.0


class FindingOut(ORMModel):
    id: int
    scan_id: int
    workspace_id: int
    source: str
    severity: Severity
    name: str
    location: str
    description: str
    cve: list[str] = Field(default_factory=list)
    cwe: list[str] = Field(default_factory=list)
    cvss: float | None = None
    status: FindingStatus
    created_at: datetime


class FindingPatchIn(BaseModel):
    status: FindingStatus


# --------------------------------------------------------------------------- #
# Phase 4: schedules
# --------------------------------------------------------------------------- #
class ScheduleIn(BaseModel):
    tool: str = Field(min_length=1, max_length=50)
    target: str = Field(min_length=1, max_length=500)
    cron: str = Field(min_length=1, max_length=120)
    options: dict[str, Any] = Field(default_factory=dict)
    enabled: bool = True


class ScheduleOut(ORMModel):
    id: int
    workspace_id: int
    tool: str
    target: str
    cron: str
    options: dict[str, Any] = Field(default_factory=dict)
    enabled: bool
    last_run_at: datetime | None = None
    next_run_at: datetime | None = None
    created_by: int | None = None
    created_at: datetime


# --------------------------------------------------------------------------- #
# Phase 4: notification channels
# --------------------------------------------------------------------------- #
ChannelType = Literal["slack", "webhook", "email"]


class ChannelIn(BaseModel):
    ctype: ChannelType
    config: dict[str, Any] = Field(default_factory=dict)
    events: list[str] = Field(default_factory=lambda: ["new_finding"])
    enabled: bool = True


class ChannelOut(ORMModel):
    id: int
    org_id: int
    ctype: str
    config: dict[str, Any] = Field(default_factory=dict)
    events: list[str] = Field(default_factory=list)
    enabled: bool
    created_at: datetime


# --------------------------------------------------------------------------- #
# Phase 4: AI triage
# --------------------------------------------------------------------------- #
class TriagedFindingSchema(BaseModel):
    finding_id: int
    verdict: str = "needs_review"
    suggested_severity: str = ""
    remediation: str = ""
    rationale: str = ""


class TriageOutSchema(BaseModel):
    """The structured triage payload (mirrors :class:`app.ai.TriageOut`)."""

    summary: str = ""
    risk_narrative: str = ""
    items: list[TriagedFindingSchema] = Field(default_factory=list)
    dedup_groups: list[list[int]] = Field(default_factory=list)


class TriageSummaryOut(ORMModel):
    """A persisted triage run's headline fields plus full payload."""

    id: int
    workspace_id: int
    summary: str
    risk_narrative: str
    model: str
    data: dict[str, Any] = Field(default_factory=dict)
    created_by: int | None = None
    created_at: datetime


class TriageRunOut(BaseModel):
    """The envelope returned by an on-demand triage endpoint."""

    enabled: bool
    model: str | None = None
    reason: str | None = None
    refused: bool = False
    result: TriageOutSchema | None = None


# --------------------------------------------------------------------------- #
# Phase 4: risk score + finding diff
# --------------------------------------------------------------------------- #
class RiskOut(BaseModel):
    score: int
    rating: str
    counts: dict[str, int] = Field(default_factory=dict)
    total: int


class DiffCounts(BaseModel):
    new: int = 0
    resolved: int = 0
    unchanged: int = 0


class DiffOut(BaseModel):
    new: list[dict[str, Any]] = Field(default_factory=list)
    resolved: list[dict[str, Any]] = Field(default_factory=list)
    unchanged: list[dict[str, Any]] = Field(default_factory=list)
    counts: DiffCounts = Field(default_factory=DiffCounts)


# --------------------------------------------------------------------------- #
# Phase 3: billing — plans, status, checkout, licensing
# --------------------------------------------------------------------------- #
class PlanOut(BaseModel):
    """A single billing plan from the static catalog (:mod:`app.plans`)."""

    id: str
    name: str
    price_usd_month: float
    limits: dict[str, Any] = Field(default_factory=dict)


class BillingStatusOut(BaseModel):
    """The org's current billing posture: mode, effective plan, limits, usage."""

    mode: str
    plan: str
    limits: dict[str, Any] = Field(default_factory=dict)
    usage: dict[str, int] = Field(default_factory=dict)
    features: dict[str, bool] = Field(default_factory=dict)


class CheckoutIn(BaseModel):
    plan: str = Field(min_length=1, max_length=50)


class CheckoutOut(BaseModel):
    url: str


class LicenseInstallIn(BaseModel):
    token: str = Field(min_length=1)


class LicenseOut(BaseModel):
    """The decoded/verified entitlements of an installed license token."""

    tier: str
    entitlements: dict[str, Any] = Field(default_factory=dict)
    expires_at: datetime | None = None
    valid: bool = False


# --------------------------------------------------------------------------- #
# Phase 5: SSO config, white-label branding, audit, GDPR export
# --------------------------------------------------------------------------- #
SsoProvider = Literal["oidc", "saml"]


class SsoConfigIn(BaseModel):
    """Admin-supplied SSO configuration for an organization.

    Secrets (``client_secret``/``x509_cert``) are accepted here but are never
    echoed back by :class:`SsoConfigOut`. Any field left ``None`` is untouched on
    update.
    """

    provider: SsoProvider = "oidc"
    issuer: str | None = Field(default=None, max_length=500)
    discovery_url: str | None = Field(default=None, max_length=500)
    client_id: str | None = Field(default=None, max_length=500)
    client_secret: str | None = Field(default=None, max_length=500)
    saml_metadata: str | None = None
    x509_cert: str | None = None
    enabled: bool = False


class SsoConfigOut(ORMModel):
    """SSO configuration as returned to admins — secrets are masked.

    ``client_secret`` and ``x509_cert`` are never echoed. Instead the boolean
    ``*_set`` flags report whether a secret is configured, so the UI can show
    "configured" without exposing the value.
    """

    id: int
    org_id: int
    provider: str
    issuer: str | None = None
    discovery_url: str | None = None
    client_id: str | None = None
    saml_metadata: str | None = None
    enabled: bool
    created_at: datetime
    client_secret_set: bool = False
    x509_cert_set: bool = False

    @classmethod
    def from_config(cls, cfg: Any) -> "SsoConfigOut":
        """Build a masked view from an :class:`~app.models.SsoConfig` row."""
        return cls(
            id=cfg.id,
            org_id=cfg.org_id,
            provider=cfg.provider,
            issuer=cfg.issuer,
            discovery_url=cfg.discovery_url,
            client_id=cfg.client_id,
            saml_metadata=cfg.saml_metadata,
            enabled=cfg.enabled,
            created_at=cfg.created_at,
            client_secret_set=bool(getattr(cfg, "client_secret", None)),
            x509_cert_set=bool(getattr(cfg, "x509_cert", None)),
        )


class BrandingIn(BaseModel):
    """White-label branding for an org's engagement reports.

    Each field is optional; ``None`` leaves the current value unchanged, and an
    empty string clears it (falling back to the RECON-X default in the report).
    """

    brand_name: str | None = Field(default=None, max_length=200)
    brand_primary_color: str | None = Field(default=None, max_length=32)
    brand_logo_url: str | None = Field(default=None, max_length=1000)
    report_footer: str | None = None
    sso_default_role: Role | None = None


class BrandingOut(ORMModel):
    """An org's current branding settings."""

    brand_name: str | None = None
    brand_primary_color: str | None = None
    brand_logo_url: str | None = None
    report_footer: str | None = None
    sso_default_role: str = "viewer"


class AuditEntryOut(ORMModel):
    """A single audit-log record."""

    id: int
    org_id: int | None = None
    user_id: int | None = None
    action: str
    detail: str = ""
    created_at: datetime


class OrgExportOut(BaseModel):
    """A GDPR-style organization data export.

    Deliberately loose/dict-ish: the payload produced by
    :func:`app.crud.export_org_data` is passed through verbatim.
    """

    organization: dict[str, Any] = Field(default_factory=dict)
    members: list[dict[str, Any]] = Field(default_factory=list)
    workspaces: list[dict[str, Any]] = Field(default_factory=list)
    exported_at: str | None = None

    model_config = ConfigDict(extra="allow")

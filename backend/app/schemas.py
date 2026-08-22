"""Pydantic v2 request/response models for the RECON-X API.

Response models set ``from_attributes=True`` so they can be built directly from
SQLAlchemy ORM instances. Timezone-aware ``datetime`` fields serialize to
ISO-8601 strings automatically. String enums are validated here rather than in
the database.
"""

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

from . import secretbox
from .branding import is_hex_color, is_safe_logo_url
from .severity import normalize_severity

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
    # Optional (STEP 4): on the cookie-authenticated refresh path the rotated
    # refresh token is returned ONLY in the httpOnly cookie, never in the body, so
    # an XSS that calls /auth/refresh cannot read it. The legacy body path (a
    # programmatic client that presents the token in the request body) still
    # receives it here.
    refresh_token: str | None = None
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
    # Purple-Team P1: MITRE ATT&CK mapping (NULL when the tool is unmapped or the
    # finding predates P1). ``technique_id`` is e.g. "T1046"; ``tactic`` is the
    # tactic id e.g. "discovery".
    technique_id: str | None = None
    tactic: str | None = None
    # --- P0: detection tier / classification / confidence / evidence -------- #
    # ``detection_tier`` is the SIGNAL | VALIDATED | EXPLOITED trust level;
    # ``kind`` is vuln | hardening | recon | info; ``confidence`` is 0-100;
    # ``evidence`` holds source-specific supporting data (never invented).
    detection_tier: str = "signal"
    kind: str = "vuln"
    confidence: int = 50
    evidence: dict = Field(default_factory=dict)
    seen_count: int = 1
    # --- P1: cross-scanner correlation ------------------------------------- #
    # ``correlation_id`` groups same-issue findings; ``related`` lists the other
    # scanner results supporting this one ([{id, source, name}]).
    correlation_id: str | None = None
    related: list = Field(default_factory=list)

    @field_validator("severity", mode="before")
    @classmethod
    def _normalize_severity(cls, v):
        """Coerce any stored/scanner severity to a valid canonical value.

        A finding persisted with an out-of-vocabulary severity (e.g. nuclei's
        ``"unknown"``, an empty string, or NULL) would otherwise fail the strict
        ``Severity`` Literal and 500 the ENTIRE findings/report/risk/triage
        surface. Normalizing here means one malformed finding degrades to a safe
        ``info`` instead of taking down the whole workspace. The original value,
        when it was written, is preserved in ``evidence.raw_severity``.
        """
        return normalize_severity(v)

    @field_validator("cve", "cwe", mode="before")
    @classmethod
    def _coerce_id_list(cls, v):
        """Tolerate legacy rows where cve/cwe was stored as a bare scalar.

        Findings persisted before cve/cwe were normalized to lists may hold a
        single string (e.g. ``"CWE-693"``) or ``None``. Coerce any scalar to a
        one-element list so serializing an old finding can never 500 the whole
        findings/report endpoint. New writes already store proper lists.
        """
        if v is None:
            return []
        if isinstance(v, (list, tuple)):
            return list(v)
        return [str(v)]

    # Legacy rows created before these columns existed can surface as NULL;
    # collapse each to its safe default rather than failing serialization.
    @field_validator("detection_tier", mode="before")
    @classmethod
    def _default_tier(cls, v):
        return v or "signal"

    @field_validator("kind", mode="before")
    @classmethod
    def _default_kind(cls, v):
        return v or "vuln"

    @field_validator("confidence", mode="before")
    @classmethod
    def _default_confidence(cls, v):
        return 50 if v is None else v

    @field_validator("seen_count", mode="before")
    @classmethod
    def _default_seen(cls, v):
        return 1 if v is None else v

    @field_validator("evidence", mode="before")
    @classmethod
    def _default_evidence(cls, v):
        return v if isinstance(v, dict) else {}

    @field_validator("related", mode="before")
    @classmethod
    def _default_related(cls, v):
        return v if isinstance(v, (list, tuple)) else []


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

    @field_validator("options", mode="before")
    @classmethod
    def _mask_secret_options(cls, v):
        # Never expose stored credential material — schedule options hold it
        # ENCRYPTED at rest; masking here shows presence ("***") without leaking
        # ciphertext (or any legacy plaintext) through the API.
        return secretbox.mask_options(v)
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

    @field_validator("brand_primary_color", mode="before")
    @classmethod
    def _validate_brand_color(cls, v):
        """Reject anything that is not a plain hex color at the write boundary.

        The value is rendered inside a report ``<style>`` block, so it is treated
        as untrusted: only a hex color may be stored. ``None``/empty clears it
        (the report falls back to its default). A CSS-injection / ``</style>`` /
        ``url()`` / ``javascript:`` / SVG payload can never match and is rejected
        with 422 rather than being persisted.
        """
        if v is None:
            return None
        s = str(v).strip()
        if not s:
            return None
        if is_hex_color(s):
            return s.lower()
        raise ValueError("brand_primary_color must be a hex color, e.g. #0d9488")

    @field_validator("brand_logo_url", mode="before")
    @classmethod
    def _validate_brand_logo(cls, v):
        """Restrict the logo URL to a safe scheme (http(s) or raster data:image).

        Blocks ``javascript:``, ``data:text/html`` and ``data:image/svg+xml``
        (SVG can carry script). ``None``/empty clears it.
        """
        if v is None:
            return None
        s = str(v).strip()
        if not s:
            return None
        if is_safe_logo_url(s):
            return s
        raise ValueError(
            "brand_logo_url must be an http(s) URL or a data:image/* (non-SVG) URI"
        )


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


# --------------------------------------------------------------------------- #
# Purple-Team P1: MITRE ATT&CK coverage matrix
# --------------------------------------------------------------------------- #
class AttackCoverageOut(BaseModel):
    """The workspace's MITRE ATT&CK coverage matrix.

    Deliberately loose/dict-friendly: the payload produced by
    :func:`app.crud.attack_coverage` is passed through verbatim. Only tactics and
    techniques with at least one finding are present; ``tactics`` is ordered by
    the ATT&CK kill-chain, and each tactic's ``techniques`` carry a per-severity
    breakdown.
    """

    tactics: list[dict[str, Any]] = Field(default_factory=list)
    total_techniques: int = 0
    total_findings: int = 0

    model_config = ConfigDict(extra="allow")


# --------------------------------------------------------------------------- #
# Purple-Team P2: SAFE ATT&CK emulation
# --------------------------------------------------------------------------- #
class EmulationRunIn(BaseModel):
    """Request body for launching a SAFE ATT&CK emulation.

    ``target`` is the authorized host/URL to emulate against (scope + netguard +
    billing gated by the router). ``techniques`` optionally restricts the run to
    specific emulation ids (``["E1", "E4"]``); when omitted the whole registry
    runs.
    """

    target: str = Field(min_length=1, max_length=500)
    techniques: list[str] | None = None


class TechniqueResultOut(ORMModel):
    """One emulated ATT&CK technique's outcome within an emulation run."""

    id: int
    emulation_run_id: int
    technique_id: str
    technique_name: str = ""
    tactic: str = ""
    status: str
    evidence: str = ""
    detail: str = ""
    created_at: datetime


class EmulationRunOut(ORMModel):
    """A SAFE emulation run with its ordered per-technique results."""

    id: int
    workspace_id: int
    created_by: int | None = None
    target: str
    status: str
    executed: int = 0
    blocked: int = 0
    failed: int = 0
    summary: dict[str, Any] = Field(default_factory=dict)
    started_at: datetime | None = None
    finished_at: datetime | None = None
    created_at: datetime
    technique_results: list[TechniqueResultOut] = Field(default_factory=list)


# --------------------------------------------------------------------------- #
# Purple-Team P3: detection connectors + correlation (BLUE side)
# --------------------------------------------------------------------------- #
ConnectorType = Literal["mock", "http", "splunk", "elastic"]


class DetectionConnectorIn(BaseModel):
    """Request body for creating a detection connector.

    ``ctype`` selects the SIEM/EDR implementation; ``config`` carries the
    type-specific settings and may contain secrets (tokens, API keys). Secrets
    are accepted here but never echoed back by :class:`DetectionConnectorOut`.
    """

    name: str = Field(min_length=1, max_length=200)
    ctype: ConnectorType
    config: dict[str, Any] = Field(default_factory=dict)
    enabled: bool = True


# Config keys whose values are secret and must never be echoed back. Their
# presence is reported via ``config_keys``; their value is masked in ``config``.
_SECRET_CONFIG_KEYS: frozenset[str] = frozenset(
    {"token", "api_key", "auth", "password", "secret", "headers"}
)


class DetectionConnectorOut(ORMModel):
    """A detection connector as returned to the API — secrets are masked.

    The raw ``config`` is **never** echoed. Instead:

    * ``config_keys`` lists the configured keys (so the UI can show what's set),
    * ``config`` is a redacted copy where secret-bearing keys are replaced with
      the string ``"***"`` and non-secret scalars are passed through.
    """

    id: int
    org_id: int
    name: str
    ctype: str
    enabled: bool
    created_at: datetime
    config_keys: list[str] = Field(default_factory=list)
    config: dict[str, Any] = Field(default_factory=dict)

    @classmethod
    def from_connector(cls, connector: Any) -> "DetectionConnectorOut":
        """Build a masked view from a :class:`~app.models.DetectionConnector`."""
        raw = dict(getattr(connector, "config", None) or {})
        redacted: dict[str, Any] = {}
        for key, value in raw.items():
            if key in _SECRET_CONFIG_KEYS:
                redacted[key] = "***"
            elif isinstance(value, (str, int, float, bool)) or value is None:
                redacted[key] = value
            else:
                # Nested/complex values may themselves carry secrets — mask them.
                redacted[key] = "***"
        return cls(
            id=connector.id,
            org_id=connector.org_id,
            name=connector.name,
            ctype=connector.ctype,
            enabled=connector.enabled,
            created_at=connector.created_at,
            config_keys=sorted(raw.keys()),
            config=redacted,
        )


class DetectionResultOut(ORMModel):
    """One technique's detection verdict within an emulation run."""

    id: int
    emulation_run_id: int
    connector_id: int | None = None
    technique_id: str
    technique_name: str = ""
    tactic: str = ""
    detected: bool
    count: int = 0
    source: str = ""
    evidence: str = ""
    created_at: datetime


class DetectionSummaryOut(BaseModel):
    """The aggregate detection-coverage summary for a validation run."""

    total: int = 0
    detected: int = 0
    missed: int = 0
    coverage_pct: int = 0
    window_seconds: int = 0
    source: str = ""


class DetectionValidateOut(BaseModel):
    """The envelope returned by the validate endpoint: results + summary."""

    results: list[DetectionResultOut] = Field(default_factory=list)
    summary: DetectionSummaryOut = Field(default_factory=DetectionSummaryOut)


# --------------------------------------------------------------------------- #
# Purple-Team P4: continuous purple loop + coverage dashboard
# --------------------------------------------------------------------------- #
class PurpleRunIn(BaseModel):
    """Request body for a continuous purple run.

    ``target`` is the authorized host/URL (scope + netguard + billing gated by
    the router). ``connector_id`` optionally selects the same-org detection
    connector to validate against — when omitted the run only emulates (no
    detection scoring). ``techniques`` optionally restricts the emulation to
    specific ids (``["E1", "E4"]``).
    """

    target: str = Field(min_length=1, max_length=500)
    connector_id: int | None = None
    techniques: list[str] | None = None


class PurpleRunOut(BaseModel):
    """The envelope returned by the purple-run endpoint.

    ``summary`` is the loose engine summary (emulation tallies plus, when
    validated, ``detected``/``missed``/``coverage_pct`` and the ``drift`` key).
    ``drift`` surfaces the dispatched drift event (or ``None``) at the top level
    for convenience; it is the same object as ``summary["drift"]``.
    """

    emulation_run: EmulationRunOut
    detections: list[DetectionResultOut] = Field(default_factory=list)
    summary: dict[str, Any] = Field(default_factory=dict)
    drift: dict[str, Any] | None = None


class CoverageDashboardOut(BaseModel):
    """The continuous-purple coverage dashboard (dict-friendly / loose).

    Shapes mirror :func:`app.crud.coverage_dashboard`; nested rows are left as
    open dicts so the engine can evolve fields without a schema churn.
    """

    summary: dict[str, Any] = Field(default_factory=dict)
    techniques: list[dict[str, Any]] = Field(default_factory=list)
    tactics: list[dict[str, Any]] = Field(default_factory=list)
    trend: list[dict[str, Any]] = Field(default_factory=list)
    gaps: list[dict[str, Any]] = Field(default_factory=list)


class PentestRunOut(ORMModel):
    """A single auto-pentest run summary for the Purple Team history view."""

    id: int
    workspace_id: int
    target: str
    status: str
    risk_score: int
    risk_label: str
    summary: dict[str, Any] = Field(default_factory=dict)
    started_at: datetime | None = None
    finished_at: datetime | None = None
    created_at: datetime | None = None


class PentestRunDetailOut(PentestRunOut):
    """A run WITH its full stage-by-stage process, for the history detail view."""

    process: dict[str, Any] = Field(default_factory=dict)


# --------------------------------------------------------------------------- #
# Purple-Team P5: human-gated, non-destructive exploitation proposals
# --------------------------------------------------------------------------- #
class ExploitProposalOut(ORMModel):
    """A single human-gated, non-destructive exploitation proposal.

    Read straight off :class:`app.models.ExploitProposal`. ``result`` is the
    recorded probe evidence once the (approved) proposal has been executed, or
    ``None`` while it is still proposed/approved/rejected.
    """

    id: int
    workspace_id: int
    finding_id: int | None = None
    technique_id: str | None = None
    title: str = ""
    rationale: str = ""
    status: str = "proposed"
    created_by: int | None = None
    approved_by: int | None = None
    result: dict[str, Any] | None = None
    created_at: datetime
    updated_at: datetime


class ProposeOut(BaseModel):
    """The envelope returned when the exploit engine proposes probes."""

    proposals: list[ExploitProposalOut] = Field(default_factory=list)


class ExecuteIn(BaseModel):
    """Request body for executing an approved proposal's SAFE validation probe.

    ``target`` is the authorized host/URL the benign probe runs against; the
    router scope + netguard gates it before :func:`app.exploit.execute` acts.
    """

    target: str = Field(min_length=1, max_length=500)


class ExecuteOut(BaseModel):
    """The envelope returned after executing an approved proposal.

    ``proposal`` is the (now ``executed``/``failed``) proposal row and ``result``
    is the recorded non-destructive probe evidence dict.
    """

    proposal: ExploitProposalOut
    result: dict[str, Any] = Field(default_factory=dict)

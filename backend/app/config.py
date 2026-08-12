"""Central configuration for the RECON-X backend.

Configuration is expressed as a pydantic-settings ``Settings`` model that reads
from the process environment (and an optional ``.env`` file). A module-level
``settings`` singleton is exposed for the new multi-tenant code.

For backward compatibility with the existing scanner engine (which imports
``from .. import config`` and reads ``config.WORDLIST`` etc.) the historical
module-level constants are kept as thin aliases over ``settings``.
"""

import warnings
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

# .../recon-tool/backend/app/config.py -> parents[2] == .../recon-tool
PROJECT_ROOT_PATH = Path(__file__).resolve().parents[2]

# Default wordlist used by the dirbuster (ffuf) scanner.
_DEFAULT_WORDLIST = (
    PROJECT_ROOT_PATH / "SecLists" / "Discovery" / "Web-Content" / "common.txt"
)

# Default SQLite database, an absolute path under backend/.
_DEFAULT_DB_URL = f"sqlite:///{(PROJECT_ROOT_PATH / 'backend' / 'reconx.db').as_posix()}"


class Settings(BaseSettings):
    """Runtime configuration, populated from environment variables.

    Every field can be overridden via its environment-variable alias. Local
    development needs no configuration at all (SQLite + insecure dev secret).
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # --- Persistence -------------------------------------------------------- #
    DATABASE_URL: str = Field(default=_DEFAULT_DB_URL)
    REDIS_URL: str = Field(default="redis://localhost:6379/0")

    # --- Auth / JWT --------------------------------------------------------- #
    JWT_SECRET: str = Field(default="dev-insecure-change-me")
    JWT_ALG: str = Field(default="HS256")
    ACCESS_TTL_MIN: int = Field(default=30)
    REFRESH_TTL_DAYS: int = Field(default=14)

    # --- Optional bootstrap seed ------------------------------------------- #
    BOOTSTRAP_ADMIN_EMAIL: str = Field(default="")
    BOOTSTRAP_ADMIN_PASSWORD: str = Field(default="")
    BOOTSTRAP_ORG_NAME: str = Field(default="RECON-X")

    # --- General ------------------------------------------------------------ #
    DEBUG: bool = Field(default=True)

    # --- Scanner engine (kept from the original config) --------------------- #
    # Aliased to the historical RECONX_* env vars so existing deployments keep
    # working unchanged.
    WORDLIST: Path = Field(default=_DEFAULT_WORDLIST, alias="RECONX_WORDLIST")
    ORIGINS: str = Field(
        default="http://localhost:5173,http://127.0.0.1:5173",
        alias="RECONX_ORIGINS",
    )
    SCAN_TIMEOUT: int = Field(default=1800, alias="RECONX_SCAN_TIMEOUT")
    MAX_CONCURRENT_SCANS: int = Field(default=4, alias="RECONX_MAX_CONCURRENT")
    API_KEY: str = Field(default="", alias="RECONX_API_KEY")

    # --- Phase 2: execution core & safety gates ----------------------------- #
    # Additive and strictly behind flags that default OFF, so the verified
    # Phase 0/1 inline flow (no Redis, no Docker) keeps working unchanged.
    EXECUTION_BACKEND: str = Field(
        default="inline", alias="RECONX_EXECUTION_BACKEND"
    )  # "inline" | "queue"
    SANDBOX_MODE: str = Field(default="none", alias="RECONX_SANDBOX")  # "none" | "docker"
    SCANNER_IMAGE: str = Field(
        default="reconx-scanner:latest", alias="RECONX_SCANNER_IMAGE"
    )
    REQUIRE_VERIFIED_ASSET: bool = Field(
        default=False, alias="RECONX_REQUIRE_VERIFIED_ASSET"
    )
    BLOCK_PRIVATE_TARGETS: bool = Field(
        default=True, alias="RECONX_BLOCK_PRIVATE_TARGETS"
    )
    STREAM_TTL_SECONDS: int = Field(
        default=900, alias="RECONX_STREAM_TTL_SECONDS"
    )

    # --- Phase 4: intelligence core (AI triage, scheduling, alerting) ------- #
    # Everything here is additive and defaults to OFF/empty so the verified
    # Phase 0/1/2 flows keep working with no external service installed.
    #
    # ANTHROPIC_API_KEY is read from the plain, un-prefixed env var (matching
    # the official SDK convention) so `anthropic.Anthropic()` and this setting
    # agree on the same key.
    ANTHROPIC_API_KEY: str = Field(default="", alias="ANTHROPIC_API_KEY")
    AI_MODEL: str = Field(default="claude-opus-4-8", alias="RECONX_AI_MODEL")
    AI_EFFORT: str = Field(default="high", alias="RECONX_AI_EFFORT")

    SCHEDULER_ENABLED: bool = Field(
        default=False, alias="RECONX_SCHEDULER_ENABLED"
    )

    SMTP_HOST: str = Field(default="", alias="RECONX_SMTP_HOST")
    SMTP_PORT: int = Field(default=587, alias="RECONX_SMTP_PORT")
    SMTP_USER: str = Field(default="", alias="RECONX_SMTP_USER")
    SMTP_PASSWORD: str = Field(default="", alias="RECONX_SMTP_PASSWORD")
    SMTP_FROM: str = Field(default="", alias="RECONX_SMTP_FROM")

    # --- Phase 3: billing core (Stripe SaaS + offline license keys) --------- #
    # Everything here is additive and defaults to OFF/empty. BILLING_MODE stays
    # "none", under which every quota/entitlement check is a no-op — so the
    # verified Phase 0/1/2/4 flows (and the existing test suite) are unaffected.
    BILLING_MODE: str = Field(
        default="none", alias="RECONX_BILLING_MODE"
    )  # "none" | "cloud" | "self_hosted"

    # Stripe (cloud / SaaS mode). All optional; Stripe stays disabled until a
    # secret key is provided.
    STRIPE_SECRET_KEY: str = Field(default="", alias="RECONX_STRIPE_SECRET_KEY")
    STRIPE_WEBHOOK_SECRET: str = Field(
        default="", alias="RECONX_STRIPE_WEBHOOK_SECRET"
    )
    STRIPE_PRICE_STARTER: str = Field(
        default="", alias="RECONX_STRIPE_PRICE_STARTER"
    )
    STRIPE_PRICE_PRO: str = Field(default="", alias="RECONX_STRIPE_PRICE_PRO")
    BILLING_SUCCESS_URL: str = Field(
        default="http://localhost:5173/billing", alias="RECONX_BILLING_SUCCESS_URL"
    )
    BILLING_CANCEL_URL: str = Field(
        default="http://localhost:5173/billing", alias="RECONX_BILLING_CANCEL_URL"
    )

    # Offline license keys (self-hosted mode). LICENSE_KEY is the signed token
    # installed on a deployment; LICENSE_PUBLIC_KEY overrides the embedded
    # vendor public key; LICENSE_PRIVATE_KEY is set ONLY by the vendor/issuer.
    LICENSE_KEY: str = Field(default="", alias="RECONX_LICENSE_KEY")
    LICENSE_PUBLIC_KEY: str = Field(default="", alias="RECONX_LICENSE_PUBLIC_KEY")
    LICENSE_PRIVATE_KEY: str = Field(
        default="", alias="RECONX_LICENSE_PRIVATE_KEY"
    )

    # --- Phase 5: enterprise / compliance core ----------------------------- #
    # Every field is additive and gated so the verified Phase 0-4 flows (and the
    # existing test suite, which configures none of these) keep working. The
    # only defaults that are "on" (security headers, metrics) are harmless: they
    # add response headers / expose a read-only endpoint without changing any
    # existing behavior. Rate limiting and SSO default OFF.
    SECURITY_HEADERS: bool = Field(
        default=True, alias="RECONX_SECURITY_HEADERS"
    )  # send CSP/HSTS/nosniff/frame-deny/referrer headers
    RATE_LIMIT_ENABLED: bool = Field(
        default=False, alias="RECONX_RATE_LIMIT_ENABLED"
    )  # in-memory per-client token bucket
    RATE_LIMIT_PER_MINUTE: int = Field(
        default=120, alias="RECONX_RATE_LIMIT_PER_MINUTE"
    )
    METRICS_ENABLED: bool = Field(
        default=True, alias="RECONX_METRICS_ENABLED"
    )  # expose Prometheus /metrics endpoint
    JSON_LOGS: bool = Field(
        default=False, alias="RECONX_JSON_LOGS"
    )  # structured (JSON) access logs
    SSO_ENABLED: bool = Field(
        default=False, alias="RECONX_SSO_ENABLED"
    )  # master switch for /auth/sso/*
    OIDC_REDIRECT_BASE: str = Field(
        default="http://localhost:8002", alias="RECONX_OIDC_REDIRECT_BASE"
    )
    DATA_RETENTION_DAYS: int = Field(
        default=0, alias="RECONX_DATA_RETENTION_DAYS"
    )  # 0 = keep forever

    @property
    def billing_enabled(self) -> bool:
        """True when quota/entitlement enforcement is active (mode != none)."""
        return (self.BILLING_MODE or "none").strip().lower() != "none"

    @property
    def stripe_enabled(self) -> bool:
        """True when a Stripe secret key is configured (SaaS billing available)."""
        return bool(self.STRIPE_SECRET_KEY.strip())

    @property
    def ai_enabled(self) -> bool:
        """True iff an Anthropic API key is configured (AI triage available)."""
        return bool(self.ANTHROPIC_API_KEY.strip())

    # --- Phase 5 convenience accessors (lowercase mirrors of the flags) ---- #
    @property
    def sso_enabled(self) -> bool:
        """True when the SSO subsystem (``/auth/sso/*``) is enabled."""
        return bool(self.SSO_ENABLED)

    @property
    def security_headers(self) -> bool:
        """True when hardening response headers should be emitted."""
        return bool(self.SECURITY_HEADERS)

    @property
    def rate_limit_enabled(self) -> bool:
        """True when the in-memory request rate limiter is active."""
        return bool(self.RATE_LIMIT_ENABLED)

    @property
    def metrics_enabled(self) -> bool:
        """True when the Prometheus ``/metrics`` endpoint is exposed."""
        return bool(self.METRICS_ENABLED)

    @property
    def json_logs(self) -> bool:
        """True when access logs should be emitted as structured JSON."""
        return bool(self.JSON_LOGS)

    @property
    def use_queue(self) -> bool:
        """True when scans should run via the out-of-process arq queue."""
        return self.EXECUTION_BACKEND.strip().lower() == "queue"

    @property
    def use_docker_sandbox(self) -> bool:
        """True when scanner tools should run inside the Docker sandbox."""
        return self.SANDBOX_MODE.strip().lower() == "docker"

    @property
    def PROJECT_ROOT(self) -> Path:
        """Absolute path to the repository root (recon-tool/)."""
        return PROJECT_ROOT_PATH

    @property
    def ALLOWED_ORIGINS(self) -> list[str]:
        """CORS origins as a list, parsed from the comma-separated ORIGINS."""
        return [o.strip() for o in self.ORIGINS.split(",") if o.strip()]

    @property
    def is_sqlite(self) -> bool:
        return self.DATABASE_URL.startswith("sqlite")


settings = Settings()

# Warn loudly if a real deployment forgot to change the signing secret.
if settings.JWT_SECRET == "dev-insecure-change-me" and not settings.DEBUG:
    warnings.warn(
        "JWT_SECRET is still the insecure development default in a non-DEBUG "
        "environment. Set JWT_SECRET to a strong random value.",
        RuntimeWarning,
        stacklevel=2,
    )

# --------------------------------------------------------------------------- #
# Backward-compatibility module constants.
#
# The scanner modules (and any legacy import) expect these names at module
# scope. They mirror the corresponding ``settings`` fields.
# --------------------------------------------------------------------------- #
PROJECT_ROOT = PROJECT_ROOT_PATH
DEFAULT_WORDLIST = _DEFAULT_WORDLIST
WORDLIST = settings.WORDLIST
ALLOWED_ORIGINS = settings.ALLOWED_ORIGINS
SCAN_TIMEOUT = settings.SCAN_TIMEOUT
MAX_CONCURRENT_SCANS = settings.MAX_CONCURRENT_SCANS
API_KEY = settings.API_KEY

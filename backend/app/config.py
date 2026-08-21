"""Central configuration for the RECON-X backend.

Configuration is expressed as a pydantic-settings ``Settings`` model that reads
from the process environment (and an optional ``.env`` file). A module-level
``settings`` singleton is exposed for the new multi-tenant code.

For backward compatibility with the existing scanner engine (which imports
``from .. import config`` and reads ``config.WORDLIST`` etc.) the historical
module-level constants are kept as thin aliases over ``settings``.
"""

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
    # Schema-bootstrap policy (P1-H4). "auto" (default) runs SQLAlchemy
    # ``create_all`` ONLY for SQLite — the zero-config local/dev/test backend.
    # For Postgres the schema is authoritative via Alembic migrations
    # (``alembic upgrade head`` in entrypoint.sh / CI), so create_all is disabled
    # to prevent a model added without a migration from being silently created
    # (schema drift). "true"/"false" force the behavior regardless of backend.
    DB_AUTO_CREATE: str = Field(default="auto", alias="RECONX_DB_AUTO_CREATE")

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
    # Secure by default: DEBUG must be explicitly turned on for local dev
    # (the dev .env sets DEBUG=true). In production it stays False.
    DEBUG: bool = Field(default=False)

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
    # Scanner execution isolation level applied to every external-tool subprocess:
    #   none    - NO ISOLATION (direct child; still gets baseline env sanitization)
    #   process - PROCESS RESTRICTION (sanitized env + scratch cwd + process group
    #             + timeout + POSIX CPU rlimit) — the default, works without Docker
    #   docker  - CONTAINER ISOLATION (ephemeral hardened container; needs Docker)
    SANDBOX_MODE: str = Field(default="process", alias="RECONX_SANDBOX")
    # Policy when the requested isolation can't be provided (e.g. SANDBOX_MODE=docker
    # with no Docker): True => refuse to run the scanner; False => degrade to
    # process_restricted and report the degraded mode clearly (never silent).
    SANDBOX_REQUIRED: bool = Field(default=False, alias="RECONX_SANDBOX_REQUIRED")
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

    # --- Real exploitation (Metasploit) — OFF by default -------------------- #
    # When REAL_EXPLOIT is enabled AND a Metasploit RPC daemon is reachable, an
    # *approved* exploit proposal executes a real Metasploit module against the
    # in-scope target instead of the safe reachability probe. It stays behind the
    # same human-approval + scope + SSRF gates. Default OFF so the hosted/demo
    # build is a safe, non-destructive tool; only self-hosted operators with an
    # authorized engagement turn it on.
    REAL_EXPLOIT: bool = Field(default=False, alias="RECONX_REAL_EXPLOIT")
    MSF_HOST: str = Field(default="127.0.0.1", alias="RECONX_MSF_HOST")
    MSF_PORT: int = Field(default=55553, alias="RECONX_MSF_PORT")
    MSF_USER: str = Field(default="msf", alias="RECONX_MSF_USER")
    MSF_PASSWORD: str = Field(default="", alias="RECONX_MSF_PASSWORD")
    MSF_SSL: bool = Field(default=True, alias="RECONX_MSF_SSL")
    MSF_EXPLOIT_TIMEOUT: int = Field(default=180, alias="RECONX_MSF_EXPLOIT_TIMEOUT")

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
    # Distributed (Redis-backed) rate limiting. ON by default so production is
    # protected out of the box; the test suite disables it (conftest) and local
    # dev can set RECONX_RATE_LIMIT_ENABLED=false. Separate per-category buckets:
    #   auth    - login/register/refresh/mfa/sso: strict (brute-force defence)
    #   scan    - scan creation (GET /scan/*, /ws/pipeline, /ws/scan): moderate
    #   general - everything else: lenient (normal API browsing)
    RATE_LIMIT_ENABLED: bool = Field(
        default=True, alias="RECONX_RATE_LIMIT_ENABLED"
    )
    RATE_LIMIT_PER_MINUTE: int = Field(
        default=120, alias="RECONX_RATE_LIMIT_PER_MINUTE"
    )  # general bucket
    RATE_LIMIT_AUTH_PER_MINUTE: int = Field(
        default=10, alias="RECONX_RATE_LIMIT_AUTH_PER_MINUTE"
    )
    RATE_LIMIT_SCAN_PER_MINUTE: int = Field(
        default=20, alias="RECONX_RATE_LIMIT_SCAN_PER_MINUTE"
    )
    RATE_LIMIT_WINDOW_SECONDS: int = Field(
        default=60, alias="RECONX_RATE_LIMIT_WINDOW_SECONDS"
    )
    # Comma/space separated CIDRs of trusted reverse proxies. Only when the direct
    # peer is one of these is X-Forwarded-For trusted for the client IP; empty
    # (default) => never trust the header (spoof-proof).
    RATE_LIMIT_TRUSTED_PROXIES: str = Field(
        default="", alias="RECONX_RATE_LIMIT_TRUSTED_PROXIES"
    )
    METRICS_ENABLED: bool = Field(
        default=False, alias="RECONX_METRICS_ENABLED"
    )  # expose Prometheus /metrics endpoint (opt-in; secure-by-default OFF)
    METRICS_TOKEN: str = Field(
        default="", alias="RECONX_METRICS_TOKEN"
    )  # when set, /metrics requires `Authorization: Bearer <token>` (scrape auth)
    JSON_LOGS: bool = Field(
        default=False, alias="RECONX_JSON_LOGS"
    )  # structured (JSON) access logs
    SSO_ENABLED: bool = Field(
        default=False, alias="RECONX_SSO_ENABLED"
    )  # master switch for /auth/sso/*
    OIDC_REDIRECT_BASE: str = Field(
        default="http://localhost:8002", alias="RECONX_OIDC_REDIRECT_BASE"
    )
    SSO_STATE_TTL_SECONDS: int = Field(
        default=600, alias="RECONX_SSO_STATE_TTL_SECONDS"
    )  # OIDC login-transaction (state/nonce) lifetime; single-use within this window
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
        """True when the request rate limiter is active."""
        return bool(self.RATE_LIMIT_ENABLED)

    @property
    def rate_limit_trusted_proxies(self) -> list:
        """Trusted-proxy CIDRs (ip_network objects) for X-Forwarded-For handling.

        Empty by default, meaning the forwarded header is never trusted and the
        direct connection peer is used for rate-limit bucketing.
        """
        from .ratelimit import parse_trusted_proxies

        return parse_trusted_proxies(self.RATE_LIMIT_TRUSTED_PROXIES)

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
        """True when scanner tools are configured to run inside the Docker sandbox.

        This is only the operator's *intent*; whether container isolation is
        actually applied is decided at run time by ``app.sandbox.effective_isolation``
        (which checks Docker availability), so nothing claims container isolation
        when Docker is absent.
        """
        return self.SANDBOX_MODE.strip().lower() == "docker"

    @property
    def sandbox_required(self) -> bool:
        """True when isolation is mandatory: refuse to run a scanner if the
        requested isolation level cannot be provided."""
        return bool(self.SANDBOX_REQUIRED)

    @property
    def real_exploit_enabled(self) -> bool:
        """True when real Metasploit exploitation is turned on for this deployment.

        This is only the operator's *intent* switch; the exploit engine still
        checks that a Metasploit RPC daemon is actually reachable at run time and
        falls back to the safe probe otherwise.
        """
        return bool(self.REAL_EXPLOIT)

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

    @property
    def db_auto_create(self) -> bool:
        """Whether startup should bootstrap tables via ``create_all``.

        "auto" (default): create_all runs ONLY for SQLite. Postgres is
        migration-managed (Alembic is authoritative), so create_all is OFF to
        prevent silent schema drift. "true"/"false" force it either way.
        """
        v = (self.DB_AUTO_CREATE or "auto").strip().lower()
        if v in ("true", "1", "yes", "on"):
            return True
        if v in ("false", "0", "no", "off"):
            return False
        return self.is_sqlite


# Known-insecure JWT signing secrets that must never sign tokens in a real
# deployment: the repo's PUBLIC dev default, empty, common placeholders, the
# test suite's fixed secret, and the .env.example placeholder. Length is enforced
# separately (see :func:`validate_jwt_secret`) so weak custom values are caught
# even when they are not on this list.
_INSECURE_JWT_SECRETS = frozenset(
    {
        "",
        "dev-insecure-change-me",
        "change-me",
        "changeme",
        "changethis",
        "secret",
        "password",
        "test-secret",
        "your-secret-key",
        "CHANGE_ME_openssl_rand_hex_32",
    }
)

#: Minimum acceptable JWT secret length (characters) in a non-DEBUG deployment.
MIN_JWT_SECRET_LEN = 32


def validate_jwt_secret(*, debug: bool, secret: str) -> None:
    """Fail closed unless a production deployment has a strong, explicit JWT secret.

    In DEBUG (local dev) anything is allowed for convenience. Otherwise the secret
    must not be a known-insecure value and must be at least
    :data:`MIN_JWT_SECRET_LEN` characters long. Raises ``RuntimeError`` with
    operator remediation guidance on failure.

    Security note: the secret value is NEVER interpolated into the error message,
    so a misconfiguration cannot leak the (attempted) secret into logs.
    """
    if debug:
        return
    candidate = (secret or "").strip()
    remediation = (
        " Set JWT_SECRET to a strong random value, e.g. "
        "`export JWT_SECRET=$(openssl rand -hex 32)` (or set DEBUG=true for local "
        "development)."
    )
    if candidate in _INSECURE_JWT_SECRETS:
        raise RuntimeError(
            "JWT_SECRET is unset or an insecure default in a non-DEBUG environment. "
            "Refusing to start - booting with a known secret would let anyone forge "
            "admin tokens." + remediation
        )
    if len(candidate) < MIN_JWT_SECRET_LEN:
        raise RuntimeError(
            f"JWT_SECRET is too short ({len(candidate)} chars) for a non-DEBUG "
            f"environment; at least {MIN_JWT_SECRET_LEN} characters are required. "
            "Refusing to start." + remediation
        )


settings = Settings()

# Fail closed at import/startup: a real (non-DEBUG) deployment must have a strong,
# explicitly-configured signing secret. The dev default is a PUBLIC constant in
# this repo, so booting with it in production is a full auth bypass. Local dev
# (DEBUG=true) is unaffected.
validate_jwt_secret(debug=settings.DEBUG, secret=settings.JWT_SECRET)

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

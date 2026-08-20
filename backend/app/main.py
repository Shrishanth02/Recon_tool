"""RECON-X API — multi-tenant reconnaissance & vulnerability-assessment platform.

Version 4.0.0 turns the original single-user demo into an auth-gated,
multi-tenant service while preserving the scanner engine verbatim. It boots with
zero external services (SQLite + in-process scans) and scales up to
Postgres + Redis purely through environment variables.

Wiring:

* CORS mirrors the original (explicit origins from settings + a localhost regex
  so any Vite dev port works).
* On startup the ORM tables are created (dev/bootstrap) and, if
  ``BOOTSTRAP_ADMIN_EMAIL``/``BOOTSTRAP_ADMIN_PASSWORD`` are configured and the
  database has no users yet, a seed admin + org + default workspace is created.
* Every feature router (auth, orgs, workspaces, assets, scans, ws) is included.
* ``GET /`` and ``GET /health`` are unauthenticated liveness endpoints.
"""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from sqlalchemy import text

from . import crud, observability, preflight
from .config import settings
from .database import SessionLocal, init_models
from .middleware import (
    RateLimitMiddleware,
    RequestContextMiddleware,
    SecurityHeadersMiddleware,
)
from .routers import ROUTERS


def _bootstrap_seed() -> None:
    """Seed a first admin user + org when configured and the DB is empty."""
    if not (settings.BOOTSTRAP_ADMIN_EMAIL and settings.BOOTSTRAP_ADMIN_PASSWORD):
        return
    db = SessionLocal()
    try:
        if crud.get_user_by_email(db, settings.BOOTSTRAP_ADMIN_EMAIL):
            return
        user, org, _ws = crud.create_user_with_org(
            db,
            email=settings.BOOTSTRAP_ADMIN_EMAIL,
            password=settings.BOOTSTRAP_ADMIN_PASSWORD,
            full_name="Bootstrap Admin",
            org_name=settings.BOOTSTRAP_ORG_NAME,
        )
        crud.audit(db, org.id, user.id, "bootstrap", user.email)
        db.commit()
    finally:
        db.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Create tables and run the optional bootstrap seed on startup.

    The Phase 4 scheduler is intentionally *not* started here: when
    ``settings.SCHEDULER_ENABLED`` is on, the out-of-process arq worker
    (``app.worker``) owns the ``check_schedules`` cron. The API process only
    serves requests, so startup behavior is unchanged from Phase 0/1/2.
    """
    observability.configure_logging(json_logs=settings.JSON_LOGS)
    init_models()
    _bootstrap_seed()
    # Preflight: clearly report which REQUIRED scanner tools are present. Missing
    # required tools are logged loudly (never silent) but do NOT block startup;
    # optional tools stay optional. Status is queryable at GET /preflight.
    preflight.log_startup_report()
    # P1-H2: never silently ship a non-DEBUG deployment with rate limiting off —
    # that leaves the auth endpoints open to brute force. Warn loudly (do not
    # refuse boot, so an operator can still make a deliberate choice).
    if not settings.DEBUG and not settings.RATE_LIMIT_ENABLED:
        logging.getLogger("reconx.startup").warning(
            "SECURITY: rate limiting is DISABLED in a non-DEBUG environment; "
            "authentication endpoints are unprotected against brute force. "
            "Set RECONX_RATE_LIMIT_ENABLED=true."
        )
    yield


app = FastAPI(title="RECON-X", version="4.0.0", lifespan=lifespan)

# --------------------------------------------------------------------------- #
# Middleware stack (Phase 5).
#
# Starlette runs middlewares in the *reverse* of their add order: the LAST one
# added is the OUTERMOST (runs first on the request, last on the response). CORS
# is therefore added LAST so it stays outermost — it handles preflight OPTIONS
# and its Access-Control-* headers are applied to every response (including a
# 429 from the rate limiter). The Phase 5 middlewares are added first so they sit
# *inside* CORS: SecurityHeadersMiddleware only ever uses setdefault(), so it can
# never clobber CORS headers. All three are cheap no-ops when their flag is off
# (rate-limit defaults off; headers/metrics default on but harmless).
# --------------------------------------------------------------------------- #
app.add_middleware(RateLimitMiddleware)
app.add_middleware(RequestContextMiddleware)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    # Trust localhost (any port) ONLY in local dev — a production build must not
    # reflect credentialed CORS for localhost origins (that lets other local apps
    # on a victim's machine call the API with the user's session). In prod, only
    # the explicit ALLOWED_ORIGINS list is honored.
    allow_origin_regex=(
        r"https?://(localhost|127\.0\.0\.1)(:\d+)?" if settings.DEBUG else None
    ),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Every feature router (auth, orgs, workspaces, assets, scans, intel, billing,
# ws) is mounted here; ROUTERS already includes the Phase 3 billing router and
# the Phase 4 intelligence router.
for _router in ROUTERS:
    app.include_router(_router)


@app.get("/")
def home():
    """Service banner (unauthenticated)."""
    return {"name": "RECON-X", "status": "online", "version": app.version}


@app.get("/health")
def health():
    """Liveness probe (unauthenticated)."""
    return {"status": "ok"}


@app.get("/ready")
def ready():
    """Readiness probe: verifies database connectivity (unauthenticated)."""
    db = SessionLocal()
    try:
        db.execute(text("SELECT 1"))
    except Exception:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE, "database unavailable"
        )
    finally:
        db.close()
    return {"status": "ready"}


@app.get("/preflight")
def preflight_status():
    """Report scanner-tool availability (unauthenticated, read-only).

    Clearly surfaces which REQUIRED scanner binaries are present vs missing and
    which OPTIONAL ones are installed, so operators can confirm a deployment has
    the tools the auto-pentest pipeline needs. ``ok`` is True iff every required
    tool is on PATH. Always 200 (a health/inventory view, never a hard failure).
    """
    return preflight.check_tools()


@app.get("/metrics")
def metrics():
    """Prometheus metrics exposition (unauthenticated, gated by METRICS_ENABLED).

    Returns the Prometheus text format when ``prometheus_client`` is installed;
    otherwise a small plain-text stub (never a 500). 404 when metrics are off.
    """
    if not settings.METRICS_ENABLED:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "metrics are disabled")
    body, content_type = observability.render_metrics()
    return Response(content=body, media_type=content_type)

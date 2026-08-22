"""Public OAST collaborator callback — records out-of-band interactions.

UNAUTHENTICATED by design: the TARGET server (or its network) reaches this route,
never the operator, so it cannot require a login. It records a minimal interaction
for a KNOWN probe token and reflects NOTHING. Unknown / malformed / expired tokens
get the SAME empty 200, so the endpoint never reveals which tokens are live. Reads
of interactions happen only inside the owning scan (tenant-isolated) — there is no
authenticated read endpoint here to widen the surface.
"""
from fastapi import APIRouter, Request, Response

from .. import oast, ratelimit
from ..config import settings
from ..database import SessionLocal

router = APIRouter()

_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]


@router.api_route("/oast/{token}", methods=_METHODS, include_in_schema=False)
async def oast_callback(token: str, request: Request) -> Response:
    """Record an out-of-band callback hit; always return an empty 200."""
    ip = request.client.host if request.client else ""
    # Rate-limit by client IP so the public endpoint can't be used to hammer the
    # DB; a throttled call still returns the same empty 200 (reveals nothing).
    if settings.RATE_LIMIT_ENABLED:
        ip = ratelimit.resolve_client_ip(
            request.client.host if request.client else None,
            request.headers.get("x-forwarded-for"),
            settings.rate_limit_trusted_proxies,
        )
        if not ratelimit.limiter().check(ratelimit.GENERAL, ip)[0].allowed:
            return Response(status_code=200)
    if oast.is_valid_token(token):
        db = SessionLocal()
        try:
            oast.record_interaction(
                db, token, source_ip=ip or "",
                method=request.method, path=request.url.path,
            )
            db.commit()
        except Exception:       # noqa: BLE001 — never surface anything to the caller
            db.rollback()
        finally:
            db.close()
    return Response(status_code=200)

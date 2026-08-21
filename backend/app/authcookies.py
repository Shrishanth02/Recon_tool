"""httpOnly refresh-token cookie transport (STEP 4 — operational hardening).

The refresh token moves out of JS-readable ``localStorage`` into an httpOnly
cookie, so an XSS on the SPA origin can no longer exfiltrate the long-lived
(14-day) refresh credential. Access tokens stay Bearer/``localStorage`` — the
cookie carries ONLY the refresh token, scoped to the refresh endpoint's path, and
is CSRF-guarded by ``SameSite=Strict`` plus an Origin-allowlist check on the one
route that trusts it.

Design notes:
* ``httponly`` — page scripts cannot read it (defeats XSS token theft).
* ``secure`` outside DEBUG — never sent over plain http in production; relaxed
  under DEBUG so local http dev (and the http test client) works.
* ``samesite='strict'`` — the cookie never rides a cross-site request, which is
  the primary CSRF defense for the cookie-authenticated ``/auth/refresh``.
* ``path='/auth'`` — the browser only attaches it to the ``/auth/*`` routes
  (``/auth/refresh`` consumes it, ``/auth/logout`` revokes + clears it); it is
  never sent with ordinary API traffic. Only ``/auth/refresh`` *trusts* it, behind
  the SameSite + Origin CSRF guard.
"""

from __future__ import annotations

from fastapi import HTTPException, Request, Response, status

from .config import settings

#: httpOnly cookie carrying the refresh token to the auth routes.
REFRESH_COOKIE = "reconx_refresh"
#: The refresh cookie (and every place it is set/cleared) lives under this path,
#: so /auth/refresh (consume) and /auth/logout (revoke+clear) both receive it.
REFRESH_COOKIE_PATH = "/auth"


def set_refresh_cookie(response: Response, token: str) -> None:
    """Set the httpOnly refresh cookie on ``response``."""
    response.set_cookie(
        REFRESH_COOKIE,
        token,
        max_age=int(settings.REFRESH_TTL_DAYS) * 86400,
        httponly=True,
        secure=not settings.DEBUG,
        samesite="strict",
        path=REFRESH_COOKIE_PATH,
    )


def clear_refresh_cookie(response: Response) -> None:
    """Delete the refresh cookie (sign-out / reuse-detected revocation)."""
    response.delete_cookie(REFRESH_COOKIE, path=REFRESH_COOKIE_PATH)


def read_refresh_cookie(request: Request) -> str | None:
    """Return the refresh token from the cookie, or None."""
    return request.cookies.get(REFRESH_COOKIE)


def enforce_refresh_origin(request: Request) -> None:
    """CSRF guard for the cookie-authenticated refresh.

    ``SameSite=Strict`` already prevents the cookie from riding a cross-site
    request; this is defense-in-depth against a browser that ignores SameSite, and
    it rejects a caller whose ``Origin`` is not an allowed app origin. Lenient in
    DEBUG (any localhost dev port), where CORS already gates and the Secure flag is
    relaxed. A request with no ``Origin`` header (e.g. a same-origin call that
    omits it, or a non-browser client) is allowed — SameSite carries the guard.
    """
    if settings.DEBUG:
        return
    origin = request.headers.get("origin")
    if origin and origin not in settings.ALLOWED_ORIGINS:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, "cross-origin refresh blocked"
        )

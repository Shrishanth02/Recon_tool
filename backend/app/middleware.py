"""Starlette middlewares for the Phase 5 enterprise core.

Three additive, individually flag-gated middlewares. None of them add a new hard
dependency, and each is a cheap no-op when its governing setting is off:

* :class:`SecurityHeadersMiddleware` — hardening response headers (default on,
  harmless). Never overwrites CORS headers set by the CORS middleware.
* :class:`RequestContextMiddleware` — assigns/propagates an ``X-Request-ID``,
  times the request, feeds :func:`app.observability.record_request`, and emits a
  structured access log line when ``settings.JSON_LOGS`` is enabled.
* :class:`RateLimitMiddleware` — in-memory per-client token bucket (default
  off); returns ``429`` with a ``Retry-After`` header when the budget is
  exhausted. ``/health``, ``/ready`` and ``/metrics`` are always exempt.

Wiring these into the app is the ``main.py`` owner's job; this module only
defines them so it stays free of app-construction side effects.
"""

from __future__ import annotations

import time

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from . import observability
from .config import settings
from . import ratelimit

__all__ = [
    "SecurityHeadersMiddleware",
    "RequestContextMiddleware",
    "RateLimitMiddleware",
]

# Paths that infrastructure probes hit; never rate-limited.
_RATE_LIMIT_EXEMPT: frozenset[str] = frozenset(
    {"/health", "/ready", "/metrics", "/preflight"}
)

_REQUEST_ID_HEADER = "X-Request-ID"

# A conservative, self-only policy. The API serves JSON, not HTML, so a strict
# default-src is safe and cannot break the SPA (which is served separately). The
# extra directives lock down framing (belt-and-braces with X-Frame-Options),
# plugins, `<base>` hijacking, and cross-origin form posts — none of which a JSON
# API ever needs.
_CSP = (
    "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; "
    "object-src 'none'; form-action 'none'"
)


def _route_label(request: Request) -> str:
    """Return a low-cardinality path label for metrics.

    Prefers the matched route's template (e.g. ``/orgs/{org_id}``) so per-id
    URLs collapse to a single series; falls back to the raw path when no route
    matched (404s, etc.).
    """
    route = request.scope.get("route")
    path_format = getattr(route, "path_format", None) or getattr(
        route, "path", None
    )
    if path_format:
        return str(path_format)
    # No route matched (404s, probes). Bucket to a constant instead of the raw
    # path: the raw path is attacker-controlled, so emitting it would both leak it
    # into /metrics and let a caller explode the label cardinality.
    return "unmatched"


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Attach hardening headers to every response when enabled.

    Adds ``X-Content-Type-Options``, ``X-Frame-Options``, ``Referrer-Policy`` and
    a conservative ``Content-Security-Policy`` unconditionally, plus HSTS on
    HTTPS requests. Existing headers (notably the CORS ``Access-Control-*`` set)
    are never overwritten — each header is only added when absent.
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        if not settings.SECURITY_HEADERS:
            return response

        def _setdefault(name: str, value: str) -> None:
            if name not in response.headers:
                response.headers[name] = value

        _setdefault("X-Content-Type-Options", "nosniff")
        _setdefault("X-Frame-Options", "DENY")
        _setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        _setdefault("Content-Security-Policy", _CSP)
        # HSTS only makes sense (and is only honored) over TLS. Behind a
        # TLS-terminating proxy the ASGI scheme is plain http, so also honor a
        # forwarded-proto of https. (Emitting HSTS on a genuine http response is
        # harmless — browsers ignore the header unless it arrives over https.)
        forwarded_proto = (
            request.headers.get("x-forwarded-proto", "").split(",")[0].strip().lower()
        )
        if request.url.scheme == "https" or forwarded_proto == "https":
            _setdefault(
                "Strict-Transport-Security",
                "max-age=31536000; includeSubDomains",
            )
        return response


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Correlation id, timing, metrics, and optional structured access logging.

    The incoming ``X-Request-ID`` is honored if present (so a trace id survives
    across services) and otherwise generated. It is echoed back on the response.
    Every request is timed and reported to the metrics layer; when
    ``settings.JSON_LOGS`` is on a structured access line is emitted.
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        rid = request.headers.get(_REQUEST_ID_HEADER) or observability.request_id()
        request.state.request_id = rid

        start = time.perf_counter()
        status_code = 500
        try:
            response = await call_next(request)
            status_code = response.status_code
            return response
        finally:
            duration = time.perf_counter() - start
            path_label = _route_label(request)
            method = request.method
            # Metrics are default-on but self-guard on prometheus availability.
            observability.record_request(
                method=method,
                path=path_label,
                status=status_code,
                duration_seconds=duration,
            )
            # Ensure the response carries the correlation id (best effort — the
            # response object is out of scope in the exception path).
            try:
                response.headers[_REQUEST_ID_HEADER] = rid  # noqa: F821
            except Exception:
                pass
            if settings.JSON_LOGS:
                observability.access_logger().info(
                    "request",
                    extra={
                        "fields": {
                            "request_id": rid,
                            "method": method,
                            "path": path_label,
                            "raw_path": request.url.path,
                            "status": status_code,
                            "duration_ms": round(duration * 1000, 2),
                            "client": request.client.host
                            if request.client
                            else None,
                        }
                    },
                )


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Distributed (Redis-backed) per-category rate limiting.

    A no-op unless ``settings.RATE_LIMIT_ENABLED``. Each request is classified
    into an ``auth`` / ``scan`` / ``general`` bucket (see
    :func:`app.ratelimit.classify_path`) and limited per CLIENT IP so N backend
    processes sharing Redis enforce one shared budget. The client IP is resolved
    proxy-aware (``X-Forwarded-For`` is trusted only from a configured trusted
    proxy). If Redis is down, ``general`` fails open while ``auth``/``scan`` fall
    back to a per-process limiter — a Redis outage never becomes an app outage,
    and auth is never left unlimited. Exempt paths (health probes) bypass it.

    The bucket is keyed by IP (not account) on purpose: it avoids letting an
    attacker lock out a victim's account and avoids a user-enumeration side
    channel — the 429 is identical whether or not the account exists.
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        if not settings.RATE_LIMIT_ENABLED:
            return await call_next(request)
        path = request.url.path
        if path in _RATE_LIMIT_EXEMPT:
            return await call_next(request)

        category = ratelimit.classify_path(path)
        ip = ratelimit.resolve_client_ip(
            request.client.host if request.client else None,
            request.headers.get("x-forwarded-for"),
            settings.rate_limit_trusted_proxies,
        )
        decision, _mode = ratelimit.limiter().check(category, ip)
        if not decision.allowed:
            retry_after = max(1, int(decision.retry_after + 0.999))
            return JSONResponse(
                {"detail": "Rate limit exceeded"},
                status_code=429,
                headers={
                    "Retry-After": str(retry_after),
                    "X-RateLimit-Limit": str(decision.limit),
                    "X-RateLimit-Remaining": str(decision.remaining),
                },
            )

        response = await call_next(request)
        response.headers.setdefault("X-RateLimit-Limit", str(decision.limit))
        response.headers.setdefault("X-RateLimit-Remaining", str(decision.remaining))
        return response

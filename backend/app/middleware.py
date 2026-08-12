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
from .ratelimit import TokenBucketRateLimiter

__all__ = [
    "SecurityHeadersMiddleware",
    "RequestContextMiddleware",
    "RateLimitMiddleware",
]

# Paths that infrastructure probes hit; never rate-limited.
_RATE_LIMIT_EXEMPT: frozenset[str] = frozenset({"/health", "/ready", "/metrics"})

_REQUEST_ID_HEADER = "X-Request-ID"

# A conservative, self-only policy. The API serves JSON, not HTML, so a strict
# default-src is safe and cannot break the SPA (which is served separately).
_CSP = "default-src 'self'"


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
    return request.url.path


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
        # HSTS only makes sense (and is only honored) over TLS.
        if request.url.scheme == "https":
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
    """In-memory per-client token-bucket rate limiting (opt-in).

    A no-op unless ``settings.RATE_LIMIT_ENABLED`` is set. The client key is the
    authenticated principal when a bearer/API-key credential is present (so a
    single tenant behind a shared NAT is not throttled as one), otherwise the
    peer IP. Exempt paths bypass the limiter entirely.

    The underlying :class:`~app.ratelimit.TokenBucketRateLimiter` is created
    lazily and rebuilt if ``RATE_LIMIT_PER_MINUTE`` changes at runtime.
    """

    def __init__(self, app) -> None:
        super().__init__(app)
        self._limiter: TokenBucketRateLimiter | None = None
        self._configured_rate: int | None = None

    def _get_limiter(self) -> TokenBucketRateLimiter:
        rate = int(settings.RATE_LIMIT_PER_MINUTE)
        if self._limiter is None or self._configured_rate != rate:
            self._limiter = TokenBucketRateLimiter(rate_per_minute=rate)
            self._configured_rate = rate
        return self._limiter

    @staticmethod
    def _client_key(request: Request) -> str:
        # Prefer a stable per-credential key so shared egress IPs aren't lumped
        # together. We only read the raw header value (no DB lookup) to keep the
        # hot path cheap; it is a bucketing key, not an authorization decision.
        api_key = request.headers.get("x-api-key")
        if api_key:
            return f"key:{api_key[:24]}"
        auth = request.headers.get("authorization")
        if auth and auth.lower().startswith("bearer "):
            return f"tok:{auth[7:].strip()[:32]}"
        client = request.client
        return f"ip:{client.host if client else 'unknown'}"

    async def dispatch(self, request: Request, call_next) -> Response:
        if not settings.RATE_LIMIT_ENABLED:
            return await call_next(request)
        if request.url.path in _RATE_LIMIT_EXEMPT:
            return await call_next(request)

        decision = self._get_limiter().check(self._client_key(request))
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
        response.headers.setdefault(
            "X-RateLimit-Remaining", str(decision.remaining)
        )
        return response

"""A pure, thread-safe, in-memory token-bucket rate limiter (stdlib only).

Used by :class:`app.middleware.RateLimitMiddleware`. Each client (keyed by IP or
authenticated principal) gets an independent bucket that refills continuously at
``rate_per_minute / 60`` tokens per second up to a burst capacity. A request
consumes one token; when the bucket is empty the request is denied and the
caller is told how many seconds to wait via ``retry_after``.

The limiter holds no framework or network dependencies, so it is trivially unit
testable and safe to import anywhere.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass

__all__ = ["TokenBucketRateLimiter", "RateLimitDecision"]


@dataclass(frozen=True)
class RateLimitDecision:
    """The outcome of a single :meth:`TokenBucketRateLimiter.check`.

    ``allowed`` is whether the request may proceed. ``remaining`` is the whole
    number of tokens left in the bucket after this call. ``retry_after`` is the
    number of seconds until at least one token is available (``0.0`` when the
    request was allowed). ``limit`` echoes the configured per-minute rate.
    """

    allowed: bool
    remaining: int
    retry_after: float
    limit: int


class TokenBucketRateLimiter:
    """A continuous-refill token bucket keyed by an arbitrary client id.

    Parameters
    ----------
    rate_per_minute:
        Sustained request budget per client per minute (also the bucket's burst
        capacity). Values ``<= 0`` are coerced to ``1`` so the limiter never
        divides by zero or blocks every request outright.
    capacity:
        Optional burst capacity override. Defaults to ``rate_per_minute``.

    The implementation is thread-safe (a single lock guards the bucket table)
    and monotonic-clock based, so it is immune to wall-clock adjustments.
    """

    def __init__(self, rate_per_minute: int, capacity: int | None = None) -> None:
        self.rate_per_minute = max(1, int(rate_per_minute))
        self.capacity = float(
            max(1, int(capacity)) if capacity is not None else self.rate_per_minute
        )
        # tokens refilled per second.
        self._refill_per_sec = self.rate_per_minute / 60.0
        # client_key -> (tokens, last_refill_monotonic)
        self._buckets: dict[str, tuple[float, float]] = {}
        self._lock = threading.Lock()

    def _now(self) -> float:
        return time.monotonic()

    def check(self, key: str, cost: float = 1.0) -> RateLimitDecision:
        """Attempt to consume ``cost`` tokens for ``key``.

        Returns a :class:`RateLimitDecision`. This both reads and mutates the
        bucket state atomically under the lock.
        """
        cost = max(0.0, float(cost))
        now = self._now()
        with self._lock:
            tokens, last = self._buckets.get(key, (self.capacity, now))
            # Continuous refill since we last saw this client.
            elapsed = max(0.0, now - last)
            tokens = min(self.capacity, tokens + elapsed * self._refill_per_sec)

            if tokens >= cost:
                tokens -= cost
                self._buckets[key] = (tokens, now)
                return RateLimitDecision(
                    allowed=True,
                    remaining=int(tokens),
                    retry_after=0.0,
                    limit=self.rate_per_minute,
                )

            # Not enough tokens: compute the wait for the shortfall.
            deficit = cost - tokens
            retry_after = (
                deficit / self._refill_per_sec if self._refill_per_sec > 0 else 60.0
            )
            self._buckets[key] = (tokens, now)
            return RateLimitDecision(
                allowed=False,
                remaining=int(tokens),
                retry_after=retry_after,
                limit=self.rate_per_minute,
            )

    def reset(self, key: str | None = None) -> None:
        """Forget one client's bucket, or all buckets when ``key`` is ``None``."""
        with self._lock:
            if key is None:
                self._buckets.clear()
            else:
                self._buckets.pop(key, None)


# =========================================================================== #
# P1-H2: distributed (Redis-backed) rate limiting with a safe local fallback.
# =========================================================================== #
import ipaddress  # noqa: E402

# Rate-limit categories. Each gets its own limit/window and Redis key namespace.
AUTH = "auth"
SCAN = "scan"
GENERAL = "general"

#: How long to stop hitting Redis after it fails, so an outage never adds
#: connect latency to every request (we use the local fallback meanwhile).
_REDIS_COOLDOWN_SECONDS = 15.0

class RedisUnavailable(Exception):
    """Raised by :class:`RedisRateLimiter` when Redis cannot be reached/used, so
    the caller can apply its per-category fail policy (never leaked to clients)."""


class RedisRateLimiter:
    """Distributed fixed-window limiter backed by a single Redis instance.

    Each ``check`` is one atomic ``MULTI/EXEC`` round-trip that (a) creates the
    window key with its expiry ONLY if absent (``SET key 0 NX PX``), (b)
    increments it, and (c) reads the remaining TTL. Because the expiry is set
    atomically at creation and never reset, the classic INCR-then-EXPIRE race
    cannot leave a key without a TTL, and N processes sharing the same Redis
    observe the SAME counter for a given key.
    """

    def __init__(self, client) -> None:
        self._client = client

    def check(self, key: str, limit: int, window_seconds: float) -> RateLimitDecision:
        window_ms = max(1, int(window_seconds * 1000))
        try:
            pipe = self._client.pipeline(transaction=True)
            pipe.set(key, 0, nx=True, px=window_ms)  # start the window atomically
            pipe.incr(key)                            # count this request
            pipe.pttl(key)                            # ms until the window resets
            results = pipe.execute()
            count = int(results[1])
            pttl = int(results[2])
        except Exception as exc:  # noqa: BLE001 - any redis error -> apply fail policy
            raise RedisUnavailable(str(exc)) from exc
        allowed = count <= limit
        remaining = max(0, limit - count)
        retry_after = 0.0
        if not allowed:
            retry_after = (pttl / 1000.0) if pttl and pttl > 0 else float(window_seconds)
        return RateLimitDecision(
            allowed=allowed, remaining=remaining, retry_after=retry_after, limit=limit
        )


# --- Client-IP resolution (proxy-aware, spoof-safe by default) -------------- #
def parse_trusted_proxies(spec: str) -> list:
    """Parse a comma/space separated CIDR list into ip_network objects.

    Invalid entries are skipped. An empty result means 'trust no proxy headers'.
    """
    nets = []
    for part in (spec or "").replace(",", " ").split():
        try:
            nets.append(ipaddress.ip_network(part, strict=False))
        except ValueError:
            continue
    return nets


def _ip_in(ip_str: str, networks: list) -> bool:
    try:
        ip = ipaddress.ip_address((ip_str or "").strip())
    except ValueError:
        return False
    return any(ip in net for net in networks)


def resolve_client_ip(peer_host, forwarded_for, trusted_proxies: list) -> str:
    """Return the client IP used for rate-limit bucketing.

    ``X-Forwarded-For`` is trusted ONLY when the direct connection peer is itself
    a configured trusted proxy; otherwise the header is ignored and the direct
    peer address is used. This prevents an attacker from bypassing limits by
    sending a forged header. With no trusted proxies configured (the default),
    the direct peer is always used.
    """
    peer = (peer_host or "unknown").strip() or "unknown"
    if not trusted_proxies or not _ip_in(peer, trusted_proxies):
        return peer
    # The peer is a trusted proxy: the real client is the right-most XFF entry
    # that is not itself one of our trusted proxies.
    for hop in reversed([p.strip() for p in (forwarded_for or "").split(",") if p.strip()]):
        if not _ip_in(hop, trusted_proxies):
            return hop
    return peer


_AUTH_EXACT = frozenset({"/auth/login", "/auth/register", "/auth/refresh"})
_AUTH_PREFIXES = ("/auth/mfa", "/auth/sso")


def classify_path(path: str) -> str:
    """Map a request path to a rate-limit category (auth | scan | general)."""
    if path in _AUTH_EXACT or any(path.startswith(p) for p in _AUTH_PREFIXES):
        return AUTH
    if path == "/scan" or path.startswith("/scan/"):
        return SCAN
    return GENERAL


class DistributedRateLimiter:
    """Category-aware limiter: Redis-backed (shared across processes) with a safe
    per-process fallback.

    Fail policy when Redis is unavailable:
      * ``general`` -> FAIL-OPEN (a Redis outage must not take down the API), and
      * ``auth`` / ``scan`` -> a per-process in-memory token bucket (degraded but
        still protective) — never silently unlimited.
    """

    def __init__(self, *, redis_limiter: "RedisRateLimiter | None" = None,
                 redis_factory=None) -> None:
        self._explicit = redis_limiter          # injected (tests); never rebuilt
        self._factory = redis_factory           # optional client factory (tests)
        self._redis = redis_limiter
        self._cooldown_until = 0.0
        self._fallbacks: dict[str, TokenBucketRateLimiter] = {}
        self._lock = threading.Lock()

    def _limits(self, category: str) -> tuple[int, int]:
        from .config import settings
        window = max(1, int(settings.RATE_LIMIT_WINDOW_SECONDS))
        if category == AUTH:
            return max(1, int(settings.RATE_LIMIT_AUTH_PER_MINUTE)), window
        if category == SCAN:
            return max(1, int(settings.RATE_LIMIT_SCAN_PER_MINUTE)), window
        return max(1, int(settings.RATE_LIMIT_PER_MINUTE)), window

    def _build_redis(self) -> "RedisRateLimiter | None":
        if self._explicit is not None:
            return self._explicit
        try:
            if self._factory is not None:
                client = self._factory()
            else:
                import redis  # lazy: keep import-safe without redis installed
                from .config import settings
                client = redis.Redis.from_url(
                    settings.REDIS_URL,
                    socket_connect_timeout=0.25,
                    socket_timeout=0.25,
                )
            return RedisRateLimiter(client)
        except Exception:  # noqa: BLE001 - redis absent/misconfigured -> fallback
            return None

    def _redis_limiter(self) -> "RedisRateLimiter | None":
        if self._redis is not None:
            return self._redis
        if time.monotonic() < self._cooldown_until:
            return None
        self._redis = self._build_redis()
        if self._redis is None:
            self._cooldown_until = time.monotonic() + _REDIS_COOLDOWN_SECONDS
        return self._redis

    def _fallback(self, category: str, limit: int) -> TokenBucketRateLimiter:
        with self._lock:
            fb = self._fallbacks.get(category)
            if fb is None or fb.rate_per_minute != limit:
                fb = TokenBucketRateLimiter(rate_per_minute=limit)
                self._fallbacks[category] = fb
            return fb

    def check(self, category: str, ip: str) -> tuple[RateLimitDecision, str]:
        """Return ``(decision, mode)`` where mode is ``redis`` | ``fallback`` |
        ``open`` for observability (never surfaced to the client)."""
        limit, window = self._limits(category)
        rl = self._redis_limiter()
        if rl is not None:
            try:
                return rl.check(f"rl:{category}:{ip}", limit, window), "redis"
            except RedisUnavailable:
                self._redis = None
                self._cooldown_until = time.monotonic() + _REDIS_COOLDOWN_SECONDS
        if category == GENERAL:
            return (
                RateLimitDecision(allowed=True, remaining=limit, retry_after=0.0, limit=limit),
                "open",
            )
        return self._fallback(category, limit).check(f"{category}:{ip}"), "fallback"

    def reset(self) -> None:
        """Test helper: forget cooldown + fallback state (Redis state is external)."""
        self._redis = self._explicit
        self._cooldown_until = 0.0
        for fb in self._fallbacks.values():
            fb.reset()


_HUB: "DistributedRateLimiter | None" = None


def limiter() -> DistributedRateLimiter:
    """Return the process-wide rate limiter (built lazily from settings)."""
    global _HUB
    if _HUB is None:
        _HUB = DistributedRateLimiter()
    return _HUB


def set_limiter(hub: "DistributedRateLimiter | None") -> None:
    """Test hook: install (or clear, with ``None``) the process-wide limiter."""
    global _HUB
    _HUB = hub

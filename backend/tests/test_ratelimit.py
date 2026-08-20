"""P1-H2 regression tests — distributed, Redis-backed rate limiting.

Redis is simulated with fakeredis (a pure-Python in-process Redis) so no Docker
or real Redis server is required. Crucially, two limiter instances sharing one
``FakeServer`` model two application PROCESSES sharing one Redis — used to prove
the limit is enforced on shared state.
"""

import time

import fakeredis
import pytest

from app import ratelimit
from app.config import settings
from app.ratelimit import (
    AUTH,
    GENERAL,
    SCAN,
    DistributedRateLimiter,
    RedisRateLimiter,
    RedisUnavailable,
    TokenBucketRateLimiter,
    classify_path,
    parse_trusted_proxies,
    resolve_client_ip,
)


def _client():
    return fakeredis.FakeStrictRedis()


# --------------------------------------------------------------------------- #
# In-memory TokenBucketRateLimiter (the per-process fallback) — preserved unit
# coverage from the original suite.
# --------------------------------------------------------------------------- #
def test_token_bucket_allows_burst_then_blocks():
    rl = TokenBucketRateLimiter(rate_per_minute=3)
    assert [rl.check("c").allowed for _ in range(3)] == [True, True, True]
    denied = rl.check("c")
    assert not denied.allowed and denied.retry_after > 0


def test_token_bucket_zero_rate_is_coerced_not_fatal():
    rl = TokenBucketRateLimiter(rate_per_minute=0)  # coerced to 1, never /0
    assert rl.check("c").allowed
    assert not rl.check("c").allowed


# --------------------------------------------------------------------------- #
# RedisRateLimiter — window counting
# --------------------------------------------------------------------------- #
def test_first_request_allowed():
    rl = RedisRateLimiter(_client())
    d = rl.check("k", 5, 60)
    assert d.allowed and d.remaining == 4 and d.limit == 5


def test_requests_within_limit_allowed_then_over_limit_rejected():
    rl = RedisRateLimiter(_client())
    outcomes = [rl.check("k", 3, 60).allowed for _ in range(5)]
    assert outcomes == [True, True, True, False, False]


def test_rejection_carries_retry_after():
    rl = RedisRateLimiter(_client())
    for _ in range(3):
        rl.check("k", 3, 60)
    d = rl.check("k", 3, 60)
    assert not d.allowed and d.retry_after > 0


def test_window_expiration_resets_the_count():
    rl = RedisRateLimiter(_client())
    for _ in range(2):
        rl.check("k", 2, 0.3)          # exhaust a 300ms window
    assert not rl.check("k", 2, 0.3).allowed
    time.sleep(0.45)                    # window elapses
    assert rl.check("k", 2, 0.3).allowed


def test_distinct_keys_are_independent():
    rl = RedisRateLimiter(_client())
    for _ in range(3):
        rl.check("a", 3, 60)
    assert not rl.check("a", 3, 60).allowed
    assert rl.check("b", 3, 60).allowed   # different client unaffected


# --------------------------------------------------------------------------- #
# THE distributed proof — two processes, one Redis, shared budget
# --------------------------------------------------------------------------- #
def test_two_processes_share_one_rate_limit_via_redis():
    server = fakeredis.FakeServer()
    proc_a = DistributedRateLimiter(
        redis_limiter=RedisRateLimiter(fakeredis.FakeStrictRedis(server=server)))
    proc_b = DistributedRateLimiter(
        redis_limiter=RedisRateLimiter(fakeredis.FakeStrictRedis(server=server)))

    allowed = 0
    modes = set()
    for i in range(14):
        hub = proc_a if i % 2 == 0 else proc_b   # alternate the two "processes"
        d, mode = hub.check(AUTH, "9.9.9.9")
        modes.add(mode)
        allowed += 1 if d.allowed else 0

    # settings default auth limit is 10 -> exactly 10 across BOTH processes.
    assert allowed == settings.RATE_LIMIT_AUTH_PER_MINUTE == 10
    assert modes == {"redis"}


# --------------------------------------------------------------------------- #
# Fail policy when Redis is unavailable
# --------------------------------------------------------------------------- #
class _DownRedis:
    def pipeline(self, *a, **k):
        raise ConnectionError("redis down")


def test_general_fails_open_when_redis_down():
    hub = DistributedRateLimiter(redis_limiter=RedisRateLimiter(_DownRedis()))
    for _ in range(500):
        d, mode = hub.check(GENERAL, "1.1.1.1")
        assert d.allowed and mode == "open"   # never turn an outage into a DoS


def test_auth_falls_back_to_local_limiter_when_redis_down(monkeypatch):
    monkeypatch.setattr(settings, "RATE_LIMIT_AUTH_PER_MINUTE", 5)
    hub = DistributedRateLimiter(redis_limiter=RedisRateLimiter(_DownRedis()))
    outcomes = [hub.check(AUTH, "1.1.1.1") for _ in range(8)]
    modes = {m for _d, m in outcomes}
    allowed = sum(1 for d, _m in outcomes if d.allowed)
    assert modes == {"fallback"}          # degraded, but NOT unlimited
    assert allowed == 5                    # still enforces the auth budget


def test_redis_timeout_is_treated_as_unavailable():
    class _Timeout:
        def pipeline(self, *a, **k):
            raise TimeoutError("socket timeout")
    rl = RedisRateLimiter(_Timeout())
    with pytest.raises(RedisUnavailable):
        rl.check("k", 5, 60)


def test_limits_come_from_configuration(monkeypatch):
    monkeypatch.setattr(settings, "RATE_LIMIT_AUTH_PER_MINUTE", 7)
    monkeypatch.setattr(settings, "RATE_LIMIT_SCAN_PER_MINUTE", 33)
    monkeypatch.setattr(settings, "RATE_LIMIT_PER_MINUTE", 111)
    monkeypatch.setattr(settings, "RATE_LIMIT_WINDOW_SECONDS", 30)
    hub = DistributedRateLimiter(redis_limiter=RedisRateLimiter(_client()))
    assert hub._limits(AUTH) == (7, 30)
    assert hub._limits(SCAN) == (33, 30)
    assert hub._limits(GENERAL) == (111, 30)


# --------------------------------------------------------------------------- #
# Client-IP resolution (trusted proxy, forged header)
# --------------------------------------------------------------------------- #
def test_no_trusted_proxy_uses_direct_peer():
    assert resolve_client_ip("203.0.113.5", "1.1.1.1", []) == "203.0.113.5"


def test_forged_xff_ignored_when_peer_not_trusted():
    nets = parse_trusted_proxies("10.0.0.0/8")
    # attacker connects directly and forges XFF -> header ignored, peer used.
    assert resolve_client_ip("203.0.113.5", "127.0.0.1, 8.8.8.8", nets) == "203.0.113.5"


def test_trusted_proxy_extracts_real_client_from_xff():
    nets = parse_trusted_proxies("10.0.0.0/8")
    assert resolve_client_ip("10.0.0.9", "203.0.113.7, 10.0.0.9", nets) == "203.0.113.7"


def test_parse_trusted_proxies_skips_junk():
    nets = parse_trusted_proxies("10.0.0.0/8, not-an-ip, 192.168.1.0/24")
    assert len(nets) == 2


# --------------------------------------------------------------------------- #
# Path classification
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("path,expected", [
    ("/auth/login", AUTH), ("/auth/register", AUTH), ("/auth/refresh", AUTH),
    ("/auth/mfa/verify", AUTH), ("/auth/sso/acme/callback", AUTH),
    ("/scan/nmap", SCAN), ("/scan", SCAN),
    ("/auth/me", GENERAL), ("/workspaces/1/findings", GENERAL), ("/", GENERAL),
])
def test_classify_path(path, expected):
    assert classify_path(path) == expected


# --------------------------------------------------------------------------- #
# Production default + config guard
# --------------------------------------------------------------------------- #
def test_rate_limiting_enabled_by_default_in_config():
    from app.config import Settings
    assert Settings.model_fields["RATE_LIMIT_ENABLED"].default is True


# --------------------------------------------------------------------------- #
# HTTP middleware integration (TestClient) — enable + inject a shared fakeredis
# --------------------------------------------------------------------------- #
@pytest.fixture()
def rate_limited(monkeypatch):
    server = fakeredis.FakeServer()
    hub = DistributedRateLimiter(
        redis_limiter=RedisRateLimiter(fakeredis.FakeStrictRedis(server=server)))
    ratelimit.set_limiter(hub)
    monkeypatch.setattr(settings, "RATE_LIMIT_ENABLED", True)
    yield
    ratelimit.set_limiter(None)


def test_auth_endpoint_is_rate_limited(client, rate_limited, monkeypatch):
    monkeypatch.setattr(settings, "RATE_LIMIT_AUTH_PER_MINUTE", 3)
    body = {"email": "x@example.com", "password": "wrong"}
    codes = [client.post("/auth/login", json=body).status_code for _ in range(4)]
    assert codes[-1] == 429
    assert sum(c == 429 for c in codes) == 1   # only the 4th (over the limit)


def test_rate_limit_response_is_generic_with_retry_after(client, rate_limited, monkeypatch):
    monkeypatch.setattr(settings, "RATE_LIMIT_AUTH_PER_MINUTE", 1)
    client.post("/auth/login", json={"email": "a@b.c", "password": "p"})
    r = client.post("/auth/login", json={"email": "a@b.c", "password": "p"})
    assert r.status_code == 429
    assert r.json() == {"detail": "Rate limit exceeded"}      # no redis internals
    assert int(r.headers["Retry-After"]) >= 1
    assert "redis" not in r.text.lower() and "traceback" not in r.text.lower()


def test_rate_limit_does_not_enumerate_accounts(client, rate_limited, monkeypatch):
    monkeypatch.setattr(settings, "RATE_LIMIT_AUTH_PER_MINUTE", 1)
    client.post("/auth/login", json={"email": "real@example.com", "password": "x"})
    # After the IP limit, an existing-account and a nonexistent-account login get
    # the IDENTICAL 429 (limited by IP, before the endpoint) — no side channel.
    r_real = client.post("/auth/login", json={"email": "real@example.com", "password": "x"})
    r_fake = client.post("/auth/login", json={"email": "nope@example.com", "password": "x"})
    assert r_real.status_code == r_fake.status_code == 429
    assert r_real.json() == r_fake.json()


def test_auth_and_general_buckets_are_separate(client, rate_limited, monkeypatch):
    monkeypatch.setattr(settings, "RATE_LIMIT_AUTH_PER_MINUTE", 2)
    monkeypatch.setattr(settings, "RATE_LIMIT_PER_MINUTE", 100)
    for _ in range(3):
        client.post("/auth/login", json={"email": "a@b.c", "password": "p"})   # exhaust auth
    assert client.post("/auth/login", json={"email": "a@b.c", "password": "p"}).status_code == 429
    # A general (unauthenticated) endpoint is a different bucket -> still fine.
    assert client.get("/").status_code == 200


def test_scan_bucket_applies_before_endpoint_auth(client, rate_limited, monkeypatch):
    monkeypatch.setattr(settings, "RATE_LIMIT_SCAN_PER_MINUTE", 2)
    # No credentials: the endpoint would 401/403, but the scan bucket fires first.
    codes = [client.get("/scan/nmap?target=example.com").status_code for _ in range(3)]
    assert codes[-1] == 429


def test_exempt_paths_are_never_limited(client, rate_limited, monkeypatch):
    monkeypatch.setattr(settings, "RATE_LIMIT_PER_MINUTE", 1)
    for _ in range(10):
        assert client.get("/health").status_code == 200   # exempt


def test_disabled_mode_is_a_noop(client, monkeypatch):
    monkeypatch.setattr(settings, "RATE_LIMIT_ENABLED", False)
    codes = [client.post("/auth/login", json={"email": "a@b.c", "password": "p"}).status_code
             for _ in range(20)]
    assert 429 not in codes

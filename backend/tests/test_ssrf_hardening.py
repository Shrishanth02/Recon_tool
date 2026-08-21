"""STEP 1 — SSRF/netguard hardening regression tests.

Covers the DNS-rebinding IP-pin (safe_http), the guarded redirect chain (the
mechanism httpx delegates to), the Playwright navigation guard, and netguard's
extended address coverage (CGNAT / Alibaba metadata / IPv4-mapped / NAT64).

None of these need a real network, external binary, or browser: the resolver is
stubbed, the requester is faked, and the Playwright route is exercised with a
mock route object. The security decision under test is always the real code.
"""

import inspect
import ipaddress
import socket
import threading

import pytest
import requests

from app import netguard
from app import safe_http as sh
from app.scanners import auth_crawl


# --------------------------------------------------------------------------- #
# 1. netguard address coverage (NG-04 / NG-05).
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("addr", [
    "169.254.169.254",            # AWS/GCP/Azure metadata
    "100.100.100.200",            # Alibaba metadata (inside CGNAT)
    "::ffff:169.254.169.254",     # IPv4-mapped metadata
    "::ffff:100.100.100.200",     # IPv4-mapped Alibaba metadata
    "64:ff9b::a9fe:a9fe",         # NAT64-embedded metadata
])
def test_metadata_blocked_regardless_of_flag(addr, monkeypatch):
    for flag in (True, False):
        monkeypatch.setattr(netguard.settings, "BLOCK_PRIVATE_TARGETS", flag)
        assert netguard._ip_is_dangerous(ipaddress.ip_address(addr)) is True, (addr, flag)


@pytest.mark.parametrize("addr", ["100.64.0.1", "100.127.255.254", "10.0.0.5", "::ffff:10.0.0.5"])
def test_cgnat_and_private_blocked_under_default_allowed_when_off(addr, monkeypatch):
    ip = ipaddress.ip_address(addr)
    monkeypatch.setattr(netguard.settings, "BLOCK_PRIVATE_TARGETS", True)
    assert netguard._ip_is_dangerous(ip) is True
    monkeypatch.setattr(netguard.settings, "BLOCK_PRIVATE_TARGETS", False)
    assert netguard._ip_is_dangerous(ip) is False  # operator opted into internal scanning


@pytest.mark.parametrize("addr", ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111", "93.184.216.34"])
def test_public_addresses_allowed(addr, monkeypatch):
    monkeypatch.setattr(netguard.settings, "BLOCK_PRIVATE_TARGETS", True)
    assert netguard._ip_is_dangerous(ipaddress.ip_address(addr)) is False


def test_resolve_and_validate_returns_vetted_ips_for_literal():
    ok, _reason, ips = netguard.resolve_and_validate("http://93.184.216.34/x")
    assert ok and ips == ["93.184.216.34"]
    ok, _reason, ips = netguard.resolve_and_validate("http://169.254.169.254/latest")
    assert not ok and ips == []


# --------------------------------------------------------------------------- #
# 2. DNS-rebinding IP-pin (NG-01) — the resolver shim + safe_request pinning.
# --------------------------------------------------------------------------- #
def test_pin_forces_vetted_ip_even_when_dns_rebinds(monkeypatch):
    # Simulate attacker DNS: the REAL resolver would answer a private IP.
    def rebinding_resolver(host, port, *a, **k):
        if host == "rebind.test":
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.5", port))]
        raise socket.gaierror("nope")
    monkeypatch.setattr(sh, "_orig_getaddrinfo", rebinding_resolver)

    # Unpinned: the shim delegates -> attacker's private IP.
    assert socket.getaddrinfo("rebind.test", 443)[0][4][0] == "10.0.0.5"
    # Pinned to a vetted public IP: re-resolution is forced to it (rebinding lost).
    with sh._pinned("rebind.test", ["93.184.216.34"]):
        got = [e[4][0] for e in socket.getaddrinfo("rebind.test", 443)]
    assert got == ["93.184.216.34"]


def test_pin_is_thread_local(monkeypatch):
    monkeypatch.setattr(sh, "_orig_getaddrinfo",
                        lambda *a, **k: (_ for _ in ()).throw(socket.gaierror("no")))
    out = {}

    def worker():
        try:
            socket.getaddrinfo("x.test", 443)
            out["v"] = "resolved"
        except socket.gaierror:
            out["v"] = "gaierror"
    with sh._pinned("x.test", ["8.8.8.8"]):
        t = threading.Thread(target=worker); t.start(); t.join()
    assert out["v"] == "gaierror"  # the main-thread pin did NOT leak to the worker


def test_safe_request_pins_connection_to_vetted_ip(monkeypatch):
    monkeypatch.setattr(netguard, "resolve_and_validate",
                        lambda t: (True, "ok", ["93.184.216.34"]))
    seen = {}

    def fake_request(method, url, allow_redirects=False, **kw):
        # WHILE the request is in flight, what does the host resolve to?
        seen["ips"] = [e[4][0] for e in socket.getaddrinfo("target.test", 443)]
        return _Resp(200, url=url)
    monkeypatch.setattr(requests, "request", fake_request)

    sh.safe_request("GET", "http://target.test/", allow_redirects=False)
    assert seen["ips"] == ["93.184.216.34"]  # Host header unchanged; connection pinned


def test_safe_request_blocks_target_that_resolves_private(monkeypatch):
    monkeypatch.setattr(netguard, "resolve_and_validate",
                        lambda t: (False, "target resolves to a blocked address (10.0.0.5)", []))
    called = {"n": 0}
    monkeypatch.setattr(requests, "request",
                        lambda *a, **k: called.__setitem__("n", called["n"] + 1))
    with pytest.raises(sh.BlockedDestination):
        sh.safe_request("GET", "http://evil.test/", allow_redirects=False)
    assert called["n"] == 0  # blocked destination is NEVER contacted


# --------------------------------------------------------------------------- #
# 3. Guarded redirect chain (the mechanism httpx delegates to) — every hop
#    is validated; a private/localhost/metadata hop is refused and never hit.
# --------------------------------------------------------------------------- #
class _Resp:
    def __init__(self, status, location=None, url="http://x/"):
        self.status_code = status
        self.headers = {"Location": location} if location else {}
        self.url = url


def _redirecting_requester(chain):
    """Return a fake requester that walks ``chain`` (list of (url_substr, next))."""
    hit = []

    def req(method, url, allow_redirects=False, **kw):
        hit.append(url)
        for frag, nxt in chain:
            if frag in url:
                return _Resp(302, location=nxt, url=url) if nxt else _Resp(200, url=url)
        return _Resp(200, url=url)
    return req, hit


@pytest.mark.parametrize("dest,should_block", [
    ("http://public2.test/ok", False),                     # public -> public
    ("http://127.0.0.1/", True),                           # public -> localhost
    ("http://10.0.0.9/", True),                            # public -> RFC1918
    ("http://169.254.169.254/latest/meta-data/", True),    # public -> metadata
    ("http://100.100.100.200/", True),                     # public -> Alibaba metadata
])
def test_guarded_redirect_hop(monkeypatch, dest, should_block):
    def rv(t):
        host = netguard._bare_host(t)
        try:
            if netguard._ip_is_dangerous(ipaddress.ip_address(host)):
                return False, f"blocked ({host})", []
        except ValueError:
            pass
        return True, "ok", ["93.184.216.34"]
    monkeypatch.setattr(netguard, "resolve_and_validate", rv)
    req, hit = _redirecting_requester([("public1.test", dest), (dest, None)])
    monkeypatch.setattr(requests, "request", req)

    if should_block:
        with pytest.raises(sh.BlockedDestination):
            sh.safe_request("GET", "http://public1.test/", allow_redirects=True)
        # the unsafe hop was NEVER contacted
        assert not any(netguard._bare_host(dest) in u for u in hit)
    else:
        resp = sh.safe_request("GET", "http://public1.test/", allow_redirects=True)
        assert resp.status_code == 200


def test_guarded_redirect_multi_hop_blocks_final_metadata(monkeypatch):
    def rv(t):
        host = netguard._bare_host(t)
        try:
            if netguard._ip_is_dangerous(ipaddress.ip_address(host)):
                return False, "blocked", []
        except ValueError:
            pass
        return True, "ok", ["93.184.216.34"]
    monkeypatch.setattr(netguard, "resolve_and_validate", rv)
    req, hit = _redirecting_requester([
        ("hop0.test", "http://hop1.test/"),
        ("hop1.test", "http://169.254.169.254/"),
    ])
    monkeypatch.setattr(requests, "request", req)
    with pytest.raises(sh.BlockedDestination):
        sh.safe_request("GET", "http://hop0.test/", allow_redirects=True)
    assert not any("169.254" in u for u in hit)


# --------------------------------------------------------------------------- #
# 4. httpx_probe no longer auto-follows redirects in the Go binary.
# --------------------------------------------------------------------------- #
def test_httpx_probe_does_not_pass_follow_redirects():
    from app.scanners import httpx_probe
    src = inspect.getsource(httpx_probe)
    assert "-follow-redirects" not in src, "httpx must not auto-follow redirects"
    assert "safe_http" in src, "httpx must follow redirects via the guarded path"


# --------------------------------------------------------------------------- #
# 5. Playwright navigation guard — same-site works; unsafe destinations abort.
# --------------------------------------------------------------------------- #
class _MockRoute:
    def __init__(self, url):
        self.request = type("R", (), {"url": url})()
        self.action = None

    def abort(self):
        self.action = "abort"

    def continue_(self):
        self.action = "continue"


def _host_based_rv(target):
    """Deterministic resolve_and_validate stub: literal IPs use the real danger
    policy; test hostnames resolve to a fixed public IP (no real DNS needed)."""
    host = netguard._bare_host(target)
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return True, "ok", ["93.184.216.34"]
    if netguard._ip_is_dangerous(ip):
        return False, f"blocked ({host})", []
    return True, "ok", [str(ip)]


@pytest.mark.parametrize("url,expect", [
    ("https://app.example.com/dashboard", "continue"),   # same-site public nav
    ("https://cdn.other.com/lib.js", "continue"),        # cross-origin PUBLIC subresource
    ("http://127.0.0.1/", "abort"),                      # localhost
    ("http://10.1.2.3/", "abort"),                       # RFC1918
    ("http://169.254.169.254/latest/meta-data/", "abort"),  # metadata
    ("http://100.100.100.200/", "abort"),                # Alibaba metadata
    ("about:blank", "continue"),                         # no network egress
])
def test_playwright_route_guard(url, expect, monkeypatch):
    monkeypatch.setattr(netguard.settings, "BLOCK_PRIVATE_TARGETS", True)
    monkeypatch.setattr(netguard, "resolve_and_validate", _host_based_rv)
    r = _MockRoute(url)
    blocked = []
    auth_crawl._guard_route(r, blocked)
    assert r.action == expect, (url, r.action)
    assert (len(blocked) == 1) == (expect == "abort")


def test_playwright_secret_from_blocked_dest_never_loaded(monkeypatch):
    # A redirect to the metadata endpoint is ABORTED, so Chromium never loads the
    # IAM-cred body -> _collect_secrets never sees it. We assert the guard aborts
    # the metadata request (the load that would feed the secret scraper).
    monkeypatch.setattr(netguard.settings, "BLOCK_PRIVATE_TARGETS", True)
    r = _MockRoute("http://169.254.169.254/latest/meta-data/iam/security-credentials/role")
    auth_crawl._guard_route(r, [])
    assert r.action == "abort"


# --------------------------------------------------------------------------- #
# 6. Scanner routing — the flagged scanners go through the guarded path.
# --------------------------------------------------------------------------- #
def test_flagged_scanners_route_through_safe_http(monkeypatch):
    from app.scanners import csrf, idor, jwt_audit
    from app.scanners import ssrf as ssrf_scanner

    def blocked(*a, **k):
        raise sh.BlockedDestination("http://blocked/", "metadata")
    monkeypatch.setattr(sh, "safe_request", blocked)

    # Each scanner's read helper must treat a guard block as a clean skip (None),
    # which only happens if it actually calls safe_http.safe_request.
    assert csrf._http("GET", "http://x/", {}) is None
    assert idor._http_get("http://x/", {}) is None
    assert jwt_audit._http("GET", "http://x/", {}) is None
    assert ssrf_scanner._http_get("http://x/") is None

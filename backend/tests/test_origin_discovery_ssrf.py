"""P1-B2 regression tests — origin-discovery candidate IPs pass netguard first.

Candidate origin IPs come from untrusted discovery sources (DNS history, crt.sh,
SPF). Each must clear the existing SSRF guard immediately before any connection;
a rejected candidate must NOT be probed. Every block test asserts the recorder
saw zero requests — i.e. no connection was made.
"""

import socket

import pytest

from app.scanners import origin_discovery as od


class FakeResp:
    status_code = 200
    headers = {"Content-Type": "text/plain"}
    text = "hello"


class Recorder:
    """Stand-in for requests.get that records every URL it is asked to fetch."""

    def __init__(self):
        self.calls = []

    def __call__(self, url, **kwargs):
        self.calls.append(url)
        return FakeResp()


# Literal blocked addresses (no DNS — deterministic netguard decision).
LITERAL_BLOCKED = [
    "10.0.0.5",          # RFC1918 private
    "192.168.1.1",       # RFC1918 private
    "127.0.0.1",         # loopback
    "169.254.1.1",       # link-local
    "169.254.169.254",   # cloud metadata (IPv4)
    "::1",               # IPv6 loopback
    "fe80::1",           # IPv6 link-local
    "fd00::1",           # IPv6 unique-local (private)
    "240.0.0.1",         # reserved
]


def test_valid_public_candidate_is_probed(monkeypatch):
    rec = Recorder()
    monkeypatch.setattr(od.requests, "get", rec)
    result = od._validate_origin("1.1.1.1", "example.com", set())
    assert rec.calls, "a valid public candidate must be probed"
    assert any("1.1.1.1" in u for u in rec.calls)
    assert result is not None


@pytest.mark.parametrize("ip", LITERAL_BLOCKED)
def test_blocked_literal_candidate_is_never_probed(monkeypatch, ip):
    rec = Recorder()
    monkeypatch.setattr(od.requests, "get", rec)
    result = od._validate_origin(ip, "example.com", set())
    assert result is None
    assert rec.calls == [], f"blocked candidate {ip} was contacted: {rec.calls}"


@pytest.mark.parametrize("bad", ["10.0.0.256", "999.999.999.999", "not-an-ip", "", ".."])
def test_malformed_candidate_is_never_probed(monkeypatch, bad):
    # Force any hostname-path resolution to fail so malformed strings can never
    # accidentally resolve to a routable address on the CI host's resolver.
    monkeypatch.setattr(
        od.netguard.socket, "getaddrinfo",
        lambda *a, **k: (_ for _ in ()).throw(socket.gaierror("no resolve")),
    )
    rec = Recorder()
    monkeypatch.setattr(od.requests, "get", rec)
    result = od._validate_origin(bad, "example.com", set())
    assert result is None
    assert rec.calls == []


def test_edge_ip_candidate_is_skipped(monkeypatch):
    rec = Recorder()
    monkeypatch.setattr(od.requests, "get", rec)
    result = od._validate_origin("1.1.1.1", "example.com", {"1.1.1.1"})
    assert result is None
    assert rec.calls == []


def test_duplicate_blocked_candidate_stays_unprobed(monkeypatch):
    rec = Recorder()
    monkeypatch.setattr(od.requests, "get", rec)
    od._validate_origin("10.0.0.5", "example.com", set())
    od._validate_origin("10.0.0.5", "example.com", set())  # repeated
    assert rec.calls == []

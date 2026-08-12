"""SSRF / egress guard tests for :mod:`app.netguard`.

These exercise :func:`validate_target` / :func:`validate_targets` directly.

To keep the suite hermetic (no real DNS, no network), every case that needs a
literal address uses one — a literal IP is checked with *no* DNS lookup — and
the hostname paths monkeypatch :func:`socket.getaddrinfo` to return a chosen set
of addresses (or raise), so DNS-rebinding and unresolvable-host behavior can be
asserted deterministically.
"""

import socket

import pytest

from app import netguard


# --------------------------------------------------------------------------- #
# Literal-IP cases (no DNS): the dangerous ranges are always refused.
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "target",
    [
        "127.0.0.1",          # IPv4 loopback
        "10.0.0.1",           # RFC1918 private
        "10.255.255.255",
        "192.168.1.1",        # RFC1918 private
        "172.16.0.1",         # RFC1918 private
        "169.254.169.254",    # cloud metadata (link-local)
        "::1",                # IPv6 loopback
        "fd00:ec2::254",      # AWS IPv6 metadata endpoint
        "0.0.0.0",            # unspecified
    ],
)
def test_dangerous_literal_ips_blocked(target):
    allowed, reason = netguard.validate_target(target)
    assert allowed is False
    assert reason


@pytest.mark.parametrize("target", ["8.8.8.8", "1.1.1.1", "93.184.216.34"])
def test_public_literal_ips_allowed(target):
    allowed, reason = netguard.validate_target(target)
    assert allowed is True
    assert reason == "ok"


def test_localhost_blocked():
    allowed, _ = netguard.validate_target("localhost")
    assert allowed is False


def test_localhost_subdomain_blocked():
    allowed, _ = netguard.validate_target("api.localhost")
    assert allowed is False


@pytest.mark.parametrize("target", ["", "   ", None])
def test_empty_target_blocked(target):
    allowed, reason = netguard.validate_target(target or "")
    assert allowed is False
    assert reason == "empty target"


def test_scheme_and_port_are_stripped_before_check():
    # http://127.0.0.1:8080/path reduces to the loopback literal -> blocked.
    allowed, _ = netguard.validate_target("http://127.0.0.1:8080/admin")
    assert allowed is False
    # A public literal with scheme/port/path stays allowed.
    allowed, _ = netguard.validate_target("https://8.8.8.8:443/resolve")
    assert allowed is True


# --------------------------------------------------------------------------- #
# BLOCK_PRIVATE_TARGETS toggle: private ranges pass when disabled, but the
# cloud-metadata endpoints stay blocked unconditionally.
# --------------------------------------------------------------------------- #
def test_block_private_false_lets_private_through(monkeypatch):
    monkeypatch.setattr(netguard.settings, "BLOCK_PRIVATE_TARGETS", False)
    for target in ["10.0.0.1", "192.168.1.1", "127.0.0.1", "::1"]:
        allowed, reason = netguard.validate_target(target)
        assert allowed is True, f"{target} -> {reason}"


def test_block_private_false_still_blocks_metadata(monkeypatch):
    monkeypatch.setattr(netguard.settings, "BLOCK_PRIVATE_TARGETS", False)
    for target in ["169.254.169.254", "fd00:ec2::254"]:
        allowed, _ = netguard.validate_target(target)
        assert allowed is False


# --------------------------------------------------------------------------- #
# Hostname cases: resolution is monkeypatched so no real DNS is used.
# --------------------------------------------------------------------------- #
def _fake_getaddrinfo(*addresses):
    """Build a getaddrinfo stand-in returning the given IP strings."""

    def _inner(host, port, *args, **kwargs):
        infos = []
        for addr in addresses:
            family = socket.AF_INET6 if ":" in addr else socket.AF_INET
            sockaddr = (addr, 0, 0, 0) if family == socket.AF_INET6 else (addr, 0)
            infos.append((family, socket.SOCK_STREAM, 6, "", sockaddr))
        return infos

    return _inner


def test_hostname_resolving_public_allowed(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo("93.184.216.34"))
    allowed, reason = netguard.validate_target("example.com")
    assert allowed is True
    assert reason == "ok"


def test_hostname_dns_rebinding_blocked(monkeypatch):
    # Host resolves to a public *and* a loopback address; the private one
    # (classic DNS-rebinding trick) must still get the whole target refused.
    monkeypatch.setattr(
        socket, "getaddrinfo", _fake_getaddrinfo("93.184.216.34", "127.0.0.1")
    )
    allowed, _ = netguard.validate_target("rebind.example.com")
    assert allowed is False


def test_hostname_resolving_to_metadata_blocked(monkeypatch):
    monkeypatch.setattr(
        socket, "getaddrinfo", _fake_getaddrinfo("169.254.169.254")
    )
    allowed, _ = netguard.validate_target("metadata.attacker.example")
    assert allowed is False


def test_unresolvable_hostname_blocked(monkeypatch):
    def _boom(host, port, *args, **kwargs):
        raise socket.gaierror("name resolution failed")

    monkeypatch.setattr(socket, "getaddrinfo", _boom)
    allowed, reason = netguard.validate_target("does-not-exist.invalid")
    assert allowed is False
    assert reason == "could not resolve host"


# --------------------------------------------------------------------------- #
# validate_targets: every item in a list must pass; first failure short-circuits.
# --------------------------------------------------------------------------- #
def test_validate_targets_all_public_allowed():
    allowed, reason = netguard.validate_targets("8.8.8.8, 1.1.1.1 93.184.216.34")
    assert allowed is True
    assert reason == "ok"


def test_validate_targets_one_bad_blocks_all():
    allowed, _ = netguard.validate_targets("8.8.8.8 127.0.0.1")
    assert allowed is False


def test_validate_targets_empty_blocked():
    allowed, reason = netguard.validate_targets("   ")
    assert allowed is False
    assert reason == "empty target"

"""Unit tests for app.scope.check — the legal/ethical scan guardrail.

``check(target, scope) -> (allowed: bool, reason: str)``.
"""

import pytest

from app import scope


def _allowed(target, scopes):
    ok, _reason = scope.check(target, scopes)
    return ok


# --------------------------------------------------------------------------- #
# Empty / unrestricted scope
# --------------------------------------------------------------------------- #
def test_empty_scope_is_unrestricted():
    assert _allowed("anything.com", []) is True
    assert _allowed("10.0.0.1", None) is True


# --------------------------------------------------------------------------- #
# Exact domain
# --------------------------------------------------------------------------- #
def test_exact_domain_matches():
    assert _allowed("example.com", ["example.com"]) is True


def test_exact_domain_rejects_other_domain():
    assert _allowed("evil.com", ["example.com"]) is False


# --------------------------------------------------------------------------- #
# Subdomains of an in-scope domain
# --------------------------------------------------------------------------- #
def test_subdomain_of_scoped_domain_matches():
    assert _allowed("api.example.com", ["example.com"]) is True
    assert _allowed("deep.nested.example.com", ["example.com"]) is True


def test_lookalike_suffix_is_not_a_subdomain():
    # notexample.com must NOT match example.com.
    assert _allowed("notexample.com", ["example.com"]) is False


# --------------------------------------------------------------------------- #
# Wildcard *.domain
# --------------------------------------------------------------------------- #
def test_wildcard_matches_subdomain_and_apex():
    assert _allowed("a.example.com", ["*.example.com"]) is True
    assert _allowed("example.com", ["*.example.com"]) is True


def test_wildcard_rejects_foreign_domain():
    assert _allowed("a.other.com", ["*.example.com"]) is False


# --------------------------------------------------------------------------- #
# CIDR ranges & IPs
# --------------------------------------------------------------------------- #
def test_cidr_contains_ip():
    assert _allowed("10.0.0.5", ["10.0.0.0/24"]) is True


def test_cidr_excludes_ip_outside_range():
    assert _allowed("10.0.1.5", ["10.0.0.0/24"]) is False


def test_exact_ip_matches():
    assert _allowed("8.8.8.8", ["8.8.8.8"]) is True
    assert _allowed("8.8.4.4", ["8.8.8.8"]) is False


# --------------------------------------------------------------------------- #
# Normalization (scheme / port / path are stripped before matching)
# --------------------------------------------------------------------------- #
def test_normalization_strips_scheme_port_and_path():
    assert _allowed("https://example.com:443/admin", ["example.com"]) is True
    assert _allowed("http://api.example.com/login", ["*.example.com"]) is True


# --------------------------------------------------------------------------- #
# Multi-target: every item must be in scope
# --------------------------------------------------------------------------- #
def test_multi_target_all_in_scope():
    assert _allowed("example.com, api.example.com", ["example.com"]) is True


def test_multi_target_one_out_of_scope_fails():
    ok, reason = scope.check("example.com, evil.com", ["example.com"])
    assert ok is False
    assert "evil.com" in reason


@pytest.mark.parametrize(
    "target,scopes,expected",
    [
        ("example.com", ["example.com"], True),
        ("sub.example.com", ["example.com"], True),
        ("x.example.com", ["*.example.com"], True),
        ("192.168.1.20", ["192.168.1.0/24"], True),
        ("192.168.2.20", ["192.168.1.0/24"], False),
        ("attacker.net", ["example.com", "*.corp.com"], False),
    ],
)
def test_scope_matrix(target, scopes, expected):
    assert _allowed(target, scopes) is expected

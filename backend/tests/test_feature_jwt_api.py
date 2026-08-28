"""Feature (JWT/API) tests: static JWT analysis + API-auth check.

No network for JWT analysis; HTTP monkeypatched for the API check. Covers
alg=none, missing/excessive exp, symmetric-alg note, sensitive claims, a clean
token (no findings), malformed tokens, no-raw-token-in-evidence, API missing-auth
(validated) vs. enforced (negative), and per-finding tier in derivation.
"""

import base64
import json

import pytest

from app import crud
from app.scanners import jwt_audit


def _mk_jwt(header, payload):
    def enc(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")
    return f"{enc(header)}.{enc(payload)}.sig"


# --------------------------------------------------------------------------- #
# JWT decode + static analysis
# --------------------------------------------------------------------------- #
def test_decode_rejects_malformed():
    assert jwt_audit._decode_jwt("only.two") is None
    assert jwt_audit._decode_jwt("a.b.c") is None          # not base64 json
    assert jwt_audit._decode_jwt("") is None


def test_alg_none_tiers_by_observation():
    tok = _mk_jwt({"alg": "none", "typ": "JWT"}, {"sub": "u", "iat": 1000})
    # Standalone token -> "suspicious token configuration" (SIGNAL, still critical).
    a = [f for f in jwt_audit._analyze_jwt(tok) if "alg: none" in f["name"]][0]
    assert a["detection_tier"] == "signal" and a["severity"] == "critical"
    assert a["cwe"] == ["CWE-347"] and a["evidence"]["observed_in_session"] is False
    # Observed in an active session -> "server configuration appears vulnerable" (VALIDATED).
    b = [f for f in jwt_audit._analyze_jwt(tok, observed=True) if "alg: none" in f["name"]][0]
    assert b["detection_tier"] == "validated"
    assert b["evidence"]["observed_in_session"] is True
    assert "server configuration appears vulnerable" in b["evidence"]["assessment"]


def test_observed_flag_promotes_config_findings():
    tok = _mk_jwt({"alg": "RS256"}, {"sub": "u"})   # missing exp
    sig = [f for f in jwt_audit._analyze_jwt(tok) if "no expiry" in f["name"]][0]
    val = [f for f in jwt_audit._analyze_jwt(tok, observed=True) if "no expiry" in f["name"]][0]
    assert sig["detection_tier"] == "signal"
    assert val["detection_tier"] == "validated"
    assert val["confidence"] > sig["confidence"]


def test_missing_exp_flagged():
    out = jwt_audit._analyze_jwt(_mk_jwt({"alg": "RS256"}, {"sub": "u"}))
    assert any("no expiry" in f["name"] for f in out)


def test_excessive_lifetime_flagged():
    tok = _mk_jwt({"alg": "RS256"}, {"iat": 1000, "exp": 1000 + 48 * 3600})
    out = jwt_audit._analyze_jwt(tok)
    life = [f for f in out if "excessive lifetime" in f["name"]]
    assert life and life[0]["evidence"]["lifetime_seconds"] == 48 * 3600


def test_symmetric_alg_is_signal_note():
    out = jwt_audit._analyze_jwt(_mk_jwt({"alg": "HS256"}, {"iat": 1000, "exp": 1000 + 600}))
    hs = [f for f in out if "symmetric" in f["name"]]
    assert hs and hs[0]["detection_tier"] == "signal"


def test_sensitive_claim_flagged():
    tok = _mk_jwt({"alg": "RS256"}, {"iat": 1000, "exp": 1000 + 600, "password": "x"})
    out = jwt_audit._analyze_jwt(tok)
    assert any("sensitive claim" in f["name"] for f in out)


def test_clean_token_has_no_findings():
    tok = _mk_jwt({"alg": "RS256"}, {"sub": "u", "iat": 1000, "exp": 1000 + 3600})
    assert jwt_audit._analyze_jwt(tok) == []


def test_evidence_never_contains_raw_token():
    tok = _mk_jwt({"alg": "none"}, {"sub": "secret-subject", "iat": 1000})
    out = jwt_audit._analyze_jwt(tok)
    for f in out:
        assert tok not in str(f["evidence"])            # raw token never stored
        assert "sig" not in str(f["evidence"].get("signature", ""))


# --------------------------------------------------------------------------- #
# API authentication check
# --------------------------------------------------------------------------- #
def test_api_missing_auth_is_validated(monkeypatch):
    def fake(url, headers):
        # Same authenticated data returned whether or not a session is presented.
        return (200, "orders total SHAREDDATA1234567890")

    monkeypatch.setattr(jwt_audit, "_http_get", fake)
    f = jwt_audit._check_api_auth("https://api.example.com/orders", {"Cookie": "s=1"})
    assert f and f["detection_tier"] == "validated"
    assert f["cwe"] == ["CWE-306"]
    assert f["evidence"]["shared_token"] == "SHAREDDATA1234567890"


def test_api_auth_enforced_is_negative(monkeypatch):
    def fake(url, headers):
        if headers.get("Cookie"):
            return (200, "private SHAREDDATA1234567890")
        return (403, "forbidden")            # anon denied

    monkeypatch.setattr(jwt_audit, "_http_get", fake)
    assert jwt_audit._check_api_auth("https://api.example.com/orders", {"Cookie": "s=1"}) is None


def test_api_login_page_is_not_missing_auth(monkeypatch):
    def fake(url, headers):
        if headers.get("Cookie"):
            return (200, "private SHAREDDATA1234567890")
        return (200, "<html><form>Please login with your password</form></html>")

    monkeypatch.setattr(jwt_audit, "_http_get", fake)
    assert jwt_audit._check_api_auth("https://api.example.com/orders", {"Cookie": "s=1"}) is None


# --------------------------------------------------------------------------- #
# Public-endpoint false positive: anon seeing the SAME content is the signature
# of a public resource, not missing auth (mirrors idor.py's anon_sees guard).
# The FP fix DEMOTES the ambiguous case to a low signal (info => 0 risk weight)
# rather than a validated/high finding — surfaced for a human, never inflating
# risk, and never silently dropped.
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("path,body", [
    ("/api/products", "catalog WIDGET1234567890 GADGET9876543210 price 9.99"),
    ("/api/config", '{"theme": "SETTINGS1234567890", "locale": "en"}'),
    ("/api/status", "ok BUILDHASH1234567890 uptime 1234 healthy true"),
    ("/api/anything", "welcome PUBLICDATA1234567890 no personal info here"),
    # A public page carrying an email must NOT promote to validated (bare email
    # is too FP-prone) — it is a signal at most.
    ("/api/contact", '{"support_note": "email us AAAAAAAAAAAA anytime"}'),
])
def test_api_public_endpoint_is_signal_not_validated(monkeypatch, path, body):
    """A legitimately PUBLIC / sensitivity-unconfirmed endpoint must NOT be a
    validated/high finding (that is the false positive). It is surfaced as a
    low-severity signal that does not inflate risk."""
    def fake(url, headers):
        return (200, body)  # identical to authed and anon; not strongly sensitive

    monkeypatch.setattr(jwt_audit, "_http_get", fake)
    f = jwt_audit._check_api_auth(f"https://api.example.com{path}", {"Cookie": "s=1"})
    assert f is not None
    assert f["detection_tier"] == "signal"
    assert f["severity"] == "info"                    # 0 risk weight -> no inflation
    assert f["evidence"]["sensitivity_confirmed"] is False


def test_api_protected_endpoint_denies_anon_no_finding(monkeypatch):
    """A genuinely protected endpoint (anon denied) yields no finding at all."""
    def fake(url, headers):
        return (200, "private SHAREDDATA1234567890") if headers.get("Cookie") else (401, "unauthorized")

    monkeypatch.setattr(jwt_audit, "_http_get", fake)
    assert jwt_audit._check_api_auth("https://api.example.com/api/me", {"Cookie": "s=1"}) is None


@pytest.mark.parametrize("path,body", [
    # per-subject path (sensitive by URL) leaking to anon
    ("/api/me", "profile SHAREDDATA1234567890 role admin"),
    # unusual path, but the shared body carries a SECRET key -> real leak
    ("/api/v1/integrations/1024", '{"webhook_secret": "whsec_SHAREDDATA1234567890"}'),
    # config dumping a credential is NOT public -> real leak (client_secret is a
    # sensitive key that, unlike "password", is not also a login-page hint)
    ("/api/config", '{"client_secret": "SHAREDDATA1234567890"}'),
])
def test_api_sensitive_data_leak_is_validated(monkeypatch, path, body):
    """EXISTING BEHAVIOR preserved (and false negatives recovered): a per-subject
    or secret-bearing resource that returns the same data to an unauthenticated
    request is still a validated missing-authentication finding."""
    def fake(url, headers):
        return (200, body)  # authed == anon, strongly sensitive content

    monkeypatch.setattr(jwt_audit, "_http_get", fake)
    f = jwt_audit._check_api_auth(f"https://api.example.com{path}", {"Cookie": "s=1"})
    assert f and f["detection_tier"] == "validated" and f["severity"] == "high"
    assert f["cwe"] == ["CWE-306"]
    assert f["evidence"]["sensitivity_confirmed"] is True


def test_api_unconfirmed_leak_is_signal_not_dropped(monkeypatch):
    """No false NEGATIVE: an anon-readable endpoint whose vocabulary is unusual
    and whose body has no obvious secret is still SURFACED (as a signal), never
    silently dropped — so a real leak can't vanish."""
    def fake(url, headers):
        return (200, "internal DASHBOARD1234567890 revenue figures q3")

    monkeypatch.setattr(jwt_audit, "_http_get", fake)
    f = jwt_audit._check_api_auth("https://api.example.com/reports/q3", {"Cookie": "s=1"})
    assert f is not None and f["detection_tier"] == "signal"


# --------------------------------------------------------------------------- #
# stream() integration + derive
# --------------------------------------------------------------------------- #
def test_stream_analyzes_token_and_endpoints(monkeypatch):
    monkeypatch.setattr(jwt_audit, "_http_get",
                        lambda url, headers: (200, "data SHAREDDATA1234567890"))
    tok = _mk_jwt({"alg": "none"}, {"sub": "u"})
    events = list(jwt_audit.stream(
        "", token=tok, api_endpoints=["https://api.example.com/orders"],
        identity={"cookie": "s=1"},
    ))
    res = next(e["data"] for e in events if e["type"] == "result")
    assert res["token_analyzed"] is True
    names = [f["name"] for f in res["findings"]]
    assert any("alg: none" in n for n in names)
    assert any("lacks authentication" in n for n in names)


def test_stream_malformed_target_errors():
    events = list(jwt_audit.stream("-oX", identity={"cookie": "s"}))
    assert any(e["type"] == "error" for e in events)


def test_derive_jwt_respects_per_finding_tier():
    result = {"findings": [
        {"severity": "critical", "name": "JWT uses 'alg: none'", "location": "jwt",
         "cwe": ["CWE-347"], "detection_tier": "validated", "confidence": 90,
         "evidence": {"alg": "none"}},
        {"severity": "info", "name": "JWT uses a symmetric algorithm", "location": "jwt",
         "cwe": ["CWE-326"], "detection_tier": "signal", "confidence": 40,
         "evidence": {"alg": "HS256"}},
    ]}
    out = crud.derive_findings("jwt", result)
    assert out[0]["detection_tier"] == "validated" and out[0]["confidence"] == 90
    assert out[1]["detection_tier"] == "signal" and out[1]["confidence"] == 40
    assert out[0]["kind"] == "vuln"

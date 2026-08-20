"""Feature (JWT/API) tests: static JWT analysis + API-auth check.

No network for JWT analysis; HTTP monkeypatched for the API check. Covers
alg=none, missing/excessive exp, symmetric-alg note, sensitive claims, a clean
token (no findings), malformed tokens, no-raw-token-in-evidence, API missing-auth
(validated) vs. enforced (negative), and per-finding tier in derivation.
"""

import base64
import json

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

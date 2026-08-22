"""Feature (open redirect / CWE-601) tests — read-only, HTTP monkeypatched.

Covers candidate detection, server-side 3xx to an external canary (reported),
same-origin and relative redirects (NOT reported), the protocol-relative bypass,
client-side meta-refresh (reported) vs a merely-reflected link (NOT reported),
non-candidate params, no params, malformed target, and per-finding derivation.
No network: ``open_redirect._probe`` is patched.
"""

from app import crud
from app.scanners import open_redirect
from app.scanners.open_redirect import _CANARY_HOST as CANARY

TARGET = "https://app.example.com/login?next=/home&id=1"


def _result(monkeypatch, fake, target=TARGET):
    monkeypatch.setattr(open_redirect, "_probe", fake)
    events = list(open_redirect.stream(target))
    return next(e["data"] for e in events if e["type"] == "result")


def test_candidate_detection():
    assert open_redirect._is_candidate("next", "1")
    assert open_redirect._is_candidate("redirect_uri", "x")
    assert open_redirect._is_candidate("q", "https://x")   # url-shaped value
    assert not open_redirect._is_candidate("id", "1")
    assert not open_redirect._is_candidate("name", "bob")


def test_redirect_host_helper():
    assert open_redirect._redirect_host(f"https://{CANARY}/x") == CANARY
    assert open_redirect._redirect_host(f"//{CANARY}/x") == CANARY
    assert open_redirect._redirect_host(f"https://user@{CANARY}/") == CANARY   # userinfo bypass
    assert open_redirect._redirect_host("/relative/path") == ""
    assert open_redirect._redirect_host("") == ""


def test_external_3xx_redirect_is_reported(monkeypatch):
    """External off-origin 3xx redirect -> reported as CWE-601 (validated)."""
    def fake(url):
        if CANARY in url:                         # app redirects to whatever 'next' is
            return (302, f"https://{CANARY}/", "")
        return (200, "", "home")

    res = _result(monkeypatch, fake)
    f = [x for x in res["findings"] if x["name"].startswith("Open redirect")]
    assert len(f) == 1
    assert f[0]["cwe"] == ["CWE-601"]
    assert f[0]["detection_tier"] == "validated" and f[0]["severity"] == "medium"
    assert f[0]["confidence"] == 80
    ev = f[0]["evidence"]
    assert ev["parameter"] == "next" and ev["method"] == "GET"
    assert ev["redirect_via"] == "3xx-location" and ev["off_origin"] is True
    assert res["tested_params"] == ["next"]


def test_same_origin_redirect_not_reported(monkeypatch):
    """A redirect that stays on the target's own origin is NOT an open redirect."""
    def fake(url):
        return (302, "https://app.example.com/dashboard", "")   # ignores 'next'

    res = _result(monkeypatch, fake)
    assert not [x for x in res["findings"] if x["name"].startswith("Open redirect")]


def test_relative_redirect_not_reported(monkeypatch):
    def fake(url):
        return (302, "/account", "")   # relative -> same origin

    res = _result(monkeypatch, fake)
    assert not [x for x in res["findings"] if x["name"].startswith("Open redirect")]


def test_no_redirect_not_reported(monkeypatch):
    def fake(url):
        return (200, "", "just a page, no redirect")

    res = _result(monkeypatch, fake)
    assert res["findings"] == []


def test_protocol_relative_bypass_reported(monkeypatch):
    """App sanitizes absolute external redirects but is bypassed by //host."""
    def fake(url):
        if "https%3A%2F%2Fopenredirect.invalid" in url:   # absolute payload -> sanitized
            return (302, "https://app.example.com/", "")
        if "%2F%2Fopenredirect.invalid" in url:           # protocol-relative payload -> bypass
            return (302, f"//{CANARY}/foo", "")
        return (200, "", "")

    res = _result(monkeypatch, fake)
    f = [x for x in res["findings"] if x["name"].startswith("Open redirect")]
    assert len(f) == 1
    assert f[0]["evidence"]["payload"] == f"//{CANARY}/"
    assert f[0]["evidence"]["redirect_via"] == "3xx-location"


def test_meta_refresh_redirect_reported(monkeypatch):
    """Client-side meta-refresh to the canary is reported (lower confidence)."""
    def fake(url):
        if CANARY in url:
            body = f'<html><head><meta http-equiv="refresh" content="0; url=https://{CANARY}/"></head></html>'
            return (200, "", body)
        return (200, "", "")

    res = _result(monkeypatch, fake)
    f = [x for x in res["findings"] if x["name"].startswith("Open redirect")]
    assert len(f) == 1
    assert f[0]["evidence"]["redirect_via"] == "meta-refresh"
    assert f[0]["confidence"] == 65        # client-side < server-side 3xx


def test_reflected_link_not_reported(monkeypatch):
    """The canary merely reflected inside a normal link (not a redirect
    construct) must NOT be reported — avoids a reflection false positive."""
    def fake(url):
        if CANARY in url:
            body = f'<html><body>Go to <a href="https://{CANARY}/">here</a></body></html>'
            return (200, "", body)
        return (200, "", "")

    res = _result(monkeypatch, fake)
    assert not [x for x in res["findings"] if x["name"].startswith("Open redirect")]


def test_non_candidate_params_not_tested(monkeypatch):
    monkeypatch.setattr(open_redirect, "_probe", lambda u: (200, "", ""))
    events = list(open_redirect.stream("https://app.example.com/x?id=1&name=bob"))
    res = next(e["data"] for e in events if e["type"] == "result")
    assert res["tested_params"] == [] and res["findings"] == []


def test_no_params_no_findings(monkeypatch):
    monkeypatch.setattr(open_redirect, "_probe", lambda u: (200, "", ""))
    events = list(open_redirect.stream("https://app.example.com/plain"))
    res = next(e["data"] for e in events if e["type"] == "result")
    assert res["findings"] == []


def test_malformed_target_errors():
    events = list(open_redirect.stream("-oX"))
    assert any(e["type"] == "error" for e in events)


def test_derive_open_redirect_is_vuln():
    result = {"findings": [{
        "severity": "medium", "name": "Open redirect in 'next'", "location": "u",
        "cwe": ["CWE-601"], "detection_tier": "validated", "confidence": 80,
        "evidence": {"parameter": "next", "redirect_via": "3xx-location"}}]}
    out = crud.derive_findings("open_redirect", result)
    assert out[0]["detection_tier"] == "validated" and out[0]["confidence"] == 80
    assert out[0]["kind"] == "vuln" and out[0]["cwe"] == ["CWE-601"]

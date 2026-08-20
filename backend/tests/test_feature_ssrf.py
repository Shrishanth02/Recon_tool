"""Feature (SSRF) tests: candidate detection + safe reflective validation.

HTTP is monkeypatched — no network. Covers positive (reflective -> validated),
negative (no reflection -> possible, never falsely validated), non-candidate
params, no-params, malformed target, and per-finding tier in derivation.
"""

from app import crud
from app.scanners import ssrf
from app.scanners.ssrf import _BENIGN

TARGET = "https://app.example.com/fetch?url=http://example.org/x&id=1"


def _result(monkeypatch, fake):
    monkeypatch.setattr(ssrf, "_http_get", fake)
    events = list(ssrf.stream(TARGET))
    return next(e["data"] for e in events if e["type"] == "result")


def test_candidate_detection():
    assert ssrf._is_candidate("url", "abc")          # name-based
    assert ssrf._is_candidate("q", "http://x")       # url value
    assert ssrf._is_candidate("redirect", "1")       # name-based
    assert not ssrf._is_candidate("id", "1")
    assert not ssrf._is_candidate("name", "bob")


def test_reflective_ssrf_is_validated(monkeypatch):
    def fake(url):
        if url == "https://app.example.com/":                 # canary root
            return (200, "<title>WelcomeToCanaryZONE9town</title>")
        if _BENIGN in url:                                    # benign baseline
            return (200, "<html>baseline</html>")
        return (200, "server fetched WelcomeToCanaryZONE9town content")  # reflects canary content

    res = _result(monkeypatch, fake)
    validated = [f for f in res["findings"] if f["detection_tier"] == "validated"]
    assert len(validated) == 1
    f = validated[0]
    assert f["cwe"] == ["CWE-918"]
    assert f["confidence"] == 85
    assert f["evidence"]["reflected_marker"] == "WelcomeToCanaryZONE9town"
    assert f["evidence"]["parameter"] == "url"
    assert f["evidence"]["method"] == "GET"


def test_no_reflection_stays_possible(monkeypatch):
    def fake(url):
        if url == "https://app.example.com/":
            return (200, "<title>SomeCanaryTitleXYZ</title>")
        return (200, "<html>no reflection here</html>")       # baseline + test: no marker

    res = _result(monkeypatch, fake)
    assert not [f for f in res["findings"] if f["detection_tier"] == "validated"]
    possible = [f for f in res["findings"] if f["detection_tier"] == "signal"]
    assert possible and possible[0]["confidence"] == 40
    # Blind cannot be confirmed without OAST — the finding says so honestly.
    assert "OAST" in possible[0]["evidence"]["note"] or "reflection" in possible[0]["evidence"]["note"]
    assert res["oast_available"] is False


def test_non_candidate_params_not_tested(monkeypatch):
    monkeypatch.setattr(ssrf, "_http_get", lambda u: (200, ""))
    events = list(ssrf.stream("https://app.example.com/x?id=1&name=bob"))
    res = next(e["data"] for e in events if e["type"] == "result")
    assert res["tested_params"] == []
    assert res["findings"] == []


def test_no_params_no_findings(monkeypatch):
    monkeypatch.setattr(ssrf, "_http_get", lambda u: (200, ""))
    events = list(ssrf.stream("https://app.example.com/plain"))
    res = next(e["data"] for e in events if e["type"] == "result")
    assert res["findings"] == []


def test_malformed_target_errors():
    events = list(ssrf.stream("-oX"))
    assert any(e["type"] == "error" for e in events)


def test_derive_ssrf_respects_per_finding_tier():
    result = {"findings": [
        {"severity": "high", "name": "SSRF (reflective) in 'url'", "location": "u",
         "cwe": ["CWE-918"], "detection_tier": "validated", "confidence": 85,
         "evidence": {"parameter": "url"}},
        {"severity": "medium", "name": "Possible SSRF in 'next'", "location": "u",
         "cwe": ["CWE-918"], "detection_tier": "signal", "confidence": 40,
         "evidence": {"parameter": "next"}},
    ]}
    out = crud.derive_findings("ssrf", result)
    assert out[0]["detection_tier"] == "validated" and out[0]["confidence"] == 85
    assert out[1]["detection_tier"] == "signal" and out[1]["confidence"] == 40
    assert out[0]["kind"] == "vuln"
    assert out[0]["evidence"]["parameter"] == "url"

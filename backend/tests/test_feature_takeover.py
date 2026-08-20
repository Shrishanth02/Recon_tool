"""Feature 2 tests: subdomain-takeover detection.

Unit-tests the scanner's decision logic (DNS + HTTP monkeypatched — no network)
and the ``takeover`` derive branch. Positive (fingerprint / dangling), negative
(serving normally / no CNAME / non-provider) and malformed cases.
"""

from app import crud
from app.scanners import takeover


def _run(host, monkeypatch, *, cname, dns_status="ok", body="", status=None, nxdomain=False):
    monkeypatch.setattr(takeover, "_resolve_cname", lambda h: (cname, dns_status))
    monkeypatch.setattr(takeover, "_target_nxdomain", lambda n: nxdomain)
    monkeypatch.setattr(takeover, "_fetch", lambda h: (body, status, None))
    events = list(takeover.stream(host))
    return next(e["data"] for e in events if e["type"] == "result")


# --------------------------------------------------------------------------- #
# Positive
# --------------------------------------------------------------------------- #
def test_fingerprint_match_is_validated(monkeypatch):
    res = _run("sub.example.com", monkeypatch, cname="mybucket.s3.amazonaws.com",
               body="<Error><Code>NoSuchBucket</Code></Error>", status=404)
    assert len(res["findings"]) == 1
    f = res["findings"][0]
    assert f["detection_tier"] == "validated"
    assert f["confidence"] == 90
    assert f["severity"] == "high"
    assert f["evidence"]["provider"] == "AWS/S3"
    assert f["evidence"]["fingerprint"] == "NoSuchBucket"
    assert "CWE-350" in f["cwe"]


def test_dangling_cname_is_signal(monkeypatch):
    # Heroku CNAME, target does not resolve, no body fingerprint -> SIGNAL.
    res = _run("sub.example.com", monkeypatch, cname="dead-app.herokuapp.com",
               body="", status=None, nxdomain=True)
    assert len(res["findings"]) == 1
    f = res["findings"][0]
    assert f["detection_tier"] == "signal"
    assert f["confidence"] == 70
    assert f["evidence"]["dangling"] is True


def test_body_fingerprint_without_provider_cname(monkeypatch):
    # CNAME not obviously a provider, but the body carries GitHub's fingerprint.
    res = _run("sub.example.com", monkeypatch, cname="host.example.net",
               body="There isn't a GitHub Pages site here.", status=404)
    assert len(res["findings"]) == 1
    assert res["findings"][0]["evidence"]["provider"] == "GitHub Pages"
    assert res["findings"][0]["detection_tier"] == "validated"


# --------------------------------------------------------------------------- #
# Negative — conservative (no false positives)
# --------------------------------------------------------------------------- #
def test_provider_serving_normally_no_finding(monkeypatch):
    res = _run("sub.example.com", monkeypatch, cname="mybucket.s3.amazonaws.com",
               body="<html>welcome</html>", status=200, nxdomain=False)
    assert res["findings"] == []


def test_bare_cname_to_non_provider_no_finding(monkeypatch):
    res = _run("sub.example.com", monkeypatch, cname="internal.corp.example",
               body="<html>ok</html>", status=200)
    assert res["findings"] == []


def test_no_cname_no_finding(monkeypatch):
    res = _run("sub.example.com", monkeypatch, cname=None, dns_status="no-cname")
    assert res["findings"] == []
    assert res["provider"] is None


def test_dangling_but_provider_not_dangling_vulnerable(monkeypatch):
    # AWS/S3's takeover signal is the body fingerprint, not a dangling target;
    # a dangling S3 CNAME with no fingerprint must NOT be reported.
    res = _run("sub.example.com", monkeypatch, cname="b.s3.amazonaws.com",
               body="", status=None, nxdomain=True)
    assert res["findings"] == []


def test_malformed_target_yields_error():
    events = list(takeover.stream("   "))
    assert any(e["type"] == "error" for e in events)


# --------------------------------------------------------------------------- #
# derive_findings — takeover branch carries per-finding tier/confidence
# --------------------------------------------------------------------------- #
def test_derive_takeover_validated():
    result = {"findings": [{
        "severity": "high", "name": "Subdomain takeover: x (AWS/S3)", "location": "x",
        "cwe": ["CWE-350"], "detection_tier": "validated", "confidence": 90,
        "evidence": {"provider": "AWS/S3", "fingerprint": "NoSuchBucket"},
    }]}
    out = crud.derive_findings("takeover", result)
    assert out[0]["detection_tier"] == "validated"
    assert out[0]["kind"] == "vuln"
    assert out[0]["confidence"] == 90
    assert out[0]["evidence"]["provider"] == "AWS/S3"


def test_derive_takeover_signal():
    result = {"findings": [{
        "severity": "high", "name": "Potential takeover", "location": "x",
        "cwe": ["CWE-350"], "detection_tier": "signal", "confidence": 70,
        "evidence": {"dangling": True, "provider": "Heroku"},
    }]}
    out = crud.derive_findings("takeover", result)
    assert out[0]["detection_tier"] == "signal"
    assert out[0]["confidence"] == 70
    assert out[0]["evidence"]["dangling"] is True


def test_derive_takeover_empty():
    assert crud.derive_findings("takeover", {"findings": []}) == []

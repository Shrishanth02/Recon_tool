"""P1 regression tests: cross-scanner correlation + safe Tier-2 validation.

Covers correlation of same-issue findings across sources, non-matching findings
staying separate, host-context enrichment, safe validation success/failure, the
scope + netguard gates on validation, and the sqlmap/webaudit evidence
improvements. Network is never touched — validation's HTTP + netguard calls are
monkeypatched.
"""

from app import correlate, crud, models, validate
from app.database import SessionLocal


# --------------------------------------------------------------------------- #
# Fixtures / helpers
# --------------------------------------------------------------------------- #
def _ws(db, email="p1@example.com"):
    _u, _o, ws = crud.create_user_with_org(db, email, "password123")
    db.commit()
    return ws


def _mk_finding(db, ws_id, **kw):
    """Insert a Finding (with its own Scan) directly, for deterministic tests."""
    scan = models.Scan(
        workspace_id=ws_id, tool=kw.get("source", "nuclei"), target="t",
        status="done", options={}, logs=[], result=kw.get("scan_result", {}),
    )
    db.add(scan)
    db.flush()
    f = models.Finding(
        scan_id=scan.id, workspace_id=ws_id,
        source=kw.get("source", "nuclei"), severity=kw.get("severity", "high"),
        name=kw.get("name", "finding"), location=kw.get("location", "https://app.example.com/"),
        description=kw.get("description", ""), cve=kw.get("cve", []) or [], cwe=kw.get("cwe", []) or [],
        cvss=kw.get("cvss"), status="open",
        detection_tier=kw.get("tier", "signal"), kind=kw.get("kind", "vuln"),
        confidence=kw.get("confidence", 50), evidence=kw.get("evidence", {}) or {},
        dedupe_key=kw.get("dedupe_key", f"k{kw.get('name','')}"), seen_count=1, related=[],
    )
    db.add(f)
    db.flush()
    return f


class FakeResp:
    """Minimal stand-in for a requests.Response used by validate/webaudit tests."""

    def __init__(self, status=200, headers=None, text=""):
        self.status_code = status
        self.headers = headers or {}
        self.text = text
        self.reason = "OK"
        self.content = (text or "").encode()

        class _Raw:
            pass

        self.raw = _Raw()
        self.raw.headers = {}  # no getlist -> no Set-Cookie parsing


# --------------------------------------------------------------------------- #
# Correlation
# --------------------------------------------------------------------------- #
def test_correlates_same_issue_across_sources():
    db = SessionLocal()
    try:
        ws = _ws(db)
        # Same host + endpoint + CWE-89, two DIFFERENT scanners.
        nf = _mk_finding(db, ws.id, source="nuclei", name="SQLi (nuclei)",
                         location="https://app.example.com/search", cwe=["CWE-89"],
                         tier="signal", confidence=50)
        inj = _mk_finding(db, ws.id, source="injection", name="SQL Injection: id",
                          location="https://app.example.com/search", cwe=["CWE-89"],
                          tier="validated", confidence=90)
        db.commit()
        out = correlate.correlate_workspace(db, ws.id)
        db.commit()
        assert out["groups"] == 1
        db.expire_all()
        nf2, inj2 = crud.get_finding(db, nf.id), crud.get_finding(db, inj.id)
        # Linked under one correlation id, each referencing the other.
        assert nf2.correlation_id and nf2.correlation_id == inj2.correlation_id
        assert {r["source"] for r in nf2.related} == {"injection"}
        assert {r["source"] for r in inj2.related} == {"nuclei"}
        # Corroboration floor: the signal is raised (validated member present) but
        # NEVER to validated-level; the validated finding keeps high confidence.
        assert nf2.confidence == 75
        assert nf2.detection_tier == "signal"      # correlation never validates
        assert inj2.confidence == 90
    finally:
        db.close()


def test_correlation_is_idempotent():
    db = SessionLocal()
    try:
        ws = _ws(db)
        nf = _mk_finding(db, ws.id, source="nuclei", name="SQLi",
                         location="https://app.example.com/s", cwe=["CWE-89"], confidence=50)
        _mk_finding(db, ws.id, source="injection", name="SQL Injection",
                    location="https://app.example.com/s", cwe=["CWE-89"], tier="validated", confidence=90)
        db.commit()
        correlate.correlate_workspace(db, ws.id); db.commit()
        correlate.correlate_workspace(db, ws.id); db.commit()  # run twice
        db.expire_all()
        assert crud.get_finding(db, nf.id).confidence == 75  # not compounded
    finally:
        db.close()


def test_does_not_correlate_different_issues():
    db = SessionLocal()
    try:
        ws = _ws(db)
        a = _mk_finding(db, ws.id, source="nuclei", name="SQLi",
                        location="https://app.example.com/search", cwe=["CWE-89"])
        b = _mk_finding(db, ws.id, source="injection", name="XSS",
                        location="https://app.example.com/other", cwe=["CWE-79"])
        db.commit()
        out = correlate.correlate_workspace(db, ws.id); db.commit()
        assert out["groups"] == 0
        db.expire_all()
        assert crud.get_finding(db, a.id).correlation_id is None
        assert crud.get_finding(db, b.id).correlation_id is None
        assert crud.get_finding(db, a.id).related == []
    finally:
        db.close()


def test_same_key_single_source_not_correlated():
    db = SessionLocal()
    try:
        ws = _ws(db)
        # Same host/endpoint/CWE but SAME source (two nuclei templates) -> not a
        # cross-scanner corroboration, so not correlated.
        a = _mk_finding(db, ws.id, source="nuclei", name="SQLi A",
                        location="https://app.example.com/search", cwe=["CWE-89"], dedupe_key="a")
        _mk_finding(db, ws.id, source="nuclei", name="SQLi B",
                    location="https://app.example.com/search", cwe=["CWE-89"], dedupe_key="b")
        db.commit()
        out = correlate.correlate_workspace(db, ws.id); db.commit()
        assert out["groups"] == 0
        db.expire_all()
        assert crud.get_finding(db, a.id).correlation_id is None
    finally:
        db.close()


def test_host_context_enrichment_from_httpx():
    db = SessionLocal()
    try:
        ws = _ws(db)
        # An httpx scan providing server/tech for the host.
        crud.save_scan(db, {
            "tool": "httpx", "target": "app.example.com", "status": "done",
            "options": {}, "logs": [],
            "result": {"rows": [{"url": "https://app.example.com", "host": "app.example.com",
                                 "webserver": "nginx", "tech": ["PHP"], "status": 200}]},
            "started_at": None, "finished_at": None, "workspace_id": ws.id,
        })
        f = _mk_finding(db, ws.id, source="nuclei", name="Some vuln",
                        location="https://app.example.com/x", cwe=["CWE-79"])
        db.commit()
        correlate.correlate_workspace(db, ws.id); db.commit()
        db.expire_all()
        ctx = crud.get_finding(db, f.id).evidence.get("host_context") or {}
        assert ctx.get("server") == "nginx"
        assert ctx.get("tech") == ["PHP"]
    finally:
        db.close()


# --------------------------------------------------------------------------- #
# Safe validation — success / failure / gates
# --------------------------------------------------------------------------- #
def _header_finding(db, ws):
    return _mk_finding(
        db, ws.id, source="nuclei",
        name="Missing security header: content-security-policy",
        location="https://app.example.com/", cwe=["CWE-693"], tier="signal", confidence=50,
    )


def test_validation_success_promotes_signal_to_validated(monkeypatch):
    db = SessionLocal()
    try:
        ws = _ws(db)
        f = _header_finding(db, ws)
        db.commit()
        monkeypatch.setattr(validate.netguard, "validate_target", lambda h: (True, "ok"))
        # Header still absent on re-fetch -> confirmed. The fetch now goes through
        # the guarded path (safe_http), so mock that (returns the fake re-fetch).
        monkeypatch.setattr(validate.safe_http, "safe_request",
                            lambda method, url, **k: FakeResp(200, {"server": "nginx"}, ""))
        out = validate.validate_workspace(ws.id, scope_list=None)
        assert out["validated"] == 1
        db.expire_all()
        f2 = crud.get_finding(db, f.id)
        assert f2.detection_tier == "validated"
        assert f2.confidence >= 85
        assert f2.evidence["validation"]["result"] == "confirmed"
        assert f2.evidence.get("observed") == "absent"   # observed value preserved
    finally:
        db.close()


def test_validation_failure_stays_signal(monkeypatch):
    db = SessionLocal()
    try:
        ws = _ws(db)
        f = _header_finding(db, ws)
        db.commit()
        monkeypatch.setattr(validate.netguard, "validate_target", lambda h: (True, "ok"))
        # Header is now PRESENT -> the "missing header" claim no longer holds.
        monkeypatch.setattr(validate.requests, "get",
                            lambda *a, **k: FakeResp(200, {"content-security-policy": "default-src 'self'"}, ""))
        out = validate.validate_workspace(ws.id, scope_list=None)
        assert out["validated"] == 0
        db.expire_all()
        f2 = crud.get_finding(db, f.id)
        assert f2.detection_tier == "signal"            # never falsely validated
        assert f2.evidence["validation"]["result"] == "not_confirmed"
    finally:
        db.close()


def test_validation_blocked_by_netguard_never_fetches(monkeypatch):
    db = SessionLocal()
    try:
        ws = _ws(db)
        f = _header_finding(db, ws)
        db.commit()
        monkeypatch.setattr(validate.netguard, "validate_target", lambda h: (False, "blocked address"))
        calls = {"n": 0}

        def boom(*a, **k):
            calls["n"] += 1
            raise AssertionError("validation must not fetch when netguard blocks")

        monkeypatch.setattr(validate.requests, "get", boom)
        out = validate.validate_workspace(ws.id, scope_list=None)
        assert out["validated"] == 0
        assert calls["n"] == 0                          # SSRF guard ran BEFORE any request
        db.expire_all()
        f2 = crud.get_finding(db, f.id)
        assert f2.detection_tier == "signal"
        assert "netguard" in (f2.evidence.get("validation", {}).get("reason") or "")
    finally:
        db.close()


def test_validation_blocked_by_scope_never_fetches(monkeypatch):
    db = SessionLocal()
    try:
        ws = _ws(db)
        f = _header_finding(db, ws)  # host app.example.com
        db.commit()
        monkeypatch.setattr(validate.netguard, "validate_target", lambda h: (True, "ok"))

        def boom(*a, **k):
            raise AssertionError("validation must not fetch out-of-scope host")

        monkeypatch.setattr(validate.requests, "get", boom)
        # Scope excludes the finding's host.
        out = validate.validate_workspace(ws.id, scope_list=["other.example.com"])
        assert out["validated"] == 0
        db.expire_all()
        f2 = crud.get_finding(db, f.id)
        assert f2.detection_tier == "signal"
        assert "scope" in (f2.evidence.get("validation", {}).get("reason") or "")
    finally:
        db.close()


def test_already_validated_finding_not_reattempted(monkeypatch):
    db = SessionLocal()
    try:
        ws = _ws(db)
        # A validated injection finding (like sqlmap) must be preserved, not re-run.
        _mk_finding(db, ws.id, source="injection", name="SQL Injection: id",
                    location="https://app.example.com/s?id=1", cwe=["CWE-89"], tier="validated", confidence=90)
        db.commit()

        def boom(*a, **k):
            raise AssertionError("already-validated findings must not be re-fetched")

        monkeypatch.setattr(validate.requests, "get", boom)
        monkeypatch.setattr(validate.netguard, "validate_target", lambda h: (True, "ok"))
        out = validate.validate_workspace(ws.id, scope_list=None)
        assert out["attempted"] == 0    # signal-only query never selected it
    finally:
        db.close()


# --------------------------------------------------------------------------- #
# Evidence improvements (sqlmap + webaudit)
# --------------------------------------------------------------------------- #
def test_injection_normalise_carries_payload_evidence():
    from app.scanners.injection import _normalise

    sqli = [{
        "param": "id", "place": "GET", "types": ["boolean-based blind"],
        "payloads": ["id=1 AND 1=1"], "dbms": "MySQL", "url": "https://x?id=1", "title": "t",
    }]
    out = _normalise(sqli, [])
    ev = out[0]["evidence"]
    assert ev["parameter"] == "id"
    assert ev["technique"] == ["boolean-based blind"]
    assert ev["payloads"] == ["id=1 AND 1=1"]      # the confirmed payload is captured
    assert ev["dbms"] == "MySQL"


def test_derive_preserves_injection_evidence():
    result = {"findings": [{
        "severity": "high", "name": "SQL Injection: id", "location": "https://x?id=1",
        "cwe": "CWE-89", "evidence": {"parameter": "id", "payloads": ["p"]},
    }]}
    out = crud.derive_findings("injection", result)
    assert out[0]["detection_tier"] == "validated"
    assert out[0]["evidence"]["parameter"] == "id"
    assert out[0]["evidence"]["payloads"] == ["p"]


def test_webaudit_missing_header_carries_observed_evidence(monkeypatch):
    from app.scanners import webaudit

    monkeypatch.setattr(webaudit, "_get", lambda *a, **k: FakeResp(200, {"server": "nginx"}, ""))
    findings, header_report = [], {}
    list(webaudit._check_headers_cookies_content("https://x/", findings, header_report))
    missing = [f for f in findings if f["name"].startswith("Missing security header")]
    assert missing
    ev = missing[0].get("evidence") or {}
    assert ev.get("observed") == "absent"
    assert ev.get("http_status") == 200

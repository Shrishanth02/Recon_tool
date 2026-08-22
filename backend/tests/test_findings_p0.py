"""P0 regression tests for the upgraded finding system.

Covers the SIGNAL vs VALIDATED classification, evidence capture, confidence,
``kind`` separation (vuln vs recon/info/hardening), safe deduplication, and the
unified confidence-aware risk scorer. Pure-function tests hit
``crud.derive_findings`` / ``risk.workspace_risk`` directly; persistence tests
use the hermetic SQLite session from ``conftest``.
"""

from datetime import datetime, timezone

from app import crud, risk, schemas
from app.database import SessionLocal


# --------------------------------------------------------------------------- #
# derive_findings — classification, tier, confidence, evidence
# --------------------------------------------------------------------------- #
def test_nuclei_finding_is_signal_with_rr_evidence():
    result = {"findings": [{
        "template_id": "cve-2023-1", "name": "Some CVE", "severity": "high",
        "matched_at": "https://x/y", "tags": ["cve", "sqli"], "description": "d",
        "cve": ["CVE-2023-1"], "cwe": ["CWE-89"], "cvss": 7.5,
        "request": "GET /y HTTP/1.1", "response": "HTTP/1.1 200 OK",
    }]}
    out = crud.derive_findings("nuclei", result)
    assert len(out) == 1
    f = out[0]
    # A raw nuclei match is a SIGNAL, not validated.
    assert f["detection_tier"] == "signal"
    assert f["kind"] == "vuln"
    assert f["confidence"] == 50
    # Request/response + template metadata are preserved as real evidence.
    assert f["evidence"]["request"].startswith("GET")
    assert f["evidence"]["response"].startswith("HTTP")
    assert f["evidence"]["template_id"] == "cve-2023-1"
    assert f["evidence"]["tags"] == ["cve", "sqli"]
    # tags carried transiently so ATT&CK mapping can classify (not persisted).
    assert f["tags"] == ["cve", "sqli"]


def test_nmap_open_port_is_recon_not_vuln():
    result = {"host": "h", "ports": [
        {"port": 22, "protocol": "tcp", "state": "open", "service": "ssh"},
    ]}
    out = crud.derive_findings("nmap", result)
    assert len(out) == 1
    assert out[0]["kind"] == "recon"
    assert out[0]["detection_tier"] == "signal"
    assert out[0]["evidence"]["port"] == 22


def test_dirbuster_path_is_info_kind():
    out = crud.derive_findings(
        "dirbuster", {"rows": [{"path": "admin", "url": "https://x/admin", "status": 200}]}
    )
    assert out and out[0]["kind"] == "info"


def test_waf_findings_are_hardening_kind():
    result = {"findings": [{
        "severity": "low", "name": "WAF did not block XSS", "location": "https://x",
        "category": "xss", "payload": "<x>", "status": 200,
    }]}
    out = crud.derive_findings("waf", result)
    assert out and out[0]["kind"] == "hardening"
    assert out[0]["evidence"].get("category") == "xss"


def test_axfr_success_is_validated_vuln_with_evidence():
    result = {
        "domain": "example.com", "vulnerable": True,
        "vulnerable_nameservers": ["ns1.example.com"],
        "records": ["a 1 IN A 1.2.3.4", "b 1 IN A 1.2.3.5"], "record_count": 2,
    }
    out = crud.derive_findings("dns_zt", result)
    assert len(out) == 1
    f = out[0]
    assert f["detection_tier"] == "validated"   # a real AXFR that succeeded
    assert f["kind"] == "vuln"
    assert f["confidence"] == 95
    assert f["severity"] == "high"
    assert f["cwe"] == ["CWE-200"]
    assert f["evidence"]["record_count"] == 2
    assert f["evidence"]["records"]             # transferred records = evidence


def test_axfr_refused_yields_no_finding():
    out = crud.derive_findings("dns_zt", {"domain": "x", "vulnerable": False, "records": []})
    assert out == []


def test_js_secrets_are_signal_vuln_findings():
    result = {"js_secrets": [
        {"type": "aws_access_key", "preview": "AKIA...xxxx", "source": "https://x/app.js"},
    ]}
    out = crud.derive_findings("crawl", result)
    assert len(out) == 1
    f = out[0]
    assert f["detection_tier"] == "signal"   # regex match — unverified
    assert f["kind"] == "vuln"
    assert f["severity"] == "high"           # aws family → high
    assert f["evidence"]["type"] == "aws_access_key"
    assert f["evidence"]["preview"]


def test_injection_findings_are_validated():
    result = {"findings": [
        {"severity": "high", "name": "SQL Injection", "location": "https://x?id=1", "cwe": "CWE-89"},
    ]}
    out = crud.derive_findings("injection", result)
    assert out and out[0]["detection_tier"] == "validated"
    assert out[0]["kind"] == "vuln"
    assert out[0]["cwe"] == ["CWE-89"]       # scalar cwe coerced to a list


# --------------------------------------------------------------------------- #
# Risk scorer — kind + confidence awareness (and legacy preservation)
# --------------------------------------------------------------------------- #
def test_non_vuln_kinds_do_not_inflate_risk():
    findings = [
        {"severity": "info", "kind": "recon"},
        {"severity": "high", "kind": "hardening"},
        {"severity": "medium", "kind": "info"},
    ]
    out = risk.workspace_risk(findings)
    assert out["score"] == 0                  # recon/hardening/info never score
    assert out["total"] == 3                  # but they are still counted


def test_confidence_weights_signal_below_validated():
    signal = risk.workspace_risk([{"severity": "high", "kind": "vuln", "confidence": 50}])["score"]
    validated = risk.workspace_risk([{"severity": "high", "kind": "vuln", "confidence": 100}])["score"]
    assert validated == 18       # full high weight
    assert signal == 9           # 18 * 0.5 confidence
    assert 0 < signal < validated


def test_legacy_findings_without_kind_keep_full_weight():
    # A finding with no kind/confidence scores exactly as before P0.
    assert risk.workspace_risk([{"severity": "critical"}])["score"] == 40


# --------------------------------------------------------------------------- #
# FindingOut — new fields + tolerance of legacy NULLs
# --------------------------------------------------------------------------- #
def test_findingout_exposes_new_fields_and_tolerates_legacy():
    class Legacy:
        id = 1; scan_id = 1; workspace_id = 1; source = "nuclei"; severity = "high"
        name = "n"; location = "l"; description = "d"; cve = []; cwe = []; cvss = None
        status = "open"; technique_id = None; tactic = None
        created_at = datetime.now(timezone.utc)
        # Legacy rows created before P0 surface these as NULL:
        detection_tier = None; kind = None; confidence = None
        evidence = None; seen_count = None

    out = schemas.FindingOut.model_validate(Legacy())
    assert out.detection_tier == "signal"
    assert out.kind == "vuln"
    assert out.confidence == 50
    assert out.evidence == {}
    assert out.seen_count == 1


# --------------------------------------------------------------------------- #
# save_scan — persistence of new fields + safe deduplication
# --------------------------------------------------------------------------- #
def _ws(db):
    _u, _o, ws = crud.create_user_with_org(db, "p0@example.com", "password123")
    db.commit()
    return ws


def _nuclei_record(ws_id, matched="https://x/a"):
    return {
        "tool": "nuclei", "target": "x", "status": "done", "options": {}, "logs": [],
        "result": {"findings": [{
            "template_id": "t1", "name": "Issue A", "severity": "high",
            "matched_at": matched, "tags": ["sqli"], "description": "d",
            "cve": [], "cwe": ["CWE-89"], "cvss": 7.5,
        }]},
        "started_at": None, "finished_at": None, "workspace_id": ws_id,
    }


def test_redact_scan_options_masks_only_secret_values():
    r = crud.redact_scan_options({
        "cookie": "session=abc", "auth_header": "Bearer t", "password": "p",
        "token": "eyJ.a.b", "username": "alice", "login_url": "https://x/login",
        "user_sel": "#u", "scan_type": "quick",
    })
    assert r["cookie"] == "***" and r["auth_header"] == "***"
    assert r["password"] == "***" and r["token"] == "***"
    # non-secret context is preserved (presence + useful, shareable config)
    assert r["username"] == "alice" and r["login_url"] == "https://x/login"
    assert r["user_sel"] == "#u" and r["scan_type"] == "quick"
    # edge cases: non-dict -> {}, empty secret left as-is (nothing to leak)
    assert crud.redact_scan_options(None) == {}
    assert crud.redact_scan_options("x") == {}
    assert crud.redact_scan_options({"cookie": ""}) == {"cookie": ""}


def test_save_scan_never_persists_authenticated_scan_secrets():
    """The Authenticated Crawl's session secrets must never reach Scan.options in
    the DB (and thus never the ScanOut API / reports). Presence is kept, value
    masked."""
    import json
    db = SessionLocal()
    try:
        ws = _ws(db)
        rec = {
            "tool": "auth_crawl", "target": "https://app.example.com", "status": "done",
            "options": {
                "cookie": "session=SECRETVALUE123", "auth_header": "Bearer TOPSECRETjwt",
                "password": "hunter2", "token": "eyJ.SECRET.sig", "username": "alice",
                "login_url": "https://app.example.com/login", "user_sel": "#u",
            },
            "logs": [], "result": {}, "started_at": None, "finished_at": None,
            "workspace_id": ws.id,
        }
        scan = crud.save_scan(db, rec)
        db.commit()
        db.refresh(scan)
        o = scan.options
        assert o["cookie"] == "***" and o["auth_header"] == "***"
        assert o["password"] == "***" and o["token"] == "***"
        assert o["username"] == "alice" and o["login_url"].endswith("/login")
        assert o["user_sel"] == "#u"
        blob = json.dumps({"options": o, "logs": scan.logs})
        for secret in ("SECRETVALUE123", "TOPSECRETjwt", "hunter2", "eyJ.SECRET.sig"):
            assert secret not in blob
    finally:
        db.close()


def test_save_scan_persists_new_fields():
    db = SessionLocal()
    try:
        ws = _ws(db)
        crud.save_scan(db, _nuclei_record(ws.id))
        db.commit()
        fs = crud.list_findings(db, ws.id)
        assert len(fs) == 1
        f = fs[0]
        assert f.detection_tier == "signal"
        assert f.kind == "vuln"
        assert f.confidence == 50
        assert f.dedupe_key
        assert f.seen_count == 1
        assert f.evidence.get("template_id") == "t1"
    finally:
        db.close()


def test_rescan_dedups_instead_of_duplicating():
    db = SessionLocal()
    try:
        ws = _ws(db)
        crud.save_scan(db, _nuclei_record(ws.id))
        db.commit()
        crud.save_scan(db, _nuclei_record(ws.id))  # identical re-scan
        db.commit()
        fs = crud.list_findings(db, ws.id)
        assert len(fs) == 1            # not duplicated
        assert fs[0].seen_count == 2   # re-observed instead
    finally:
        db.close()


def test_save_scan_clamps_overlong_fields_instead_of_losing_scan():
    # STEP 4 resilience: an over-long scanner value must be clamped to the column
    # width, not raise a Postgres DataError at flush that loses the whole scan.
    db = SessionLocal()
    try:
        ws = _ws(db)
        rec = _nuclei_record(ws.id)
        rec["result"]["findings"][0]["name"] = "N" * 900              # > String(500)
        rec["result"]["findings"][0]["matched_at"] = "http://x/" + "a" * 2000  # > String(1000)
        crud.save_scan(db, rec)
        db.commit()
        fs = crud.list_findings(db, ws.id)
        assert len(fs) == 1                 # finding kept, not lost
        assert len(fs[0].name) == 500
        assert len(fs[0].location) == 1000
    finally:
        db.close()


def test_save_scan_survives_attack_mapping_error(monkeypatch):
    # A raising ATT&CK mapper must degrade ONE finding to "unmapped", never abort
    # the whole scan's finding set.
    from app import attack

    def _boom(tool, finding):
        raise RuntimeError("mapper blew up")

    monkeypatch.setattr(attack, "map_finding", _boom)
    db = SessionLocal()
    try:
        ws = _ws(db)
        crud.save_scan(db, _nuclei_record(ws.id))
        db.commit()
        fs = crud.list_findings(db, ws.id)
        assert len(fs) == 1                              # finding still persisted
        assert fs[0].technique_id is None and fs[0].tactic is None  # just unmapped
    finally:
        db.close()


def test_different_findings_are_not_merged():
    db = SessionLocal()
    try:
        ws = _ws(db)
        crud.save_scan(db, _nuclei_record(ws.id, matched="https://x/a"))
        db.commit()
        crud.save_scan(db, _nuclei_record(ws.id, matched="https://x/b"))
        db.commit()
        # Different location → genuinely different finding → NOT merged.
        assert len(crud.list_findings(db, ws.id)) == 2
    finally:
        db.close()


def test_rescan_preserves_analyst_triage_status():
    db = SessionLocal()
    try:
        ws = _ws(db)
        crud.save_scan(db, _nuclei_record(ws.id))
        db.commit()
        f = crud.list_findings(db, ws.id)[0]
        f.status = "false_positive"
        db.add(f)
        db.commit()
        crud.save_scan(db, _nuclei_record(ws.id))  # re-scan the same issue
        db.commit()
        fs = crud.list_findings(db, ws.id)
        assert len(fs) == 1
        assert fs[0].status == "false_positive"    # human decision preserved
        assert fs[0].seen_count == 2
    finally:
        db.close()


def test_axfr_reaches_findings_via_save_scan():
    db = SessionLocal()
    try:
        ws = _ws(db)
        rec = {
            "tool": "dns_zt", "target": "example.com", "status": "done",
            "options": {}, "logs": [],
            "result": {
                "domain": "example.com", "vulnerable": True,
                "vulnerable_nameservers": ["ns1"], "records": ["a IN A 1.1.1.1"],
                "record_count": 1,
            },
            "started_at": None, "finished_at": None, "workspace_id": ws.id,
        }
        crud.save_scan(db, rec)
        db.commit()
        fs = crud.list_findings(db, ws.id)
        assert len(fs) == 1
        assert fs[0].detection_tier == "validated"
        assert fs[0].kind == "vuln"
        assert fs[0].evidence.get("record_count") == 1
    finally:
        db.close()


def test_waf_findings_do_not_inflate_workspace_risk():
    db = SessionLocal()
    try:
        ws = _ws(db)
        rec = {
            "tool": "waf", "target": "https://x", "status": "done",
            "options": {}, "logs": [],
            "result": {"findings": [
                {"severity": "low", "name": "WAF passthrough SQLi", "location": "https://x",
                 "category": "sqli", "payload": "' OR 1=1", "status": 200},
            ]},
            "started_at": None, "finished_at": None, "workspace_id": ws.id,
        }
        crud.save_scan(db, rec)
        db.commit()
        fs = crud.list_findings(db, ws.id)
        assert len(fs) == 1 and fs[0].kind == "hardening"
        # Hardening signal is persisted but must NOT contribute to risk.
        assert risk.workspace_risk(fs)["score"] == 0
    finally:
        db.close()

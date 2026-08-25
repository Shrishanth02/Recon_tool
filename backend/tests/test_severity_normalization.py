"""P0-7 regression tests — severity robustness.

A single malformed scanner/DB severity (``"unknown"``, ``""``, ``None``, a case
variant, or garbage) must never 500 the findings/risk/report/triage surfaces.
These tests cover the one normalization strategy end-to-end:

* the pure normalizer (:mod:`app.severity`);
* the API schema (:class:`app.schemas.FindingOut`) — the primary 500 point;
* the write boundary (:func:`app.crud.save_scan`) incl. raw-value preservation;
* risk scoring, the report, and AI triage compaction;
* HTTP: ``/findings``, ``/risk`` and ``/report`` survive a legacy bad row.
"""

from datetime import datetime, timezone

import pytest

from app import ai, crud, models, risk
from app.database import SessionLocal
from app.schemas import FindingOut
from app.severity import (
    FALLBACK_SEVERITY,
    SEVERITIES,
    coerce_cvss,
    is_known_severity,
    normalize_severity,
)


# --------------------------------------------------------------------------- #
# Unit — the single normalization strategy
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("sev", list(SEVERITIES))
def test_every_supported_severity_is_preserved(sev):
    assert normalize_severity(sev) == sev


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("CRITICAL", "critical"),
        ("High", "high"),
        ("  medium ", "medium"),
        ("LOW", "low"),
        ("Info", "info"),
    ],
)
def test_case_and_whitespace_variants_normalize(raw, expected):
    assert normalize_severity(raw) == expected


@pytest.mark.parametrize(
    "alias", ["informational", "information", "none", "unknown", "undefined", "null"]
)
def test_known_aliases_map_to_info(alias):
    assert normalize_severity(alias) == "info"
    assert normalize_severity(alias.upper()) == "info"


@pytest.mark.parametrize("bad", ["", "   ", None])
def test_empty_and_null_fall_back(bad):
    assert normalize_severity(bad) == FALLBACK_SEVERITY


@pytest.mark.parametrize("garbage", ["banana", "9.5", 5, 0, [], {}, object()])
def test_malformed_values_never_raise(garbage):
    # Must return a valid severity and never raise, whatever the input type.
    assert normalize_severity(garbage) in SEVERITIES


def test_severity_semantics_are_not_weakened():
    # A recognized value is NEVER downgraded — critical stays critical.
    assert normalize_severity("critical") == "critical"
    assert normalize_severity("CRITICAL") == "critical"
    assert normalize_severity("high") == "high"
    # The fallback only ever applies to genuinely unrecognized input.
    assert normalize_severity("kritical") == "info"


def test_is_known_severity():
    assert is_known_severity("critical") and is_known_severity("INFO")
    assert not is_known_severity("unknown")   # alias, not canonical
    assert not is_known_severity("")
    assert not is_known_severity(None)
    assert not is_known_severity(7)


# --------------------------------------------------------------------------- #
# Schema — FindingOut never 500s on a bad stored severity
# --------------------------------------------------------------------------- #
def _finding_row(**over):
    base = dict(
        id=1, scan_id=1, workspace_id=1, source="nuclei", severity="high",
        name="X", location="http://x", description="", status="open",
        created_at=datetime.now(timezone.utc),
    )
    base.update(over)
    return base


@pytest.mark.parametrize(
    "stored,expected",
    [("unknown", "info"), ("", "info"), (None, "info"),
     ("CRITICAL", "critical"), ("weird-value", "info"), ("high", "high")],
)
def test_findingout_coerces_any_stored_severity(stored, expected):
    out = FindingOut.model_validate(_finding_row(severity=stored))
    assert out.severity == expected  # no ValidationError raised


# --------------------------------------------------------------------------- #
# Write path — save_scan normalizes AND preserves the raw scanner value
# --------------------------------------------------------------------------- #
def _nuclei_record(name: str, severity, location: str) -> dict:
    now = datetime.now(timezone.utc)
    return {
        "tool": "nuclei", "target": location, "status": "done", "options": {},
        "logs": [], "started_at": now, "finished_at": now,
        "result": {"findings": [{
            "severity": severity, "name": name, "template_id": f"t-{name}",
            "matched_at": location, "description": "d", "cve": [], "cwe": ["CWE-79"],
            "cvss": 1.0,
        }]},
    }


def _new_ws(email: str) -> int:
    db = SessionLocal()
    try:
        _u, _o, ws = crud.create_user_with_org(db, email, "password123")
        db.commit()
        return ws.id
    finally:
        db.close()


def test_save_scan_normalizes_unknown_and_preserves_raw():
    ws_id = _new_ws("sev-write@example.com")
    db = SessionLocal()
    try:
        crud.save_scan(db, {**_nuclei_record("U", "unknown", "http://a/u"),
                            "workspace_id": ws_id})
        db.commit()
        f = crud.list_findings(db, ws_id)[0]
        assert f.severity == "info"                       # normalized
        assert f.evidence.get("raw_severity") == "unknown"  # original preserved
    finally:
        db.close()


def test_save_scan_keeps_case_variant_without_stashing_raw():
    ws_id = _new_ws("sev-write2@example.com")
    db = SessionLocal()
    try:
        crud.save_scan(db, {**_nuclei_record("H", "High", "http://a/h"),
                            "workspace_id": ws_id})
        db.commit()
        f = crud.list_findings(db, ws_id)[0]
        assert f.severity == "high"                       # canonicalized case
        assert "raw_severity" not in (f.evidence or {})   # a known value, not stashed
    finally:
        db.close()


# --------------------------------------------------------------------------- #
# Risk / triage — continue with mixed valid + invalid findings
# --------------------------------------------------------------------------- #
def test_risk_continues_and_preserves_critical_with_mixed_findings():
    mixed = [
        {"severity": "critical", "kind": "vuln", "confidence": 100},
        {"severity": "unknown", "kind": "vuln", "confidence": 100},
        {"severity": "", "kind": "vuln", "confidence": 100},
        {"severity": "High", "kind": "vuln", "confidence": 100},
    ]
    result = risk.workspace_risk(mixed)              # must not raise
    # The critical still contributes (not silently downgraded); score is non-zero.
    assert result["score"] > 0
    assert result["counts"]["critical"] == 1
    assert result["counts"]["high"] == 1
    # The two malformed ones collapsed to info (0 points), not to critical.
    assert result["counts"]["info"] == 2


def test_triage_compaction_normalizes_severities():
    findings = [{"id": 1, "severity": "unknown", "name": "n", "location": "l"},
                {"id": 2, "severity": "CRITICAL", "name": "m", "location": "k"}]
    compact = ai._compact_findings(findings)
    sevs = {c["severity"] for c in compact}
    assert sevs <= set(SEVERITIES)
    assert compact[0]["severity"] == "info"
    assert compact[1]["severity"] == "critical"


# --------------------------------------------------------------------------- #
# HTTP — one malformed row never 500s the workspace surfaces
# --------------------------------------------------------------------------- #
def _persist_finding(ws_id: int, name: str, severity: str, location: str) -> int:
    db = SessionLocal()
    try:
        crud.save_scan(db, {**_nuclei_record(name, severity, location),
                            "workspace_id": ws_id})
        db.commit()
        return next(f.id for f in crud.list_findings(db, ws_id) if f.name == name)
    finally:
        db.close()


def _corrupt_severity(finding_id: int, bad: str) -> None:
    """Write an out-of-vocabulary severity straight to the column, simulating a
    legacy row created before P0-7 normalized the write path."""
    db = SessionLocal()
    try:
        row = db.get(models.Finding, finding_id)
        row.severity = bad
        db.add(row)
        db.commit()
    finally:
        db.close()


def test_findings_api_does_not_500_on_a_malformed_row(client, auth):
    ws_id = auth["ws_id"]
    good = _persist_finding(ws_id, "GoodCrit", "critical", "http://a/crit")
    bad = _persist_finding(ws_id, "BadRow", "high", "http://a/bad")
    _corrupt_severity(bad, "unknown")  # legacy/corrupt value in the DB

    resp = client.get(f"/workspaces/{ws_id}/findings", headers=auth["headers"])
    assert resp.status_code == 200, resp.text  # was a 500 before the fix
    by_name = {f["name"]: f for f in resp.json()}
    assert by_name["GoodCrit"]["severity"] == "critical"  # valid finding intact
    assert by_name["BadRow"]["severity"] == "info"        # malformed -> safe info
    assert good and bad


def test_risk_and_report_endpoints_survive_a_malformed_row(client, auth):
    ws_id = auth["ws_id"]
    _persist_finding(ws_id, "RealHigh", "high", "http://a/real")
    bad = _persist_finding(ws_id, "Broken", "medium", "http://a/broken")
    _corrupt_severity(bad, "totally-bogus")

    r_risk = client.get(f"/workspaces/{ws_id}/risk", headers=auth["headers"])
    assert r_risk.status_code == 200, r_risk.text

    r_report = client.get(f"/workspaces/{ws_id}/report", headers=auth["headers"])
    assert r_report.status_code == 200, r_report.text
    # The report still renders both findings (the bad one under a real bucket).
    assert "RealHigh" in r_report.text
    assert "Broken" in r_report.text


# =========================================================================== #
# P1 — CVSS robustness. A template/data-controlled cvss must never crash the
# dedup merge (max(str, float) TypeError) or 500 the findings/report surface.
# Mirrors the severity strategy: pure coercer + FindingOut + write boundary.
# =========================================================================== #
@pytest.mark.parametrize(
    "raw,expected",
    [
        (7.5, 7.5), (7, 7.0), ("7.5", 7.5), ("  9 ", 9.0), (0, 0.0), (10, 10.0),
        (None, None), ("high", None), ("", None), (True, None), (False, None),
        ([1], None), ({"a": 1}, None), (11.0, None), (-1.0, None),
        (float("nan"), None), (float("inf"), None),
    ],
)
def test_coerce_cvss_unit(raw, expected):
    assert coerce_cvss(raw) == expected


@pytest.mark.parametrize(
    "stored,expected",
    [(7.5, 7.5), ("7.5", 7.5), (None, None), ("high", None), (True, None),
     (11.0, None), (float("nan"), None)],
)
def test_findingout_coerces_any_stored_cvss(stored, expected):
    """FindingOut must never 500 on a non-numeric/out-of-range stored cvss."""
    out = FindingOut.model_validate(_finding_row(cvss=stored))
    assert out.cvss == expected  # no ValidationError raised


def _nuclei_record_cvss(name: str, cvss, location: str) -> dict:
    rec = _nuclei_record(name, "high", location)
    rec["result"]["findings"][0]["cvss"] = cvss
    return rec


def test_save_scan_coerces_malformed_cvss_and_keeps_scan():
    """A non-numeric cvss must not raise; the scan + finding survive with cvss=None."""
    ws_id = _new_ws("cvss-write@example.com")
    db = SessionLocal()
    try:
        crud.save_scan(db, {**_nuclei_record_cvss("BadCvss", "not-a-number", "http://a/x"),
                            "workspace_id": ws_id})
        db.commit()
        f = next(f for f in crud.list_findings(db, ws_id) if f.name == "BadCvss")
        assert f.cvss is None
    finally:
        db.close()


def test_save_scan_preserves_a_valid_cvss():
    """Existing behaviour intact: a valid numeric cvss round-trips unchanged."""
    ws_id = _new_ws("cvss-write2@example.com")
    db = SessionLocal()
    try:
        crud.save_scan(db, {**_nuclei_record_cvss("GoodCvss", 7.5, "http://a/y"),
                            "workspace_id": ws_id})
        db.commit()
        f = next(f for f in crud.list_findings(db, ws_id) if f.name == "GoodCvss")
        assert f.cvss == 7.5
    finally:
        db.close()


def test_dedup_merge_with_malformed_cvss_does_not_crash():
    """The re-scan merge does max(existing.cvss, f['cvss']). A malformed cvss on
    either observation must be coerced so the merge never raises TypeError and
    the surviving row keeps the valid score."""
    ws_id = _new_ws("cvss-merge@example.com")
    db = SessionLocal()
    try:
        # First observation: a valid 7.5.
        crud.save_scan(db, {**_nuclei_record_cvss("Merge", 7.5, "http://a/m"),
                            "workspace_id": ws_id})
        db.commit()
        # Re-scan the SAME finding with a malformed cvss — must not crash the merge.
        crud.save_scan(db, {**_nuclei_record_cvss("Merge", "garbage", "http://a/m"),
                            "workspace_id": ws_id})
        db.commit()
        rows = [f for f in crud.list_findings(db, ws_id) if f.name == "Merge"]
        assert len(rows) == 1                 # merged, not duplicated
        assert rows[0].seen_count == 2
        assert rows[0].cvss == 7.5            # kept the valid score
    finally:
        db.close()


def test_dedup_merge_takes_max_of_valid_cvss():
    """Two valid observations still merge to the higher score (behaviour intact)."""
    ws_id = _new_ws("cvss-merge2@example.com")
    db = SessionLocal()
    try:
        crud.save_scan(db, {**_nuclei_record_cvss("MergeMax", 5.0, "http://a/n"),
                            "workspace_id": ws_id})
        db.commit()
        crud.save_scan(db, {**_nuclei_record_cvss("MergeMax", 8.8, "http://a/n"),
                            "workspace_id": ws_id})
        db.commit()
        rows = [f for f in crud.list_findings(db, ws_id) if f.name == "MergeMax"]
        assert len(rows) == 1 and rows[0].cvss == 8.8
    finally:
        db.close()


def _corrupt_cvss(finding_id: int, bad) -> None:
    """Write a numeric-but-invalid cvss straight to the column, simulating a
    legacy row persisted before the write boundary coerced cvss. (The Float
    column's driver processor already rejects a NON-numeric value on write, so a
    bad *stored* cvss is necessarily a number the column accepts but a strict
    consumer must not — NaN/inf/out-of-range.)"""
    db = SessionLocal()
    try:
        row = db.get(models.Finding, finding_id)
        row.cvss = bad
        db.add(row)
        db.commit()
    finally:
        db.close()


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), 11.0])
def test_findings_api_does_not_500_on_a_malformed_cvss_row(client, auth, bad):
    """End-to-end: a legacy row with a NaN/inf/out-of-range cvss must not 500
    /findings (NaN in particular would otherwise emit invalid JSON)."""
    ws_id = auth["ws_id"]
    good = _persist_finding(ws_id, "GoodCvssRow", "high", "http://a/gc")
    bad_id = _persist_finding(ws_id, "BadCvssRow", "high", "http://a/bc")
    _corrupt_cvss(bad_id, bad)

    r = client.get(f"/workspaces/{ws_id}/findings", headers=auth["headers"])
    assert r.status_code == 200, r.text
    by_name = {f["name"]: f for f in r.json()}
    assert by_name["BadCvssRow"]["cvss"] is None    # coerced, not a 500
    assert by_name["GoodCvssRow"]["name"] == "GoodCvssRow"
    assert good != bad_id

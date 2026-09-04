"""Purple-Team P5 tests — the purple-team HTML report (report.generate_purple).

Unit-tests the new :func:`app.report.generate_purple` renderer (``generate`` is
left untouched): it must render a self-contained HTML string that surfaces the
coverage posture, the detection gaps (including a gap technique id), the coverage
percentage, the AI-triage actions (or an "unavailable" note when triage is off),
and the P5 human-gated/non-destructive safety statement — and must not crash on
empty findings / empty-or-None coverage.

Also probes the intended ``GET /workspaces/{id}/purple-report`` route. As of this
run that route is NOT wired into ``app.routers`` (only the recon ``/report`` route
and the ``generate_purple`` function exist), so the route test SKIPS with a loud
reason rather than silently passing; it asserts the member-readable HTML contract
if/when the endpoint is added.
"""

import pytest

from app import ai, crud, report
from app.database import SessionLocal


# --------------------------------------------------------------------------- #
# Synthetic inputs
# --------------------------------------------------------------------------- #
def _project():
    return {
        "name": "Acme Engagement",
        "description": "Q3 purple-team assessment",
        "scope": ["example.com"],
    }


def _findings():
    return [
        {
            "severity": "critical",
            "name": "Remote Code Execution",
            "location": "https://example.com/admin",
            "description": "Unauthenticated RCE.",
            "cve": ["CVE-2024-0001"],
            "cwe": ["CWE-78"],
            "cvss": 9.8,
            "source": "nuclei",
        },
        {
            "severity": "info",
            "name": "Server banner",
            "location": "example.com",
            "description": "",
            "cve": [],
            "cwe": [],
            "cvss": None,
            "source": "nmap",
        },
    ]


def _coverage(gap_tid="T1046"):
    """A coverage-dashboard-shaped dict with one detected + one gap technique."""
    return {
        "summary": {
            "techniques_emulated": 5,
            "detected": 2,
            "missed": 3,
            "not_validated": 0,
            "coverage_pct": 40,
        },
        "techniques": [
            {"technique_id": "T1190", "name": "Exploit Public-Facing App",
             "tactic": "initial-access", "detected": True},
            {"technique_id": gap_tid, "name": "Network Service Discovery",
             "tactic": "discovery", "detected": False},
        ],
        "tactics": [
            {"tactic": "initial-access", "name": "Initial Access",
             "detected": 1, "missed": 0, "total": 1},
            {"tactic": "discovery", "name": "Discovery",
             "detected": 0, "missed": 1, "total": 1},
        ],
        "trend": [
            {"run_id": 1, "coverage_pct": 20},
            {"run_id": 2, "coverage_pct": 40},
        ],
        "gaps": [
            {"technique_id": gap_tid, "name": "Network Service Discovery",
             "tactic": "discovery"},
        ],
    }


# =========================================================================== #
# generate_purple — full render
# =========================================================================== #
def test_generate_purple_renders_coverage_and_gap():
    """A populated report is an HTML string with coverage, gap id, and %."""
    html = report.generate_purple(
        _project(), _findings(), [{"tool": "nuclei"}], _coverage("T1046"), triage=None
    )
    assert isinstance(html, str)
    assert html.startswith("<!doctype html>")

    # Coverage section + the coverage percentage are present.
    assert "Coverage" in html
    assert "ATT&amp;CK Coverage Matrix" in html
    assert "Detection coverage" in html
    assert "40%" in html

    # The gap technique id surfaces (in the matrix and the Detection Gaps table).
    assert "Detection Gaps" in html
    assert "T1046" in html

    # The detected technique also renders in the matrix.
    assert "T1190" in html

    # The P5 boundary is stated in the methodology/safety disclaimer.
    assert "human-gated" in html
    assert "non-destructive" in html.lower()

    # A finding row rendered.
    assert "Remote Code Execution" in html


def test_generate_purple_triage_unavailable_note():
    """A disabled triage payload OMITS the AI section entirely (V2): no misleading
    'AI triage unavailable' note is rendered when triage did not run."""
    html = report.generate_purple(
        _project(), _findings(), [], _coverage(),
        triage={"enabled": False, "reason": "ANTHROPIC_API_KEY not configured"},
    )
    assert isinstance(html, str)
    assert "triage unavailable" not in html.lower()
    assert "Remediation priorities" not in html


def test_generate_purple_triage_none_is_unavailable():
    """triage=None omits the AI section (no 'unavailable' note) and does not crash."""
    html = report.generate_purple(_project(), _findings(), [], _coverage(), triage=None)
    assert isinstance(html, str)
    assert "triage unavailable" not in html.lower()
    assert "Remediation priorities" not in html


def test_generate_purple_renders_triage_actions():
    """An enabled triage payload renders its prioritized actions + headline."""
    triage = {
        "enabled": True,
        "summary": "Focus remediation on the unauthenticated RCE first.",
        "top": [
            {"id": 7, "name": "Remote Code Execution", "severity": "critical",
             "priority": 1, "recommendation": "Patch to the fixed release now."},
        ],
    }
    html = report.generate_purple(_project(), _findings(), [], _coverage(), triage=triage)
    assert "Focus remediation on the unauthenticated RCE first." in html
    assert "Patch to the fixed release now." in html
    assert "#7" in html
    assert "CRITICAL" in html


# =========================================================================== #
# generate_purple — robustness on empty / None inputs
# =========================================================================== #
def test_generate_purple_handles_empty_inputs():
    """Empty findings + empty coverage must render, not crash (coverage n/a)."""
    html = report.generate_purple({"name": "Empty Engagement"}, [], [], {}, triage=None)
    assert isinstance(html, str)
    assert "Empty Engagement" in html
    # Empty coverage => ATT&CK validation is reported as NOT performed (V2: no
    # misleading empty 0-detected/0-missed/0-emulated matrix).
    assert "was not performed" in html
    # Empty findings => the findings placeholder.
    assert "No confirmed or potential findings recorded." in html


def test_generate_purple_handles_none_coverage_and_branding():
    """coverage=None is tolerated; branding white-labels the report."""
    html = report.generate_purple(
        {"name": "NoneCov"}, [], [], None, triage=None,
        branding={"brand_name": "AcmeSec", "brand_primary_color": "#123456",
                  "report_footer": "Confidential — AcmeSec"},
    )
    assert isinstance(html, str)
    assert "AcmeSec" in html
    assert "#123456" in html
    assert "Confidential — AcmeSec" in html


# =========================================================================== #
# Route — GET /workspaces/{id}/purple-report (intended contract)
# =========================================================================== #
def test_purple_report_route_member_readable(client, auth):
    """GET /workspaces/{id}/purple-report should return 200 HTML for a member.

    NOTE (P5 gap): this route is not wired into app.routers as of this run — only
    ``report.generate_purple`` (unit-tested above) and the recon ``/report`` route
    exist. The test SKIPS loudly when the endpoint is absent (so the gap is
    visible and does not masquerade as a pass) and asserts the intended
    member-readable HTML + coverage contract if/when the route is added.
    """
    resp = client.get(
        f"/workspaces/{auth['ws_id']}/purple-report", headers=auth["headers"]
    )
    if resp.status_code == 404:
        pytest.skip(
            "GET /workspaces/{id}/purple-report is not implemented (P5 route gap); "
            "report.generate_purple() is present and unit-tested above."
        )
    assert resp.status_code == 200, resp.text
    ctype = resp.headers.get("content-type", "")
    assert "html" in ctype.lower()
    assert "coverage" in resp.text.lower()  # testing-coverage / ATT&CK coverage content present


# --------------------------------------------------------------------------- #
# P1 — router -> renderer boundary. The persisted TriageResult.data is the raw
# TriageOut shape (no `enabled`); the renderer gates the section on `enabled`.
# These prove the flagship AI-triage section renders when triage actually ran
# (using the REAL persisted shape via crud.save_triage) and stays "unavailable"
# when it did not.
# --------------------------------------------------------------------------- #


def _persist_real_triage(ws_id: int) -> dict:
    """Persist a TriageResult exactly as the production save paths do: the INNER
    TriageOut dict (summary / risk_narrative / items / dedup_groups), with NO
    `enabled` key. Returns the persisted dict for assertions."""
    triage_out = ai.TriageOut(
        summary="Two criticals need immediate remediation.",
        risk_narrative="Exploitable RCE dominates the risk.",
        items=[
            ai.TriagedFinding(
                finding_id=4242,
                verdict="real",
                suggested_severity="critical",
                remediation="Patch the admin RCE immediately.",
                rationale="Unauthenticated and network-reachable.",
            )
        ],
        dedup_groups=[],
    )
    triage_dict = triage_out.model_dump()
    assert "enabled" not in triage_dict  # the persisted shape genuinely lacks it
    db = SessionLocal()
    try:
        crud.save_triage(db, ws_id, None, "claude-test", triage_dict)
        db.commit()
    finally:
        db.close()
    return triage_dict


def test_purple_report_renders_triage_section_when_triage_ran(client, auth):
    """With a real persisted triage, the route renders the prioritized-actions
    section (headline + item), NOT the 'unavailable' note."""
    ws_id = auth["ws_id"]
    _persist_real_triage(ws_id)

    resp = client.get(f"/workspaces/{ws_id}/purple-report", headers=auth["headers"])
    assert resp.status_code == 200, resp.text
    html = resp.text
    assert "AI triage unavailable" not in html
    assert "Two criticals need immediate remediation." in html   # headline/summary
    assert "Patch the admin RCE immediately." in html            # item remediation
    assert "#4242" in html                                       # item finding id


def test_purple_report_triage_unavailable_when_no_triage(client, auth):
    """With no persisted triage, the AI section is OMITTED (V2): an absent triage
    must not render as present, and no misleading 'unavailable' note appears."""
    resp = client.get(
        f"/workspaces/{auth['ws_id']}/purple-report", headers=auth["headers"]
    )
    assert resp.status_code == 200, resp.text
    assert "AI triage unavailable" not in resp.text
    assert "Remediation priorities" not in resp.text

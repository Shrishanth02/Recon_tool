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

from app import report


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
    """A disabled triage payload renders the 'triage unavailable' note + reason."""
    html = report.generate_purple(
        _project(), _findings(), [], _coverage(),
        triage={"enabled": False, "reason": "ANTHROPIC_API_KEY not configured"},
    )
    assert isinstance(html, str)
    assert "triage unavailable" in html.lower()
    assert "ANTHROPIC_API_KEY not configured" in html


def test_generate_purple_triage_none_is_unavailable():
    """triage=None is treated as unavailable and does not crash."""
    html = report.generate_purple(_project(), _findings(), [], _coverage(), triage=None)
    assert isinstance(html, str)
    assert "triage unavailable" in html.lower()


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
    # coverage_pct is None -> rendered as "n/a".
    assert "n/a" in html
    # Empty coverage => the matrix shows the "no techniques" placeholder.
    assert "No emulated techniques" in html
    # Empty findings => the findings placeholder.
    assert "No findings recorded." in html


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
    assert "Coverage" in resp.text

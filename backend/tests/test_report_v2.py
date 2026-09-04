"""Reporting V2 regression tests — classification, correlation, coverage, honesty.

Covers the exact defects seen in a real generated report: "Possible IDOR" and a
blind-SSRF candidate must NOT count as confirmed vulnerabilities; hardening and
recon must not flood the vulnerability list; NOT TESTED must be distinct from "no
finding"; ATT&CK/AI sections must be conditional; scope must be honest; secrets
must be redacted; rendering must be XSS-safe.
"""
from app import report, report_model as rm

TOOLS = {"nmap": True, "subfinder": True, "httpx": True, "nuclei": True, "ffuf": True,
         "sqlmap": False, "dalfox": True, "whois": False, "arjun": False}
SCANS = [{"tool": t} for t in ("injection", "idor", "ssrf", "webaudit", "nmap", "nuclei",
                               "dirbuster", "csrf", "jwt", "role_matrix", "open_redirect",
                               "takeover", "origin", "waf", "subdomains", "dns_zt")]


def _idor_signal(n=1):
    return {"name": f"Possible IDOR: object-identifier endpoint ({n})", "severity": "medium",
            "kind": "vuln", "detection_tier": "signal", "confidence": 45,
            "location": f"https://i.pravatar.cc/{n}?img=10", "cwe": ["CWE-639"],
            "description": "cannot be confirmed with fewer than two authorized identities"}


def _confirmed_env():
    return {"name": "Exposed sensitive file: /.env", "severity": "high", "kind": "vuln",
            "detection_tier": "validated", "confidence": 90, "location": "https://x.com/.env",
            "cwe": ["CWE-538"], "evidence": {"http_status": 200}}


# ------------------------- classification (model) --------------------------- #
def test_signal_vuln_is_potential_not_confirmed():
    assert rm.classify(_idor_signal()) == rm.STATUS_POTENTIAL


def test_validated_vuln_is_confirmed():
    assert rm.classify(_confirmed_env()) == rm.STATUS_CONFIRMED


def test_high_severity_signal_is_still_only_potential():
    """Severity must NOT imply confirmation — a HIGH signal is Potential."""
    f = {**_idor_signal(), "severity": "high", "confidence": 45}
    assert rm.classify(f) == rm.STATUS_POTENTIAL


def test_hardening_and_recon_are_not_vulns():
    assert rm.classify({"kind": "hardening", "detection_tier": "validated", "severity": "low"}) == rm.STATUS_HARDENING
    assert rm.classify({"kind": "recon", "severity": "info"}) == rm.STATUS_INFORMATIONAL
    assert rm.classify({"kind": "info", "severity": "info"}) == rm.STATUS_INFORMATIONAL


def test_low_confidence_signal_is_inconclusive():
    assert rm.classify({**_idor_signal(), "confidence": 20}) == rm.STATUS_INCONCLUSIVE


# ------------------------- counts / aggregation ----------------------------- #
def test_counts_separate_confirmed_potential_hardening_info():
    findings = [_confirmed_env()] + [_idor_signal(n) for n in range(5)]
    for host in ("a.com", "b.com"):
        findings.append({"name": "Missing security header: CSP", "severity": "low",
                         "kind": "hardening", "detection_tier": "validated", "location": f"https://{host}",
                         "cwe": ["CWE-693"]})
    findings += [{"name": f"Discovered path /p{i}", "severity": "info", "kind": "info",
                  "detection_tier": "signal", "location": f"https://a.com/p{i}"} for i in range(30)]
    m = rm.build_model({"name": "t", "scope": ["x.com"]}, findings, SCANS, tools=TOOLS)
    c = m["counts"]
    assert c["confirmed_total"] == 1
    assert c["potential_total"] == 5      # the IDOR signals are potential, not vulns
    assert c["hardening_total"] == 2      # one per host, aggregated
    assert c["informational_total"] == 30
    assert m["overall_risk"] == "High"    # from the confirmed .env only


def test_overall_risk_is_confirmed_only():
    """A pile of HIGH potential signals must NOT raise the overall (confirmed) risk."""
    findings = [{**_idor_signal(n), "severity": "high"} for n in range(8)]
    m = rm.build_model({"name": "t"}, findings, SCANS, tools=TOOLS)
    assert m["counts"]["confirmed_total"] == 0
    assert m["overall_risk"] == "No confirmed findings"


def test_dedupe_collapses_identical_findings():
    m = rm.build_model({"name": "t"}, [_confirmed_env(), _confirmed_env()], SCANS, tools=TOOLS)
    assert m["counts"]["confirmed_total"] == 1


# ------------------------- coverage: tested vs not-tested ------------------- #
def test_sqli_not_tested_when_sqlmap_absent():
    m = rm.build_model({"name": "t"}, [], SCANS, tools=TOOLS)
    sqli = [r for r in m["coverage_matrix"] if r["area"] == "SQL Injection"][0]
    assert sqli["status"] == "NOT TESTED"
    assert "sqlmap" in sqli["limitation"]


def test_area_tested_no_finding_is_distinct_from_not_tested():
    m = rm.build_model({"name": "t"}, [], SCANS, tools={**TOOLS, "sqlmap": True})
    sqli = [r for r in m["coverage_matrix"] if r["area"] == "SQL Injection"][0]
    assert sqli["status"] == "TESTED" and sqli["result"] == "No finding"


def test_scanner_not_run_is_not_tested():
    m = rm.build_model({"name": "t"}, [], [{"tool": "webaudit"}], tools=TOOLS)
    nmap = [r for r in m["coverage_matrix"] if r["area"] == "Ports / Services"][0]
    assert nmap["status"] == "NOT TESTED"


def test_area_marked_not_tested_when_its_scan_errored():
    """A scan that RAN but ERRORED must not render as 'TESTED / No finding' — that
    would be a false-clean. It is NOT TESTED (scan failed)."""
    m = rm.build_model({"name": "t"}, [], [{"tool": "ssrf", "status": "failed"}], tools=TOOLS)
    ssrf = [r for r in m["coverage_matrix"] if r["area"] == "SSRF"][0]
    assert ssrf["status"] == "NOT TESTED"
    assert "fail" in (ssrf["result"] + ssrf["limitation"]).lower()


def test_errored_scan_does_not_hide_a_successful_one():
    """If the same scanner has one errored and one successful run, the area is
    still TESTED (a good run exists)."""
    m = rm.build_model(
        {"name": "t"}, [],
        [{"tool": "ssrf", "status": "failed"}, {"tool": "ssrf", "status": "done"}],
        tools=TOOLS,
    )
    ssrf = [r for r in m["coverage_matrix"] if r["area"] == "SSRF"][0]
    assert ssrf["status"] == "TESTED"


def test_missing_scan_status_is_treated_as_successful():
    """Back-compat: a scan record with no status field is assumed successful (the
    DB default is 'done'), so existing callers keep their TESTED result."""
    m = rm.build_model({"name": "t"}, [], [{"tool": "ssrf"}], tools=TOOLS)
    ssrf = [r for r in m["coverage_matrix"] if r["area"] == "SSRF"][0]
    assert ssrf["status"] == "TESTED"


# ------------------------- conditional ATT&CK / AI -------------------------- #
def test_attck_absent_when_no_emulation():
    html = report.generate_purple({"name": "t", "scope": ["x.com"]}, [_confirmed_env()], SCANS, {}, tools=TOOLS)
    assert "was not performed" in html
    assert "0 detected / 0 missed" not in html


def test_attck_present_when_emulated():
    cov = {"summary": {"coverage_pct": 40},
           "techniques": [{"technique_id": "T1046", "name": "Svc Scan", "tactic": "discovery", "detected": True}],
           "tactics": [{"tactic": "discovery", "name": "Discovery", "detected": 1, "missed": 0, "total": 1}],
           "gaps": []}
    html = report.generate_purple({"name": "t"}, [], SCANS, cov, tools=TOOLS)
    assert "ATT&amp;CK Coverage Matrix" in html and "T1046" in html


def test_ai_section_omitted_when_disabled():
    html = report.generate_purple({"name": "t"}, [_confirmed_env()], SCANS, {},
                                  triage={"enabled": False, "reason": "no key"}, tools=TOOLS)
    assert "Remediation priorities" not in html
    assert "triage unavailable" not in html.lower()  # coverage may say "Tool unavailable"; that's fine


def test_ai_section_present_when_items_even_without_enabled_flag():
    triage = {"summary": "Fix RCE first.", "items": [{"finding_id": 42, "remediation": "Patch now.",
              "suggested_severity": "critical"}]}
    html = report.generate_purple({"name": "t"}, [], SCANS, {}, triage=triage, tools=TOOLS)
    assert "Remediation priorities" in html and "#42" in html and "Patch now." in html


# ------------------------- scope honesty ----------------------------------- #
def test_scope_absent_is_honest():
    html = report.generate({"name": "t"}, [], SCANS, tools=TOOLS)
    assert "Scope not explicitly defined" in html
    assert "conducted only against authorized" not in html.lower()


def test_scope_present_is_shown():
    html = report.generate({"name": "t", "scope": ["x.com"]}, [], SCANS, tools=TOOLS)
    assert "x.com" in html


# ------------------------- CVSS / status rendering ------------------------- #
def test_cvss_not_scored_when_absent():
    html = report.generate({"name": "t"}, [_idor_signal()], SCANS, tools=TOOLS)
    assert "CVSS: Not Scored" in html
    assert "Potential" in html  # status badge


def test_cvss_shown_when_present():
    f = {**_confirmed_env(), "cvss": 8.6}
    html = report.generate({"name": "t"}, [f], SCANS, tools=TOOLS)
    assert "CVSS 8.6" in html


# ------------------------- security: redaction + escaping ------------------ #
def test_evidence_secret_is_redacted():
    f = {**_confirmed_env(), "evidence": {"authorization": "Bearer SUPERSECRETTOKEN123", "req": "password=hunter2"}}
    html = report.generate({"name": "t"}, [f], SCANS, tools=TOOLS)
    assert "SUPERSECRETTOKEN123" not in html
    assert "hunter2" not in html
    assert "[REDACTED]" in html


def test_rendering_is_xss_safe():
    evil = {"name": "<script>alert(1)</script>", "severity": "high", "kind": "vuln",
            "detection_tier": "validated", "location": "https://x.com/<img src=x onerror=alert(1)>",
            "description": "</style><svg onload=alert(1)>"}
    html = report.generate({"name": "<b>proj</b>"}, [evil], SCANS, tools=TOOLS)
    # The payloads must be neutralized as inert escaped text (no executable tags).
    assert "<script>alert(1)</script>" not in html
    assert "<img src=x onerror" not in html   # raw tag must be escaped (&lt;img …)
    assert "<svg onload" not in html
    assert "&lt;script&gt;" in html            # confirm it was escaped, not dropped


# ------------------------- QC contradiction -------------------------------- #
def test_qc_flags_confirmed_with_hedged_description():
    f = {"name": "X", "severity": "high", "kind": "vuln", "detection_tier": "validated",
         "location": "https://x.com", "description": "This cannot be confirmed without a second identity."}
    m = rm.build_model({"name": "t"}, [f], SCANS, tools=TOOLS)
    assert m["qc_issues"], "a Confirmed finding whose description hedges must be flagged"


# ============ Supplied-report regression fixture (Phase 24) ================= #
def _supplied_report_fixture():
    """Mirror the real redopsx-purple-report.html: pravatar IDOR signals + SSRF
    signal + repeated hardening headers + info flood."""
    F = []
    for n in (200, 500, 42, 101, 2016, 2012, 2008, 1999, 2000):
        F.append(_idor_signal(n))
    F.append({"name": "Possible Server-Side Request Forgery in 'img'", "severity": "medium",
              "kind": "vuln", "detection_tier": "signal", "confidence": 40,
              "location": "https://i.pravatar.cc/200?img=10", "cwe": ["CWE-918"]})
    for host in ("skillsuprise.com", "www.skillsuprise.com", "management.skillsuprise.com"):
        for h in ("Missing security header: X-Frame-Options",
                  "Missing security header: Strict-Transport-Security",
                  "Missing security header: Content-Security-Policy",
                  "Clickjacking: no frame protection"):
            F.append({"name": h, "severity": "low", "kind": "hardening", "detection_tier": "validated",
                      "location": f"https://{host}", "cwe": ["CWE-693"]})
    for p in range(60):
        F.append({"name": f"Discovered path /{p}", "severity": "info", "kind": "info",
                  "detection_tier": "signal", "location": f"https://management.skillsuprise.com/{p}"})
    return F


def test_supplied_report_regression_counts():
    """BEFORE (old report): 36 'Vulnerabilities' (16 medium incl. IDOR/SSRF signals + 20 low
    hardening), ~1056 info flooding the list, SQLi shown as tested.
    AFTER (V2): 0 Confirmed, 10 Potential, hardening + info separated, SQLi NOT TESTED."""
    m = rm.build_model({"name": "skillsuprise", "scope": ["skillsuprise.com"]},
                       _supplied_report_fixture(), SCANS, tools=TOOLS)
    c = m["counts"]
    assert c["confirmed_total"] == 0                     # nothing was validated
    assert c["potential_total"] == 10                    # 9 IDOR + 1 SSRF, now Potential
    assert c["hardening_total"] == 12                    # 3 hosts x 4, aggregated (not "vulnerabilities")
    assert c["informational_total"] == 60                # aggregated, out of the vuln list
    assert m["overall_risk"] == "No confirmed findings"  # not "Medium"
    sqli = [r for r in m["coverage_matrix"] if r["area"] == "SQL Injection"][0]
    assert sqli["status"] == "NOT TESTED"


def test_supplied_report_renders_without_overclaiming():
    html = report.generate_purple({"name": "skillsuprise", "scope": ["skillsuprise.com"]},
                                  _supplied_report_fixture(), SCANS, {}, tools=TOOLS)
    assert html.startswith("<!doctype html>")
    assert "Potential findings (unconfirmed)" in html
    assert "Confirmed findings" not in html   # there are none
    assert "was not performed" in html        # no purple emulation

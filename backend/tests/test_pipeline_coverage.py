"""Tier-2 coverage-honesty tests for :func:`app.pipeline.run_pipeline`.

A 0-finding scan must not read as "clean" when a capability could not run
because its optional tool is missing. The pipeline's final summary carries a
``coverage`` block built from ``preflight.check_tools()`` (PATH availability) and
the injection stage's own ``tools`` marker (what actually ran this scan). These
tests prove:

* missing SQLi/XSS tools -> explicitly reported as "not tested / tool unavailable";
* installed tools -> no false "not tested" status;
* the injection marker is authoritative when injection actually ran;
* a genuine 0-finding scan still reports 0 findings;
* the pre-existing summary keys are unchanged (no regression).

Every scanner is stubbed offline; netguard is neutralized.
"""

import asyncio

from app import pipeline
from app.pipeline import PipelineConfig

SEED = "https://app.example.com"
_LEGACY_SUMMARY_KEYS = {
    "target", "subdomains_found", "live_hosts", "total_findings",
    "severity_counts", "risk_score", "risk_label", "finished_at",
}


def _run(target, **kwargs):
    async def _go():
        return [e async for e in pipeline.run_pipeline(target, **kwargs)]

    return asyncio.run(_go())


def _summary(events):
    return next(e["summary"] for e in events if e.get("type") == "pipeline_done")


def _patch(monkeypatch, *, tools_present, injection_marker, parameterized):
    """Stub the pipeline offline.

    tools_present: what preflight.check_tools() reports for the optional tools.
    injection_marker: the ``tools`` dict the injection stage emits, or None to
        make injection not run (no parameterized URL discovered).
    parameterized: whether the crawl yields a parameterized URL (so injection runs).
    """
    optional = {"sqlmap": tools_present, "dalfox": tools_present,
                "whois": True, "katana": tools_present, "gau": tools_present,
                "arjun": tools_present}
    monkeypatch.setattr(pipeline.preflight, "check_tools", lambda: {
        "required": {}, "optional": optional, "missing_required": [],
        "missing_optional": sorted(t for t, ok in optional.items() if not ok),
        "ok": True,
    })

    def whois_stream(target, **_k):
        yield {"type": "result", "data": {"domain": target}}

    def subdomain_stream(target, **_k):
        yield {"type": "result", "data": {"subdomains": []}}

    def httpx_stream(target, **_k):
        yield {"type": "result", "data": {"rows": [{"url": SEED, "host": "app.example.com"}]}}

    def nuclei_stream(target, **_k):
        yield {"type": "result", "data": {"findings": []}}

    def crawl_stream(target, **_k):
        purls = [{"url": f"{target}/item?id=1"}] if parameterized else []
        yield {"type": "result", "data": {"target": target, "urls": [],
                                          "parameterized_urls": purls, "findings": []}}

    def injection_stream(target, *_a, **_k):
        data = {"target": target, "findings": []}
        if injection_marker is not None:
            data["tools"] = dict(injection_marker)
        yield {"type": "result", "data": data}

    def deep_stub(target, *_a, **_k):
        yield {"type": "result", "data": {"target": target, "findings": []}}

    monkeypatch.setattr(pipeline.whois_lookup, "stream", whois_stream)
    monkeypatch.setattr(pipeline.subdomain, "stream", subdomain_stream)
    monkeypatch.setattr(pipeline.httpx_probe, "stream", httpx_stream)
    monkeypatch.setattr(pipeline.nmap_scan, "stream", deep_stub)
    monkeypatch.setattr(pipeline.techdetect, "stream", deep_stub)
    monkeypatch.setattr(pipeline.nuclei_scan, "stream", nuclei_stream)
    monkeypatch.setattr(pipeline.dirbuster, "stream",
                        lambda t, *a, **k: iter([{"type": "result",
                                                  "data": {"target": t, "rows": []}}]))
    monkeypatch.setattr(pipeline, "dns_zt_stream",
                        lambda t, **k: iter([{"type": "result",
                                              "data": {"domain": t, "vulnerable": False}}]))
    monkeypatch.setattr(pipeline.origin_discovery, "stream", deep_stub)
    monkeypatch.setattr(pipeline.crawl, "stream", crawl_stream)
    monkeypatch.setattr(pipeline.webaudit, "stream", deep_stub)
    monkeypatch.setattr(pipeline.injection, "stream", injection_stream)
    monkeypatch.setattr(pipeline.waf_test, "stream", deep_stub)
    monkeypatch.setattr(pipeline.takeover, "stream", deep_stub)
    monkeypatch.setattr(pipeline.auth_crawl, "stream", deep_stub)
    monkeypatch.setattr(pipeline.ssrf, "stream", deep_stub)
    monkeypatch.setattr(pipeline.idor, "stream", deep_stub)
    monkeypatch.setattr(pipeline.jwt_audit, "stream", deep_stub)
    monkeypatch.setattr(pipeline.csrf, "stream", deep_stub)
    monkeypatch.setattr(pipeline.role_matrix, "stream", deep_stub)
    monkeypatch.setattr(pipeline.open_redirect, "stream", deep_stub)
    from app import netguard as _ng
    monkeypatch.setattr(_ng, "validate_target", lambda target: (True, "ok"))


def _not_tested_tools(summary):
    return {nt["tool"] for nt in summary["coverage"]["not_tested"]}


# --------------------------------------------------------------------------- #
# Missing tools -> explicitly not tested.
# --------------------------------------------------------------------------- #
def test_missing_injection_tools_are_reported_not_tested(monkeypatch):
    # Tools absent from PATH, injection did not run (no params) -> preflight
    # fallback marks both capabilities not-tested.
    _patch(monkeypatch, tools_present=False, injection_marker=None, parameterized=False)
    summary = _summary(_run("example.com", config=PipelineConfig()))
    assert _not_tested_tools(summary) == {"sqlmap", "dalfox"}
    caps = {nt["capability"] for nt in summary["coverage"]["not_tested"]}
    assert caps == {"SQL injection", "Cross-site scripting"}
    assert all(nt["reason"] == "tool not installed"
               for nt in summary["coverage"]["not_tested"])


def test_injection_ran_without_tools_is_authoritative_not_tested(monkeypatch):
    # Even if PATH claims the tools are present, the injection stage's own marker
    # (they did NOT run this scan) is authoritative -> not tested.
    _patch(monkeypatch, tools_present=True,
           injection_marker={"sqlmap": False, "dalfox": False}, parameterized=True)
    summary = _summary(_run("example.com", config=PipelineConfig()))
    assert _not_tested_tools(summary) == {"sqlmap", "dalfox"}


# --------------------------------------------------------------------------- #
# Installed tools -> no false "not tested".
# --------------------------------------------------------------------------- #
def test_installed_tools_no_false_not_tested_via_marker(monkeypatch):
    _patch(monkeypatch, tools_present=True,
           injection_marker={"sqlmap": True, "dalfox": True}, parameterized=True)
    summary = _summary(_run("example.com", config=PipelineConfig()))
    assert summary["coverage"]["not_tested"] == []


def test_installed_tools_no_false_not_tested_via_preflight(monkeypatch):
    # Injection did not run, but the tools are installed -> "tested capability
    # available, no targets" is NOT a not-tested state.
    _patch(monkeypatch, tools_present=True, injection_marker=None, parameterized=False)
    summary = _summary(_run("example.com", config=PipelineConfig()))
    assert summary["coverage"]["not_tested"] == []


# --------------------------------------------------------------------------- #
# A genuine 0-finding scan stays 0 findings; existing behaviour intact.
# --------------------------------------------------------------------------- #
def test_zero_finding_scan_still_reports_zero(monkeypatch):
    _patch(monkeypatch, tools_present=True,
           injection_marker={"sqlmap": True, "dalfox": True}, parameterized=True)
    summary = _summary(_run("example.com", config=PipelineConfig()))
    assert summary["total_findings"] == 0
    assert summary["coverage"]["not_tested"] == []  # additive, not a fake finding


def test_summary_keeps_all_existing_keys(monkeypatch):
    _patch(monkeypatch, tools_present=False, injection_marker=None, parameterized=False)
    summary = _summary(_run("example.com", config=PipelineConfig()))
    assert _LEGACY_SUMMARY_KEYS <= set(summary)          # no key removed
    assert "coverage" in summary                         # only additive change
    assert set(summary["coverage"]) == {"tools", "missing_optional", "not_tested"}

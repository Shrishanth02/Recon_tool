"""Tier-3 pipeline wiring: crawl-discovered forms reach CSRF and discovered API
endpoints reach the JWT/API + GraphQL stage — on an UNAUTHENTICATED scan.

The corpus funnel already routes ``forms``/``api_endpoints`` (Tier 1); these
tests prove the two consumer stages actually fire on those inputs with no
operator auth: CSRF has no auth gate, and the JWT/API stage-17 gate now runs on
discovered API endpoints (jwt_audit performs only the read-only GraphQL check
without an identity).
"""

import asyncio

from app import pipeline
from app.pipeline import PipelineConfig

SEED = "https://app.example.com"


def _run(target, **kwargs):
    async def _go():
        return [e async for e in pipeline.run_pipeline(target, **kwargs)]

    return asyncio.run(_go())


def _patch(monkeypatch, *, crawl_result, captures):
    def httpx_stream(target, **_k):
        yield {"type": "result", "data": {"rows": [{"url": SEED, "host": "app.example.com"}]}}

    def crawl_stream(target, **_k):
        yield {"type": "result", "data": crawl_result}

    def csrf_stream(target, *_a, **_k):
        captures["csrf"].append(target)
        yield {"type": "result", "data": {"target": target, "findings": []}}

    def jwt_stream(target, *_a, **kw):
        captures["jwt_api_endpoints"].extend(kw.get("api_endpoints") or [])
        yield {"type": "result", "data": {"target": target, "findings": []}}

    def deep_stub(target, *_a, **_k):
        yield {"type": "result", "data": {"target": target, "findings": []}}

    monkeypatch.setattr(pipeline.whois_lookup, "stream",
                        lambda t, **k: iter([{"type": "result", "data": {"domain": t}}]))
    monkeypatch.setattr(pipeline.subdomain, "stream",
                        lambda t, **k: iter([{"type": "result", "data": {"subdomains": []}}]))
    monkeypatch.setattr(pipeline.httpx_probe, "stream", httpx_stream)
    monkeypatch.setattr(pipeline.nmap_scan, "stream", deep_stub)
    monkeypatch.setattr(pipeline.techdetect, "stream", deep_stub)
    monkeypatch.setattr(pipeline.nuclei_scan, "stream",
                        lambda t, **k: iter([{"type": "result", "data": {"findings": []}}]))
    monkeypatch.setattr(pipeline.dirbuster, "stream",
                        lambda t, *a, **k: iter([{"type": "result",
                                                  "data": {"target": t, "rows": []}}]))
    monkeypatch.setattr(pipeline, "dns_zt_stream",
                        lambda t, **k: iter([{"type": "result",
                                              "data": {"domain": t, "vulnerable": False}}]))
    monkeypatch.setattr(pipeline.origin_discovery, "stream", deep_stub)
    monkeypatch.setattr(pipeline.crawl, "stream", crawl_stream)
    monkeypatch.setattr(pipeline.webaudit, "stream", deep_stub)
    monkeypatch.setattr(pipeline.injection, "stream", deep_stub)
    monkeypatch.setattr(pipeline.waf_test, "stream", deep_stub)
    monkeypatch.setattr(pipeline.takeover, "stream", deep_stub)
    monkeypatch.setattr(pipeline.auth_crawl, "stream", deep_stub)
    monkeypatch.setattr(pipeline.ssrf, "stream", deep_stub)
    monkeypatch.setattr(pipeline.idor, "stream", deep_stub)
    monkeypatch.setattr(pipeline.jwt_audit, "stream", jwt_stream)
    monkeypatch.setattr(pipeline.csrf, "stream", csrf_stream)
    monkeypatch.setattr(pipeline.role_matrix, "stream", deep_stub)
    monkeypatch.setattr(pipeline.open_redirect, "stream", deep_stub)
    from app import netguard as _ng
    monkeypatch.setattr(_ng, "validate_target", lambda target: (True, "ok"))


def test_discovered_form_reaches_csrf_unauthenticated(monkeypatch):
    captures = {"csrf": [], "jwt_api_endpoints": []}
    crawl_result = {
        "target": SEED, "urls": [], "parameterized_urls": [],
        "forms": [{"action": f"{SEED}/transfer", "method": "POST",
                   "inputs": ["amount", "to"]}],
        "api_endpoints": [], "findings": [],
    }
    _patch(monkeypatch, crawl_result=crawl_result, captures=captures)
    _run("example.com", config=PipelineConfig())  # no auth
    assert f"{SEED}/transfer" in captures["csrf"]


def test_discovered_api_endpoint_reaches_jwt_api_unauthenticated(monkeypatch):
    captures = {"csrf": [], "jwt_api_endpoints": []}
    crawl_result = {
        "target": SEED, "urls": [], "parameterized_urls": [],
        "forms": [],
        "api_endpoints": [f"{SEED}/graphql"], "findings": [],
    }
    _patch(monkeypatch, crawl_result=crawl_result, captures=captures)
    _run("example.com", config=PipelineConfig())  # no auth, no token
    # Stage-17 gate now runs on discovered endpoints even without auth.
    assert f"{SEED}/graphql" in captures["jwt_api_endpoints"]


def test_no_api_endpoints_still_skips_jwt_when_unauthenticated(monkeypatch):
    # Guard: the gate relaxation must not make JWT/API run when there is nothing
    # to audit (no token, no endpoints) — behaviour unchanged in that case.
    captures = {"csrf": [], "jwt_api_endpoints": []}
    crawl_result = {"target": SEED, "urls": [], "parameterized_urls": [],
                    "forms": [], "api_endpoints": [], "findings": []}
    _patch(monkeypatch, crawl_result=crawl_result, captures=captures)
    _run("example.com", config=PipelineConfig())
    assert captures["jwt_api_endpoints"] == []

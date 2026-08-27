"""Tier-1 discovery-corpus tests for :func:`app.pipeline.run_pipeline`.

The pipeline unifies every discovery source (crawl, auth_crawl, ffuf, Arjun)
into one corpus (``param_entries`` / ``discovered_urls``) that the downstream
scanners consume. These tests prove the three previously-discarded sources now
reach the RIGHT corpus, observed through the scanners that consume it, and that
the crawl fan-out is bounded by config:

* ffuf rows WITH a query  -> param_entries  -> observed at ``injection.stream``;
* ffuf rows WITHOUT a query -> discovered_urls -> observed at ``role_matrix.stream``;
* Arjun ``params_discovered`` -> synthetic ``?name=1`` param_entries -> injection;
* the crawl seed count is ``min(len(live_urls), config.max_crawl_seeds)``.

Every scanner is stubbed offline; netguard is neutralized (the stub hosts do not
resolve) so the corpus routing is asserted in isolation.
"""

import asyncio

import pytest

from app import pipeline
from app.pipeline import PipelineConfig

SEED = "https://app.example.com"


def _patch_common(monkeypatch, *, live_urls, dirbuster_stream, crawl_stream, captures):
    """Stub every scanner offline. ``captures`` collects consumer call targets."""
    def whois_stream(target, **_k):
        yield {"type": "result", "data": {"domain": target}}

    def subdomain_stream(target, **_k):
        yield {"type": "result", "data": {"subdomains": []}}

    def httpx_stream(target, **_k):
        yield {"type": "result", "data": {"rows": [{"url": u} for u in live_urls]}}

    def nmap_stream(target, **_k):
        yield {"type": "result", "data": {"host": target, "ports": []}}

    def nuclei_stream(target, **_k):
        yield {"type": "result", "data": {"findings": []}}

    def injection_stream(target, *_a, **_k):
        captures["injection"].append(target)
        yield {"type": "result", "data": {"target": target, "findings": []}}

    def role_matrix_stream(target, *_a, **_k):
        captures["role_matrix"].append(target)
        yield {"type": "result", "data": {"target": target, "findings": []}}

    def deep_stub(target, *_a, **_k):
        yield {"type": "result", "data": {"target": target, "findings": []}}

    monkeypatch.setattr(pipeline.whois_lookup, "stream", whois_stream)
    monkeypatch.setattr(pipeline.subdomain, "stream", subdomain_stream)
    monkeypatch.setattr(pipeline.httpx_probe, "stream", httpx_stream)
    monkeypatch.setattr(pipeline.nmap_scan, "stream", nmap_stream)
    monkeypatch.setattr(pipeline.techdetect, "stream", deep_stub)
    monkeypatch.setattr(pipeline.nuclei_scan, "stream", nuclei_stream)
    monkeypatch.setattr(pipeline.dirbuster, "stream", dirbuster_stream)
    monkeypatch.setattr(pipeline, "dns_zt_stream",
                        lambda target, **_k: iter(
                            [{"type": "result", "data": {"domain": target, "vulnerable": False}}]))
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
    monkeypatch.setattr(pipeline.role_matrix, "stream", role_matrix_stream)
    monkeypatch.setattr(pipeline.open_redirect, "stream", deep_stub)
    from app import netguard as _ng
    monkeypatch.setattr(_ng, "validate_target", lambda target: (True, "ok"))


def _run(target, **kwargs):
    async def _go():
        return [e async for e in pipeline.run_pipeline(target, **kwargs)]

    return asyncio.run(_go())


# --------------------------------------------------------------------------- #
# Corpus routing — each discarded source reaches the right corpus.
# --------------------------------------------------------------------------- #
@pytest.fixture()
def corpus_run(monkeypatch):
    captures = {"injection": [], "role_matrix": [], "crawl_seeds": []}

    def dirbuster_stream(target, *_a, **_k):
        # One path WITHOUT a query and one WITH a query, both on this target.
        yield {"type": "result", "data": {"target": target, "rows": [
            {"url": f"{target}/admin"},
            {"url": f"{target}/search?q=1"},
        ]}}

    def crawl_stream(target, *_a, **_k):
        captures["crawl_seeds"].append(target)
        yield {"type": "result", "data": {
            "target": target,
            "urls": [f"{target}/page"],
            "parameterized_urls": [],
            "params_discovered": ["hidden_p"],
            "findings": [],
        }}

    _patch_common(monkeypatch, live_urls=[SEED],
                  dirbuster_stream=dirbuster_stream, crawl_stream=crawl_stream,
                  captures=captures)
    return captures


def test_ffuf_query_row_reaches_injection_corpus(corpus_run):
    # Two operator identities so the role-matrix (discovered_urls consumer) runs.
    cfg = PipelineConfig(auth_identities=[
        {"label": "a", "cookie": "s=1"}, {"label": "b", "cookie": "s=2"}])
    _run("example.com", config=cfg)
    # ffuf row with a query -> param_entries -> injection.
    assert f"{SEED}/search?q=1" in corpus_run["injection"]


def test_arjun_param_reaches_injection_corpus(corpus_run):
    cfg = PipelineConfig(auth_identities=[
        {"label": "a", "cookie": "s=1"}, {"label": "b", "cookie": "s=2"}])
    _run("example.com", config=cfg)
    # Arjun hidden param -> synthetic benign entry -> param_entries -> injection.
    assert f"{SEED}?hidden_p=1" in corpus_run["injection"]


def test_ffuf_pathonly_row_reaches_discovered_urls(corpus_run):
    cfg = PipelineConfig(auth_identities=[
        {"label": "a", "cookie": "s=1"}, {"label": "b", "cookie": "s=2"}])
    _run("example.com", config=cfg)
    # ffuf row without a query -> discovered_urls -> role-matrix consumer.
    assert f"{SEED}/admin" in corpus_run["role_matrix"]


# --------------------------------------------------------------------------- #
# Crawl fan-out is bounded by config (was hard-coded to 1).
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("max_seeds,expected", [(1, 1), (2, 2), (3, 3), (10, 5)])
def test_crawl_seed_fanout_is_bounded(monkeypatch, max_seeds, expected):
    live = [f"https://h{i}.example.com" for i in range(5)]  # 5 live hosts
    seeds = []

    def dirbuster_stream(target, *_a, **_k):
        yield {"type": "result", "data": {"target": target, "rows": []}}

    def crawl_stream(target, *_a, **_k):
        seeds.append(target)
        yield {"type": "result", "data": {"target": target, "urls": [],
                                          "parameterized_urls": [], "findings": []}}

    _patch_common(monkeypatch, live_urls=live,
                  dirbuster_stream=dirbuster_stream, crawl_stream=crawl_stream,
                  captures={"injection": [], "role_matrix": [], "crawl_seeds": []})
    _run("example.com", config=PipelineConfig(max_crawl_seeds=max_seeds))
    # Exactly min(len(live_urls), max_crawl_seeds) distinct seeds are crawled.
    assert len(seeds) == expected
    assert seeds == live[:expected]

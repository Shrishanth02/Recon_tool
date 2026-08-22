"""P0 tests for the auto-pentest engine (:func:`app.pipeline.run_pipeline`).

The pipeline is driven end-to-end with every scanner stubbed by a fast, offline
generator (no external tools, no network). We assert three P0 guarantees:

* **persistence** — the ``persist`` callback receives save_scan-shaped records
  for the nuclei / nmap / dirbuster stages (and one such record actually feeds
  :func:`crud.save_scan` to derive a finding);
* **scope enforcement** — when a ``scope_list`` is set, a discovered host that
  is out of scope is dropped before any host is probed;
* **unrestricted** — ``scope_list=None`` keeps every discovered host.
"""

import asyncio

import pytest

from app import crud, pipeline
from app.database import SessionLocal

_RECORD_KEYS = {
    "tool",
    "target",
    "status",
    "options",
    "logs",
    "result",
    "started_at",
    "finished_at",
}


@pytest.fixture()
def stub_pipeline(monkeypatch):
    """Replace every scanner stream with a fast offline stub.

    Returns a ``calls`` dict recording the targets each stage was invoked with,
    so scope filtering can be asserted from what the HTTP probe actually saw.
    """
    calls = {"httpx_target": [], "nmap_hosts": [], "nuclei_target": [], "dirbust_urls": []}

    # example.com discovers one in-scope subdomain and one out-of-scope host.
    subs_result = {"subdomains": ["app.example.com", "evil.attacker.com"]}
    httpx_result = {
        "rows": [
            {"url": "https://app.example.com", "host": "app.example.com"},
            {"url": "https://example.com", "host": "example.com"},
        ]
    }
    nuclei_result = {
        "findings": [
            {
                "severity": "high",
                "name": "Stub High Finding",
                "template_id": "stub-high",
                "matched_at": "https://app.example.com",
                "description": "injected by the stub",
                "cve": ["CVE-2024-9999"],
                "cwe": ["CWE-79"],
                "cvss": 7.5,
            }
        ]
    }

    def whois_stream(target, **_k):
        yield {"type": "result", "data": {"domain": target}}

    def subdomain_stream(target, **_k):
        yield {"type": "result", "data": subs_result}

    def httpx_stream(target, **_k):
        calls["httpx_target"].append(target)
        yield {"type": "result", "data": httpx_result}

    def nmap_stream(target, **_k):
        calls["nmap_hosts"].append(target)
        yield {"type": "result", "data": {"host": target, "ports": []}}

    def tech_stream(target, **_k):
        yield {"type": "result", "data": {"url": target, "technologies": []}}

    def nuclei_stream(target, **_k):
        calls["nuclei_target"].append(target)
        yield {"type": "result", "data": nuclei_result}

    def dirbuster_stream(target, **_k):
        calls["dirbust_urls"].append(target)
        yield {"type": "result", "data": {"target": target, "rows": []}}

    def dns_zt_stream(target, **_k):
        yield {"type": "result", "data": {"domain": target, "vulnerable": False}}

    monkeypatch.setattr(pipeline.whois_lookup, "stream", whois_stream)
    monkeypatch.setattr(pipeline.subdomain, "stream", subdomain_stream)
    monkeypatch.setattr(pipeline.httpx_probe, "stream", httpx_stream)
    monkeypatch.setattr(pipeline.nmap_scan, "stream", nmap_stream)
    monkeypatch.setattr(pipeline.techdetect, "stream", tech_stream)
    monkeypatch.setattr(pipeline.nuclei_scan, "stream", nuclei_stream)
    monkeypatch.setattr(pipeline.dirbuster, "stream", dirbuster_stream)
    # dns_zt is imported by name into the pipeline module namespace.
    monkeypatch.setattr(pipeline, "dns_zt_stream", dns_zt_stream)

    # Stub the deep-scan stages (9-13) too so the pipeline test stays hermetic
    # and fast — otherwise origin/crawl/webaudit/injection/waf make REAL network
    # calls to the target on every run. Their own logic is covered by their
    # standalone smoke tests; here we only need them to not touch the network.
    def deep_stub(target, *_a, **_k):
        yield {"type": "result", "data": {"target": target, "findings": []}}

    monkeypatch.setattr(pipeline.origin_discovery, "stream", deep_stub)
    monkeypatch.setattr(pipeline.crawl, "stream", deep_stub)
    monkeypatch.setattr(pipeline.webaudit, "stream", deep_stub)
    monkeypatch.setattr(pipeline.injection, "stream", deep_stub)
    monkeypatch.setattr(pipeline.waf_test, "stream", deep_stub)
    monkeypatch.setattr(pipeline.takeover, "stream", deep_stub)
    monkeypatch.setattr(pipeline.auth_crawl, "stream", deep_stub)
    monkeypatch.setattr(pipeline.ssrf, "stream", deep_stub)
    monkeypatch.setattr(pipeline.idor, "stream", deep_stub)
    monkeypatch.setattr(pipeline.jwt_audit, "stream", deep_stub)
    monkeypatch.setattr(pipeline.csrf, "stream", deep_stub)
    # Neutralize the SSRF/egress guard for these OFFLINE tests: the stub hosts
    # (app.example.com, evil.attacker.com) don't resolve, so the real netguard
    # (fail-closed on unresolvable) would correctly drop them and defeat the
    # scope-filtering assertions. netguard's own blocking is covered in
    # test_netguard.py; here we assert the *scope* logic in isolation. The
    # pipeline imports netguard lazily, so patch it at the source module.
    from app import netguard as _ng
    monkeypatch.setattr(_ng, "validate_target", lambda target: (True, "ok"))
    return calls


def _run(target, **kwargs):
    """Drive run_pipeline to completion, returning the list of streamed events."""

    async def _go():
        events = []
        async for event in pipeline.run_pipeline(target, **kwargs):
            events.append(event)
        return events

    return asyncio.run(_go())


# --------------------------------------------------------------------------- #
# (a) Persistence — save_scan-shaped records for nuclei / nmap / dirbuster.
# --------------------------------------------------------------------------- #
def test_persist_receives_save_scan_shaped_records(stub_pipeline):
    records = []
    events = _run("example.com", persist=records.append)

    # The run reached its summary.
    assert any(e.get("type") == "pipeline_done" for e in events)

    tools = [r["tool"] for r in records]
    assert "nuclei" in tools
    assert "nmap" in tools
    assert "dirbuster" in tools

    # Every persisted record matches the save_scan contract exactly.
    for rec in records:
        assert set(rec) == _RECORD_KEYS
        assert rec["status"] == "done"
        assert rec["options"] == {}
        assert rec["logs"] == []
        assert rec["result"] is not None
        assert rec["started_at"] and rec["finished_at"]

    # The nmap record is keyed to the host it scanned, dirbuster to its URL.
    nmap_rec = next(r for r in records if r["tool"] == "nmap")
    assert nmap_rec["target"] in {"app.example.com", "example.com"}
    dirb_rec = next(r for r in records if r["tool"] == "dirbuster")
    assert dirb_rec["target"].startswith("https://")


def test_persisted_nuclei_record_feeds_save_scan(stub_pipeline):
    """A record handed to persist is directly consumable by crud.save_scan."""
    records = []
    _run("example.com", persist=records.append)
    nuclei_rec = next(r for r in records if r["tool"] == "nuclei")

    db = SessionLocal()
    try:
        _u, _o, ws = crud.create_user_with_org(db, "pipeline@example.com", "password123")
        db.commit()

        scan = crud.save_scan(db, {**nuclei_rec, "workspace_id": ws.id})
        db.commit()

        assert scan.id is not None
        assert scan.tool == "nuclei"
        # The nuclei-shaped result derived exactly one high finding.
        findings = crud.list_findings(db, ws.id)
        assert len(findings) == 1
        assert findings[0].severity == "high"
        assert findings[0].name == "Stub High Finding"
    finally:
        db.close()


def test_persist_is_optional(stub_pipeline):
    # With no persist callback the pipeline still runs to completion.
    events = _run("example.com")
    assert any(e.get("type") == "pipeline_done" for e in events)


# --------------------------------------------------------------------------- #
# (b) Scope enforcement — an out-of-scope discovered host is dropped.
# --------------------------------------------------------------------------- #
def test_out_of_scope_host_is_filtered(stub_pipeline):
    events = _run("example.com", scope_list=["*.example.com"])

    # The HTTP probe (the first stage to touch discovered hosts) never saw the
    # out-of-scope host, but did see the in-scope subdomain and the root.
    assert stub_pipeline["httpx_target"], "HTTP probe should have run"
    probed = stub_pipeline["httpx_target"][0]
    assert "evil.attacker.com" not in probed
    assert "app.example.com" in probed
    assert "example.com" in probed

    # A skip log was emitted for the dropped host.
    logs = "\n".join(e["data"] for e in events if e.get("type") == "pipeline_log")
    assert "out of scope — skipping evil.attacker.com" in logs

    # No later stage touched the out-of-scope host either.
    assert "evil.attacker.com" not in stub_pipeline["nmap_hosts"]


# --------------------------------------------------------------------------- #
# (c) Unrestricted — scope_list=None keeps every discovered host.
# --------------------------------------------------------------------------- #
def test_scope_none_keeps_all_hosts(stub_pipeline):
    _run("example.com", scope_list=None)

    assert stub_pipeline["httpx_target"], "HTTP probe should have run"
    probed = stub_pipeline["httpx_target"][0]
    assert "evil.attacker.com" in probed
    assert "app.example.com" in probed
    assert "example.com" in probed


# --------------------------------------------------------------------------- #
# (d) SSRF regression — a discovered host that netguard blocks (e.g. the cloud
#     metadata IP) is NEVER probed, even with unrestricted scope. Guards against
#     regressing the pipeline back into an unguarded SSRF primitive.
# --------------------------------------------------------------------------- #
def test_pipeline_drops_netguard_blocked_host(monkeypatch):
    calls = {"httpx": [], "nmap": []}

    def subs(target, **_k):
        yield {"type": "result", "data": {"subdomains": ["169.254.169.254"]}}

    def httpx(target, **_k):
        calls["httpx"].append(target)
        yield {"type": "result", "data": {"rows": []}}

    def nmap(target, **_k):
        calls["nmap"].append(target)
        yield {"type": "result", "data": {"host": target, "ports": []}}

    def passthru(target, **_k):
        yield {"type": "result", "data": {"domain": target}}

    monkeypatch.setattr(pipeline.whois_lookup, "stream", passthru)
    monkeypatch.setattr(pipeline.subdomain, "stream", subs)
    monkeypatch.setattr(pipeline.httpx_probe, "stream", httpx)
    monkeypatch.setattr(pipeline.nmap_scan, "stream", nmap)
    monkeypatch.setattr(pipeline.techdetect, "stream", passthru)
    monkeypatch.setattr(pipeline.nuclei_scan, "stream", passthru)
    monkeypatch.setattr(pipeline.dirbuster, "stream", passthru)
    monkeypatch.setattr(pipeline, "dns_zt_stream", passthru)
    # netguard blocks the metadata IP, allows the (public) root domain — the
    # deterministic stand-in for the real guard's always-on metadata block.
    from app import netguard as _ng
    monkeypatch.setattr(
        _ng, "validate_target",
        lambda t: (False, "blocked address") if "169.254" in t else (True, "ok"),
    )

    events = _run("example.com", scope_list=None)  # unrestricted scope

    probed = ",".join(calls["httpx"])
    assert "169.254.169.254" not in probed, "metadata IP must never be probed"
    assert "example.com" in probed, "the safe root should still be scanned"
    assert "169.254.169.254" not in ",".join(calls["nmap"])
    logs = "\n".join(e["data"] for e in events if e.get("type") == "pipeline_log")
    assert "blocked (egress guard)" in logs


# --------------------------------------------------------------------------- #
# (e) Feature 2 — a subdomain-takeover finding from stage 14 flows to persist.
# --------------------------------------------------------------------------- #
def test_takeover_finding_flows_to_persist(stub_pipeline, monkeypatch):
    def takeover_stub(target, *_a, **_k):
        if target == "app.example.com":
            yield {"type": "result", "data": {
                "target": target, "cname": "b.s3.amazonaws.com", "provider": "AWS/S3",
                "findings": [{
                    "severity": "high",
                    "name": f"Subdomain takeover: {target} (AWS/S3)",
                    "location": target, "cwe": ["CWE-350"],
                    "detection_tier": "validated", "confidence": 90,
                    "evidence": {"provider": "AWS/S3", "fingerprint": "NoSuchBucket"},
                }],
            }}
        else:
            yield {"type": "result", "data": {"target": target, "findings": []}}

    monkeypatch.setattr(pipeline.takeover, "stream", takeover_stub)

    records = []
    events = _run("example.com", persist=records.append,
                  scope_list=["*.example.com", "example.com"])
    assert any(e.get("type") == "pipeline_done" for e in events)
    tk = [r for r in records if r["tool"] == "takeover"]
    assert tk, "the takeover result should have been persisted"
    assert any(
        f.get("detection_tier") == "validated"
        for r in tk for f in (r["result"].get("findings") or [])
    )


# --------------------------------------------------------------------------- #
# (f) Feature 3 — authenticated crawl feeds injection; scope/netguard gate every
#     discovered URL; unauthenticated runs are unchanged.
# --------------------------------------------------------------------------- #
_SCOPE = ["*.example.com", "example.com"]


def _crawl_stub(param_url):
    def _s(url, *_a, **_k):
        yield {"type": "result", "data": {
            "target": url, "parameterized_urls": [{"url": param_url, "params": ["id"]}],
        }}
    return _s


def test_authenticated_crawl_feeds_injection(stub_pipeline, monkeypatch):
    def auth_stub(url, *_a, **k):
        # The operator's session actually reaches auth_crawl.
        assert k.get("cookie") == "session=abc"
        yield {"type": "result", "data": {
            "target": url, "authenticated": True, "login_method": "cookie",
            "parameterized_urls": [{"url": "https://app.example.com/admin?uid=7", "params": ["uid"]}],
        }}

    def inj_stub(url, *_a, **_k):
        yield {"type": "result", "data": {"target": url, "findings": [{
            "severity": "high", "name": "SQL Injection: p", "location": url,
            "cwe": "CWE-89", "tool": "sqlmap", "evidence": {"parameter": "p"},
        }]}}

    monkeypatch.setattr(pipeline.crawl, "stream", _crawl_stub("https://app.example.com/pub?id=1"))
    monkeypatch.setattr(pipeline.auth_crawl, "stream", auth_stub)
    monkeypatch.setattr(pipeline.injection, "stream", inj_stub)

    cfg = pipeline.PipelineConfig(auth={"cookie": "session=abc"})
    records = []
    _run("example.com", persist=records.append, scope_list=_SCOPE, config=cfg)

    assert any(r["tool"] == "auth_crawl" for r in records)         # auth stage ran
    inj = [r for r in records if r["tool"] == "injection"]
    urls = {r["target"] for r in inj}
    assert "https://app.example.com/admin?uid=7" in urls           # authenticated endpoint tested
    # The finding on the authenticated endpoint is annotated as such.
    ann = [f for r in inj for f in (r["result"].get("findings") or [])
           if f.get("evidence", {}).get("authenticated")]
    assert ann and ann[0]["evidence"]["discovery_source"] == "auth_crawl"
    assert ann[0]["evidence"]["http_method"] == "GET"


def test_unauthenticated_run_skips_auth_crawl(stub_pipeline, monkeypatch):
    calls = {"auth": 0}

    def auth_stub(url, *_a, **_k):
        calls["auth"] += 1
        yield {"type": "result", "data": {"target": url, "parameterized_urls": []}}

    monkeypatch.setattr(pipeline.auth_crawl, "stream", auth_stub)
    records = []
    _run("example.com", persist=records.append, scope_list=_SCOPE)  # no config.auth
    assert calls["auth"] == 0
    assert not any(r["tool"] == "auth_crawl" for r in records)


def test_injection_skips_out_of_scope_discovered_url(stub_pipeline, monkeypatch):
    inj_urls = []

    def crawl_stub(url, *_a, **_k):
        yield {"type": "result", "data": {"target": url, "parameterized_urls": [
            {"url": "https://evil.other.com/x?id=1", "params": ["id"]},
            {"url": "https://app.example.com/ok?id=1", "params": ["id"]},
        ]}}

    def inj_stub(url, *_a, **_k):
        inj_urls.append(url)
        yield {"type": "result", "data": {"target": url, "findings": []}}

    monkeypatch.setattr(pipeline.crawl, "stream", crawl_stub)
    monkeypatch.setattr(pipeline.injection, "stream", inj_stub)
    _run("example.com", persist=lambda r: None, scope_list=_SCOPE)
    assert "https://evil.other.com/x?id=1" not in inj_urls          # out of scope -> skipped
    assert "https://app.example.com/ok?id=1" in inj_urls


def test_injection_skips_netguard_blocked_discovered_url(stub_pipeline, monkeypatch):
    from app import netguard as _ng
    monkeypatch.setattr(_ng, "validate_target",
                        lambda t: (False, "blocked") if "bad" in t else (True, "ok"))
    inj_urls = []

    def crawl_stub(url, *_a, **_k):
        yield {"type": "result", "data": {"target": url, "parameterized_urls": [
            {"url": "https://bad.example.com/x?id=1", "params": ["id"]},
            {"url": "https://app.example.com/ok?id=1", "params": ["id"]},
        ]}}

    def inj_stub(url, *_a, **_k):
        inj_urls.append(url)
        yield {"type": "result", "data": {"target": url, "findings": []}}

    monkeypatch.setattr(pipeline.crawl, "stream", crawl_stub)
    monkeypatch.setattr(pipeline.injection, "stream", inj_stub)
    _run("example.com", persist=lambda r: None, scope_list=_SCOPE)
    assert not any("bad.example.com" in u for u in inj_urls)        # netguard blocked
    assert any("app.example.com" in u for u in inj_urls)


def test_injection_target_cap_is_respected(stub_pipeline, monkeypatch):
    def crawl_stub(url, *_a, **_k):
        many = [{"url": f"https://app.example.com/p{i}?id=1", "params": ["id"]} for i in range(25)]
        yield {"type": "result", "data": {"target": url, "parameterized_urls": many}}

    inj_urls = []

    def inj_stub(url, *_a, **_k):
        inj_urls.append(url)
        yield {"type": "result", "data": {"target": url, "findings": []}}

    monkeypatch.setattr(pipeline.crawl, "stream", crawl_stub)
    monkeypatch.setattr(pipeline.injection, "stream", inj_stub)
    cfg = pipeline.PipelineConfig(max_injection_targets=10)
    _run("example.com", persist=lambda r: None, scope_list=_SCOPE, config=cfg)
    assert len(inj_urls) == 10                                      # capped


# --------------------------------------------------------------------------- #
# (g) SSRF / IDOR / JWT stages — flow + gating + scope/netguard.
# --------------------------------------------------------------------------- #
def _crawl_params_urls(param_urls=(), urls=()):
    def _s(url, *_a, **_k):
        yield {"type": "result", "data": {
            "target": url,
            "parameterized_urls": [{"url": u, "params": ["url"]} for u in param_urls],
            "urls": list(urls),
        }}
    return _s


def test_ssrf_stage_flows_to_persist(stub_pipeline, monkeypatch):
    def ssrf_stub(url, *_a, **_k):
        yield {"type": "result", "data": {"target": url, "findings": [{
            "severity": "high", "name": "SSRF (reflective) in 'url'", "location": url,
            "cwe": ["CWE-918"], "detection_tier": "validated", "confidence": 85,
            "evidence": {"parameter": "url"},
        }]}}

    monkeypatch.setattr(pipeline.crawl, "stream",
                        _crawl_params_urls(param_urls=["https://app.example.com/fetch?url=x"]))
    monkeypatch.setattr(pipeline.ssrf, "stream", ssrf_stub)
    records = []
    _run("example.com", persist=records.append, scope_list=_SCOPE)
    sr = [r for r in records if r["tool"] == "ssrf"]
    assert sr and any(f["detection_tier"] == "validated"
                      for r in sr for f in r["result"].get("findings", []))


def test_ssrf_stage_skips_out_of_scope_url(stub_pipeline, monkeypatch):
    tested = []

    def ssrf_stub(url, *_a, **_k):
        tested.append(url)
        yield {"type": "result", "data": {"target": url, "findings": []}}

    monkeypatch.setattr(pipeline.crawl, "stream", _crawl_params_urls(
        param_urls=["https://evil.other.com/f?url=x", "https://app.example.com/f?url=x"]))
    monkeypatch.setattr(pipeline.ssrf, "stream", ssrf_stub)
    _run("example.com", persist=lambda r: None, scope_list=_SCOPE)
    assert not any("evil.other.com" in u for u in tested)
    assert any("app.example.com" in u for u in tested)


def test_idor_stage_runs_with_two_identities(stub_pipeline, monkeypatch):
    def idor_stub(url, *_a, **k):
        assert k.get("identities") and len(k["identities"]) >= 2
        yield {"type": "result", "data": {"target": url, "findings": [{
            "severity": "high", "name": "IDOR (123)",
            "location": "https://app.example.com/account/123", "cwe": ["CWE-639"],
            "detection_tier": "validated", "confidence": 85, "evidence": {"object_id": "123"},
        }]}}

    monkeypatch.setattr(pipeline.crawl, "stream",
                        _crawl_params_urls(urls=["https://app.example.com/account/123"]))
    monkeypatch.setattr(pipeline.idor, "stream", idor_stub)
    cfg = pipeline.PipelineConfig(auth_identities=[{"label": "A", "cookie": "sa"},
                                                   {"label": "B", "cookie": "sb"}])
    records = []
    _run("example.com", persist=records.append, scope_list=_SCOPE, config=cfg)
    ir = [r for r in records if r["tool"] == "idor"]
    assert ir and any(f["detection_tier"] == "validated"
                      for r in ir for f in r["result"].get("findings", []))


def test_idor_stage_runs_without_two_identities_for_unauth_check(stub_pipeline, monkeypatch):
    """With <2 identities the IDOR stage STILL runs so the scanner can perform the
    anonymous unauthenticated-object-access check; only the cross-user comparison
    inside the scanner is gated on >=2 identities."""
    seen = {"n": 0, "identities": None}

    def idor_stub(url, *_a, **k):
        seen["n"] += 1
        seen["identities"] = k.get("identities")
        yield {"type": "result", "data": {"target": url, "findings": []}}

    monkeypatch.setattr(pipeline.crawl, "stream",
                        _crawl_params_urls(urls=["https://app.example.com/account/123"]))
    monkeypatch.setattr(pipeline.idor, "stream", idor_stub)
    _run("example.com", persist=lambda r: None, scope_list=_SCOPE)  # no identities
    assert seen["n"] == 1               # stage runs for the anonymous object-access check
    assert seen["identities"] == []     # but with no identities to compare cross-user


def test_jwt_stage_runs_with_bearer_token(stub_pipeline, monkeypatch):
    def jwt_stub(target, *_a, **k):
        assert "bearer" in (k.get("auth_header", "")).lower()
        yield {"type": "result", "data": {"target": target, "findings": [{
            "severity": "critical", "name": "JWT alg none", "location": "jwt",
            "cwe": ["CWE-347"], "detection_tier": "validated", "confidence": 90,
            "evidence": {"alg": "none"},
        }]}}

    monkeypatch.setattr(pipeline.jwt_audit, "stream", jwt_stub)
    cfg = pipeline.PipelineConfig(auth={"auth_header": "Authorization: Bearer eyJ.x.y"})
    records = []
    _run("example.com", persist=records.append, scope_list=_SCOPE, config=cfg)
    jr = [r for r in records if r["tool"] == "jwt"]
    assert jr and any(f["detection_tier"] == "validated"
                      for r in jr for f in r["result"].get("findings", []))


def test_authenticated_form_post_injection(stub_pipeline, monkeypatch):
    def auth_stub(url, *_a, **_k):
        yield {"type": "result", "data": {
            "target": url, "authenticated": True, "parameterized_urls": [], "urls": [],
            "api_endpoints": [],
            "forms": [{"action": "https://app.example.com/create", "method": "POST",
                       "inputs": ["title", "body"]}],
        }}

    seen = {}

    def inj_stub(url, *_a, **k):
        # form injection passes method + urlencoded body
        if k.get("method") == "POST":
            seen.update(url=url, method=k.get("method"), data=k.get("data"),
                        ctype=k.get("content_type"))
        yield {"type": "result", "data": {"target": url, "findings": [{
            "severity": "high", "name": "SQLi", "location": url, "cwe": "CWE-89",
            "detection_tier": "validated", "confidence": 90, "evidence": {"parameter": "title"},
        }]}}

    monkeypatch.setattr(pipeline.auth_crawl, "stream", auth_stub)
    monkeypatch.setattr(pipeline.injection, "stream", inj_stub)
    cfg = pipeline.PipelineConfig(auth={"cookie": "s=1"})
    records = []
    _run("example.com", persist=records.append, scope_list=_SCOPE, config=cfg)
    assert seen.get("method") == "POST"
    assert "title=1" in (seen.get("data") or "") and "body=1" in (seen.get("data") or "")
    inj = [r for r in records if r["tool"] == "injection"]
    assert any(f["evidence"].get("discovery_source") == "auth_crawl_form"
               for r in inj for f in r["result"].get("findings", []))


def test_csrf_stage_tests_state_changing_forms(stub_pipeline, monkeypatch):
    def auth_stub(url, *_a, **_k):
        yield {"type": "result", "data": {
            "target": url, "authenticated": True, "parameterized_urls": [], "urls": [],
            "api_endpoints": [],
            "forms": [{"action": "https://app.example.com/transfer", "method": "POST",
                       "inputs": ["amount", "csrf"]}],
        }}

    seen = {}

    def csrf_stub(url, *_a, **k):
        seen.update(url=url, method=k.get("method"), inputs=k.get("inputs"),
                    idh=k.get("identity_headers"))
        yield {"type": "result", "data": {"target": url, "findings": [{
            "severity": "high", "name": "CSRF not enforced", "location": url,
            "cwe": ["CWE-352"], "detection_tier": "validated", "confidence": 80,
            "evidence": {"endpoint": url},
        }]}}

    monkeypatch.setattr(pipeline.auth_crawl, "stream", auth_stub)
    monkeypatch.setattr(pipeline.csrf, "stream", csrf_stub)
    cfg = pipeline.PipelineConfig(auth={"cookie": "s=1"})
    records = []
    _run("example.com", persist=records.append, scope_list=_SCOPE, config=cfg)
    assert seen.get("method") == "POST"
    assert seen.get("idh", {}).get("Cookie") == "s=1"      # identity threaded through
    cr = [r for r in records if r["tool"] == "csrf"]
    assert cr and any(f["detection_tier"] == "validated"
                      for r in cr for f in r["result"].get("findings", []))


def test_bizlogic_stage_emits_info_signals(stub_pipeline, monkeypatch):
    def auth_stub(url, *_a, **_k):
        yield {"type": "result", "data": {
            "target": url, "authenticated": True, "parameterized_urls": [], "urls": [],
            "api_endpoints": [],
            "forms": [{"action": "https://app.example.com/checkout", "method": "POST",
                       "inputs": ["price", "qty"]}],
        }}

    monkeypatch.setattr(pipeline.auth_crawl, "stream", auth_stub)
    cfg = pipeline.PipelineConfig(auth={"cookie": "s=1"})
    records = []
    _run("example.com", persist=records.append, scope_list=_SCOPE, config=cfg)
    br = [r for r in records if r["tool"] == "bizlogic"]
    assert br
    findings = [f for r in br for f in r["result"].get("findings", [])]
    assert findings
    # Business-logic signals are informational and never validated automatically.
    assert all(f["kind"] == "info" and f["detection_tier"] == "signal" for f in findings)


def test_drain_isolates_a_raising_scanner():
    """STEP 4 resilience: a scanner that RAISES must not propagate out of _drain
    and abort the whole pipeline — it becomes a stage error line, exactly like an
    emitted {"type":"error"} event, so remaining stages still run."""
    import threading

    def _raising_gen():
        yield {"type": "log", "data": "before-crash"}
        raise RuntimeError("scanner blew up")

    async def _go():
        q: asyncio.Queue = asyncio.Queue()
        loop = asyncio.get_running_loop()
        cancel = threading.Event()
        # Run like the real pipeline (in a worker thread). _drain must NOT raise.
        result = await loop.run_in_executor(
            None, pipeline._drain, _raising_gen(), cancel, 6, q, loop
        )
        await asyncio.sleep(0)  # let the scheduled call_soon_threadsafe puts run
        events = []
        while not q.empty():
            events.append(q.get_nowait())
        return result, events

    result, events = asyncio.run(_go())
    assert result is None  # no result produced, but crucially no exception propagated
    datas = [e.get("data", "") for e in events]
    assert any("before-crash" in d for d in datas)  # pre-crash output preserved
    assert any("stage error" in d for d in datas)   # the crash surfaced as a stage line

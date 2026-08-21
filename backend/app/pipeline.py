"""Automated end-to-end pentesting pipeline engine.

Given a single target (domain, IP, or URL), this module drives the full kill-chain:

    Stage 1  — WHOIS + subdomain enumeration (subfinder)
    Stage 2  — HTTP probe (httpx) on all discovered hosts
    Stage 3  — Port scan (nmap service) on live hosts
    Stage 4  — Tech fingerprinting (builtwith + HTTP)
    Stage 5  — Vulnerability scan (nuclei) on live HTTP targets
    Stage 6  — Content discovery (ffuf) on each live web target
    Stage 7  — (Optional) DNS zone transfer attempt
    Summary  — Aggregate all findings, compute risk score

Every stage streams its events via an ``asyncio.Queue`` to the WebSocket
caller in the form::

    {"type": "pipeline_stage",  "stage": <int>, "name": <str>, "status": "started"}
    {"type": "pipeline_log",    "stage": <int>, "data": <str>}
    {"type": "pipeline_result", "stage": <int>, "name": <str>, "data": <dict>}
    {"type": "pipeline_stage",  "stage": <int>, "name": <str>, "status": "done"|"error"|"skipped"}
    {"type": "pipeline_done",   "risk_score": <int>, "summary": <dict>}

A ``threading.Event`` (``cancel``) lets the caller abort at any point.
"""

from __future__ import annotations

import asyncio
import logging
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, AsyncIterator, Iterator
from urllib.parse import parse_qsl, urlsplit

from . import bizlogic
from . import risk as risk_mod
from . import scope as scope_mod
from .scanners import (
    auth_crawl,
    crawl,
    csrf,
    dirbuster,
    httpx_probe,
    idor,
    injection,
    jwt_audit,
    nmap_scan,
    nuclei_scan,
    origin_discovery,
    ssrf,
    subdomain,
    takeover,
    techdetect,
    waf_test,
    webaudit,
    whois_lookup,
)
from .scanners.dns_zone_transfer import stream as dns_zt_stream

logger = logging.getLogger("reconx.pipeline")


# --------------------------------------------------------------------------- #
# Data structures
# --------------------------------------------------------------------------- #

@dataclass
class PipelineConfig:
    """Tunable knobs for the auto-pentest run."""

    # Nmap profile used in stage 3
    nmap_profile: str = "service"
    # Nuclei severity filter
    nuclei_severity: str = "low,medium,high,critical"
    # Maximum subdomains to HTTP-probe (avoid blasting huge attack surfaces)
    max_http_targets: int = 50
    # Maximum live hosts to port-scan
    max_nmap_targets: int = 10
    # Maximum live web targets to run nuclei against
    max_nuclei_targets: int = 20
    # Maximum live web targets to dir-bust
    max_dirbust_targets: int = 5
    # Whether to attempt DNS zone transfer
    dns_zone_transfer: bool = True
    # Maximum discovered hosts to check for subdomain takeover
    max_takeover_targets: int = 25
    # Maximum parameterized URLs to run active injection testing against (raised
    # from the old hard-coded 3; still bounded for safety/resources).
    max_injection_targets: int = 10
    # Maximum parameterized URLs to run SSRF detection/validation against.
    max_ssrf_targets: int = 5
    # Operator-supplied authenticated-session config for the authenticated crawl
    # stage (cookie / auth_header / username+password / login_url). TRANSIENT —
    # carried only in-memory for the run and never persisted. Empty => the
    # authenticated stage is skipped and the pipeline runs exactly as before.
    auth: dict | None = None
    # Optional list of >=2 operator-authorized identities ({label, cookie,
    # auth_header}) enabling cross-user IDOR validation. TRANSIENT — never
    # persisted. Fewer than 2 => IDOR stays suspected-only / skipped.
    auth_identities: list | None = None


STAGE_NAMES = {
    1: "WHOIS Lookup",
    2: "Subdomain Enumeration",
    3: "HTTP Probe",
    4: "Port Scan",
    5: "Tech Fingerprinting",
    6: "Vulnerability Scan",
    7: "Content Discovery",
    8: "DNS Zone Transfer",
    9: "Origin Discovery",
    10: "Deep Crawl",
    11: "Web Audit",
    12: "Injection Scan",
    13: "WAF Test",
    14: "Subdomain Takeover",
    15: "SSRF Probe",
    16: "IDOR / Authorization",
    17: "JWT / API Security",
    18: "CSRF Check",
    19: "Business Logic",
    20: "Summary",
}

#: The final Summary stage number (kept as a name so front/back stay in sync).
SUMMARY_STAGE = 20


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _clean(value: str) -> str:
    """Strip scheme and trailing slash from a target."""
    v = (value or "").strip()
    v = v.replace("https://", "").replace("http://", "")
    return v.split("/")[0].strip()


def _has_auth(auth: dict | None) -> bool:
    """True when the operator supplied a usable authenticated session.

    Requires a cookie, an auth header, or a username+password pair. Anything
    else (including an all-empty dict) means "no auth" and the authenticated
    crawl stage is skipped, leaving unauthenticated behaviour unchanged.
    """
    if not auth:
        return False
    return bool(
        (auth.get("cookie") or "").strip()
        or (auth.get("auth_header") or "").strip()
        or ((auth.get("username") or "").strip() and (auth.get("password") or "").strip())
    )


def _extract_subdomains(result: dict | None) -> list[str]:
    if not result:
        return []
    return result.get("subdomains") or []


def _extract_live_urls(result: dict | None) -> list[str]:
    if not result:
        return []
    return [r["url"] for r in (result.get("rows") or []) if r.get("url")]


def _extract_live_hosts(result: dict | None) -> list[str]:
    if not result:
        return []
    return [r.get("host") or _clean(r.get("url", "")) for r in (result.get("rows") or []) if r.get("url")]


def _drain(
    gen: Iterator[dict],
    cancel: threading.Event,
    stage: int,
    queue: asyncio.Queue,
    loop: asyncio.AbstractEventLoop,
) -> dict | None:
    """Drain a scanner generator, pumping events into *queue*.

    Returns the final ``result`` data dict (or ``None`` if no result was
    produced or the scan was cancelled).
    """
    result_data = None
    # STEP 4 resilience: isolate a scanner that RAISES (as opposed to the
    # disciplined path of emitting an {"type":"error"} event). Without this, one
    # raising scanner propagates out to the single run-wide handler and aborts
    # every remaining stage (no Summary, no pipeline_done). Catching here turns a
    # raise into a stage-scoped error line, exactly like an emitted error event,
    # so the pipeline continues to the next stage.
    try:
        for ev in gen:
            if cancel.is_set():
                break
            kind = ev.get("type")
            if kind == "log":
                loop.call_soon_threadsafe(
                    queue.put_nowait,
                    {"type": "pipeline_log", "stage": stage, "data": ev["data"]},
                )
            elif kind == "result":
                result_data = ev.get("data")
            elif kind == "error":
                loop.call_soon_threadsafe(
                    queue.put_nowait,
                    {"type": "pipeline_log", "stage": stage, "data": f"⚠ {ev['data']}"},
                )
            # returncode events are silently swallowed
    except Exception as exc:  # noqa: BLE001 - one raising scanner must not abort the run
        logger.warning("pipeline stage %s scanner raised: %s", stage, exc)
        loop.call_soon_threadsafe(
            queue.put_nowait,
            {"type": "pipeline_log", "stage": stage, "data": f"⚠ stage error: {exc}"},
        )
    return result_data


# --------------------------------------------------------------------------- #
# Public streaming entrypoint
# --------------------------------------------------------------------------- #

async def run_pipeline(
    target: str,
    *,
    cancel: threading.Event | None = None,
    config: PipelineConfig | None = None,
    workspace_id: int | None = None,
    created_by: int | None = None,
    scope_list: list | None = None,
    persist: "callable | None" = None,
) -> AsyncIterator[dict[str, Any]]:
    """Async generator that streams the full automated pentest pipeline.

    Yields event dicts suitable for forwarding directly over a WebSocket.

    Parameters
    ----------
    scope_list:
        The engagement's authorized scope (list of domains/wildcards/IPs/CIDRs,
        as accepted by :func:`app.scope.check`). After subdomain enumeration,
        every discovered host is filtered against this list — hosts that are not
        in scope are dropped (and a log line is emitted) so the pipeline never
        touches an out-of-scope target. An empty/``None`` scope means
        unrestricted and keeps every discovered host.
    persist:
        Optional ``persist(record: dict) -> None`` callback invoked once per
        per-tool result so the caller can save it (e.g. via
        :func:`app.crud.save_scan`, which also derives Findings). The callback
        is wrapped so it can never raise into the pipeline. When ``None`` no
        persistence happens and streaming behavior is byte-identical to a run
        with neither ``scope_list`` nor ``persist`` supplied.
    """
    if cancel is None:
        cancel = threading.Event()
    if config is None:
        config = PipelineConfig()

    domain = _clean(target)
    loop = asyncio.get_running_loop()
    queue: asyncio.Queue = asyncio.Queue()
    sentinel = object()

    # Collected data passed between stages
    ctx: dict[str, Any] = {
        "domain": domain,
        "subdomains": [],
        "live_urls": [],
        "live_hosts": [],
        "all_findings": [],
        "stage_results": {},
    }

    def emit_stage(stage: int, status: str) -> None:
        loop.call_soon_threadsafe(
            queue.put_nowait,
            {
                "type": "pipeline_stage",
                "stage": stage,
                "name": STAGE_NAMES.get(stage, f"Stage {stage}"),
                "status": status,
            },
        )

    def emit_result(stage: int, data: Any) -> None:
        loop.call_soon_threadsafe(
            queue.put_nowait,
            {
                "type": "pipeline_result",
                "stage": stage,
                "name": STAGE_NAMES.get(stage, f"Stage {stage}"),
                "data": data,
            },
        )

    def do_persist(tool: str, tool_target: str, result_data: Any) -> None:
        """Persist a single per-tool result via the caller's callback.

        A no-op when ``persist`` is ``None`` or there is no result. The call is
        wrapped so a persistence failure can never abort the pipeline — it is
        surfaced as a warning log line instead.
        """
        if persist is None or result_data is None:
            return
        record = {
            "tool": tool,
            "target": tool_target,
            "status": "done",
            "options": {},
            "logs": [],
            "result": result_data,
            "started_at": _now(),
            "finished_at": _now(),
        }
        try:
            persist(record)
        except Exception as exc:  # noqa: BLE001 — persistence must never crash a run
            loop.call_soon_threadsafe(
                queue.put_nowait,
                {
                    "type": "pipeline_log",
                    "stage": 0,
                    "data": f"⚠ Failed to persist {tool} result for {tool_target}: {exc}",
                },
            )

    def worker() -> None:
        """Run all pipeline stages in a thread."""
        try:
            # ---------------------------------------------------------------- #
            # Stage 1 — WHOIS
            # ---------------------------------------------------------------- #
            emit_stage(1, "started")
            whois_result = _drain(
                whois_lookup.stream(domain, cancel=cancel),
                cancel, 1, queue, loop,
            )
            if cancel.is_set():
                return
            ctx["stage_results"][1] = whois_result
            if whois_result:
                emit_result(1, whois_result)
                do_persist("whois", domain, whois_result)
            emit_stage(1, "done")

            # ---------------------------------------------------------------- #
            # Stage 2 — Subdomain Enumeration
            # ---------------------------------------------------------------- #
            emit_stage(2, "started")
            sub_result = _drain(
                subdomain.stream(domain, cancel=cancel),
                cancel, 2, queue, loop,
            )
            if cancel.is_set():
                return
            ctx["stage_results"][2] = sub_result
            subs = _extract_subdomains(sub_result)
            # Always include the root domain in the candidate set.
            all_targets = sorted(set([domain] + subs))

            # ---- Scope + SSRF/egress enforcement on every discovered host - #
            # TWO independent gates, both applied to the root domain AND every
            # subfinder-discovered host:
            #   * scope.check   — engagement legality (skipped when scope is empty)
            #   * netguard      — egress SAFETY; ALWAYS runs, even with an empty or
            #     "*" scope, so the pipeline can never be pointed at loopback,
            #     RFC-1918, link-local, or the cloud metadata endpoint. This closes
            #     the SSRF hole where a discovered/attacker-controlled host resolves
            #     to an internal IP (DNS-rebinding) — scope authorizes, netguard
            #     enforces reachability, and you need both.
            from . import netguard as _netguard

            allowed_hosts: list[str] = []
            for host in all_targets:
                if scope_list:
                    ok, _reason = scope_mod.check(host, scope_list)
                    if not ok:
                        loop.call_soon_threadsafe(
                            queue.put_nowait,
                            {"type": "pipeline_log", "stage": 2,
                             "data": f"out of scope — skipping {host}"},
                        )
                        continue
                safe, nreason = _netguard.validate_target(host)
                if not safe:
                    loop.call_soon_threadsafe(
                        queue.put_nowait,
                        {"type": "pipeline_log", "stage": 2,
                         "data": f"blocked (egress guard) — skipping {host}: {nreason}"},
                    )
                    continue
                allowed_hosts.append(host)
            all_targets = allowed_hosts

            ctx["subdomains"] = all_targets
            if sub_result:
                emit_result(2, sub_result)
                do_persist("subdomains", domain, sub_result)
            emit_stage(2, "done")

            if not all_targets:
                # Everything discovered was out of scope → nothing to probe.
                loop.call_soon_threadsafe(
                    queue.put_nowait,
                    {
                        "type": "pipeline_log",
                        "stage": 2,
                        "data": "⚠ No in-scope hosts to probe. Skipping remaining stages.",
                    },
                )
                _finish(ctx, cancel, loop, queue)
                return

            # ---------------------------------------------------------------- #
            # Stage 3 — HTTP Probe (discover live hosts + URLs)
            # ---------------------------------------------------------------- #
            probe_targets = all_targets[: config.max_http_targets]
            emit_stage(3, "started")
            loop.call_soon_threadsafe(
                queue.put_nowait,
                {
                    "type": "pipeline_log",
                    "stage": 3,
                    "data": f"Probing {len(probe_targets)} host(s)...",
                },
            )
            httpx_result = _drain(
                httpx_probe.stream(",".join(probe_targets), cancel=cancel),
                cancel, 3, queue, loop,
            )
            if cancel.is_set():
                return
            ctx["stage_results"][3] = httpx_result
            ctx["live_urls"] = _extract_live_urls(httpx_result)
            ctx["live_hosts"] = _extract_live_hosts(httpx_result)
            if httpx_result:
                emit_result(3, httpx_result)
                do_persist("httpx", domain, httpx_result)
            emit_stage(3, "done")

            if not ctx["live_urls"]:
                # No live hosts → skip remaining stages
                loop.call_soon_threadsafe(
                    queue.put_nowait,
                    {
                        "type": "pipeline_log",
                        "stage": 3,
                        "data": "⚠ No live hosts found. Skipping remaining stages.",
                    },
                )
                _finish(ctx, cancel, loop, queue)
                return

            # ---------------------------------------------------------------- #
            # Stage 4 — Port Scan on first N live hosts
            # ---------------------------------------------------------------- #
            emit_stage(4, "started")
            nmap_targets = ctx["live_hosts"][: config.max_nmap_targets]
            nmap_results = []
            for host in nmap_targets:
                if cancel.is_set():
                    break
                loop.call_soon_threadsafe(
                    queue.put_nowait,
                    {"type": "pipeline_log", "stage": 4, "data": f"Port scanning {host}..."},
                )
                r = _drain(
                    nmap_scan.stream(host, scan_type=config.nmap_profile, cancel=cancel),
                    cancel, 4, queue, loop,
                )
                if r:
                    nmap_results.append(r)
                    do_persist("nmap", host, r)
            if cancel.is_set():
                return
            ctx["stage_results"][4] = nmap_results
            if nmap_results:
                emit_result(4, {"hosts": nmap_results})
            emit_stage(4, "done" if not cancel.is_set() else "stopped")

            # ---------------------------------------------------------------- #
            # Stage 5 — Tech Fingerprinting
            # ---------------------------------------------------------------- #
            emit_stage(5, "started")
            tech_results = []
            for url in ctx["live_urls"][:10]:
                if cancel.is_set():
                    break
                r = _drain(
                    techdetect.stream(url, cancel=cancel),
                    cancel, 5, queue, loop,
                )
                if r:
                    tech_results.append(r)
                    do_persist("tech", r.get("url") or url, r)
            if cancel.is_set():
                return
            ctx["stage_results"][5] = tech_results
            if tech_results:
                emit_result(5, {"tech_profiles": tech_results})
            emit_stage(5, "done")

            # ---------------------------------------------------------------- #
            # Stage 6 — Vulnerability Scan (nuclei)
            # ---------------------------------------------------------------- #
            emit_stage(6, "started")
            nuclei_targets = ctx["live_urls"][: config.max_nuclei_targets]
            combined_target = " ".join(nuclei_targets)
            loop.call_soon_threadsafe(
                queue.put_nowait,
                {
                    "type": "pipeline_log",
                    "stage": 6,
                    "data": f"Running nuclei against {len(nuclei_targets)} target(s)...",
                },
            )
            nuclei_result = _drain(
                nuclei_scan.stream(
                    combined_target,
                    severity=config.nuclei_severity,
                    cancel=cancel,
                ),
                cancel, 6, queue, loop,
            )
            if cancel.is_set():
                return
            ctx["stage_results"][6] = nuclei_result
            if nuclei_result:
                ctx["all_findings"].extend(nuclei_result.get("findings") or [])
                emit_result(6, nuclei_result)
                do_persist("nuclei", combined_target, nuclei_result)
            emit_stage(6, "done")

            # ---------------------------------------------------------------- #
            # Stage 7 — Content Discovery (ffuf) on first N web targets
            # ---------------------------------------------------------------- #
            emit_stage(7, "started")
            dirbust_targets = ctx["live_urls"][: config.max_dirbust_targets]
            dirbust_results = []
            for url in dirbust_targets:
                if cancel.is_set():
                    break
                loop.call_soon_threadsafe(
                    queue.put_nowait,
                    {"type": "pipeline_log", "stage": 7, "data": f"Directory busting {url}..."},
                )
                r = _drain(
                    dirbuster.stream(url, cancel=cancel),
                    cancel, 7, queue, loop,
                )
                if r:
                    dirbust_results.append(r)
                    do_persist("dirbuster", r.get("target") or url, r)
            if cancel.is_set():
                return
            ctx["stage_results"][7] = dirbust_results
            if dirbust_results:
                emit_result(7, {"targets": dirbust_results})
            emit_stage(7, "done")

            # ---------------------------------------------------------------- #
            # Stage 8 — DNS Zone Transfer (optional)
            # ---------------------------------------------------------------- #
            if config.dns_zone_transfer:
                emit_stage(8, "started")
                zt_result = _drain(
                    dns_zt_stream(domain, cancel=cancel),
                    cancel, 8, queue, loop,
                )
                if not cancel.is_set():
                    ctx["stage_results"][8] = zt_result
                    if zt_result:
                        emit_result(8, zt_result)
                        # Persist so a SUCCESSFUL AXFR (a validated finding) reaches
                        # the findings register / risk / report instead of being
                        # dropped. derive_findings only emits a finding when the
                        # transfer actually succeeded (vulnerable=True).
                        do_persist("dns_zt", domain, zt_result)
                    emit_stage(8, "done")
            else:
                emit_stage(8, "skipped")

            def _plog(stage: int, msg: str) -> None:
                loop.call_soon_threadsafe(
                    queue.put_nowait,
                    {"type": "pipeline_log", "stage": stage, "data": msg},
                )

            def _host_allowed(u: str) -> bool:
                """Scope + egress gate for a discovered URL before active testing."""
                host = _clean(u)
                if scope_list and not scope_mod.check(host, scope_list)[0]:
                    return False
                return _netguard.validate_target(host)[0]

            # ---------------------------------------------------------------- #
            # Stage 9 — Origin Discovery (find the real server behind a CDN/WAF)
            # ---------------------------------------------------------------- #
            emit_stage(9, "started")
            origin_result = _drain(
                origin_discovery.stream(domain, cancel=cancel), cancel, 9, queue, loop,
            )
            if cancel.is_set():
                return
            ctx["stage_results"][9] = origin_result
            if origin_result:
                emit_result(9, origin_result)
                do_persist("origin", domain, origin_result)
            emit_stage(9, "done")

            # ---------------------------------------------------------------- #
            # Stage 10 — Deep Crawl + hidden-parameter discovery (primary site).
            # Runs the UNauthenticated crawl always, and an AUTHENTICATED crawl
            # additionally when the operator supplied an authorized session — the
            # authenticated attack surface is fed into the injection stage. Each
            # discovered parameterized URL keeps its discovery source so findings
            # can show whether the endpoint was authenticated.
            # ---------------------------------------------------------------- #
            emit_stage(10, "started")
            crawl_seed = ctx["live_urls"][:1] or ([f"https://{domain}"] if domain else [])
            param_entries: list[dict] = []  # {url, source, method, authenticated}
            discovered_urls: list[str] = []  # for IDOR (id-bearing) discovery
            api_endpoints: list[str] = []    # for JWT/API auth checks
            forms_all: list[dict] = []       # {action, method, inputs} for POST injection
            crawl_result = None

            def _add_params(items, source: str, authenticated: bool) -> None:
                for p in (items or []):
                    u = p.get("url")
                    if u:
                        param_entries.append({
                            "url": u, "source": source, "method": "GET",
                            "authenticated": authenticated,
                        })
                        discovered_urls.append(u)

            bizlogic_sources: list[dict] = []  # crawl/auth_crawl results for the workflow model
            for url in crawl_seed:
                if cancel.is_set():
                    break
                crawl_result = _drain(crawl.stream(url, cancel=cancel), cancel, 10, queue, loop)
                if crawl_result:
                    _add_params(crawl_result.get("parameterized_urls"), "crawl", False)
                    discovered_urls.extend(crawl_result.get("urls") or [])
                    bizlogic_sources.append({**crawl_result, "authenticated": False})
                    do_persist("crawl", url, crawl_result)

            # Authenticated crawl — ONLY when the operator supplied an authorized
            # session (cookie / auth header / credentials). Unauthenticated runs
            # skip this entirely and behave exactly as before.
            if _has_auth(config.auth):
                _plog(10, "Authenticated crawl (operator-supplied session)…")
                for url in crawl_seed:
                    if cancel.is_set():
                        break
                    ac = _drain(
                        auth_crawl.stream(url, cancel=cancel, **config.auth),
                        cancel, 10, queue, loop,
                    )
                    if ac:
                        _add_params(ac.get("parameterized_urls"), "auth_crawl",
                                    bool(ac.get("authenticated")))
                        discovered_urls.extend(ac.get("urls") or [])
                        api_endpoints.extend(ac.get("api_endpoints") or [])
                        forms_all.extend(ac.get("forms") or [])
                        bizlogic_sources.append(ac)
                        do_persist("auth_crawl", url, ac)

            ctx["param_entries"] = param_entries
            ctx["discovered_urls"] = discovered_urls
            ctx["api_endpoints"] = api_endpoints
            ctx["forms"] = forms_all
            ctx["bizlogic_sources"] = bizlogic_sources

            if cancel.is_set():
                return
            ctx["stage_results"][10] = crawl_result
            if crawl_result:
                emit_result(10, crawl_result)
            emit_stage(10, "done")

            # ---------------------------------------------------------------- #
            # Stage 11 — Web Audit (headers / CORS / exposed files / TLS)
            # ---------------------------------------------------------------- #
            emit_stage(11, "started")
            audit_results = []
            for url in (ctx["live_urls"][: config.max_http_targets])[:8]:
                if cancel.is_set():
                    break
                r = _drain(webaudit.stream(url, cancel=cancel), cancel, 11, queue, loop)
                if r:
                    audit_results.append(r)
                    ctx["all_findings"].extend(r.get("findings") or [])
                    do_persist("webaudit", r.get("target") or url, r)
            if cancel.is_set():
                return
            ctx["stage_results"][11] = audit_results
            if audit_results:
                emit_result(11, {"audits": audit_results})
            emit_stage(11, "done")

            # ---------------------------------------------------------------- #
            # Stage 12 — Injection Scan (SQLi/XSS on discovered parameters)
            # ---------------------------------------------------------------- #
            emit_stage(12, "started")
            # De-dupe discovered URLs (keep the first source seen) and cap for
            # safety/resources — raised from the old hard-coded 3.
            seen_urls: dict[str, dict] = {}
            for e in param_entries:
                seen_urls.setdefault(e["url"], e)
            inj_candidates = list(seen_urls.values())[: config.max_injection_targets]
            inj_results = []
            if not inj_candidates:
                _plog(12, "No parameterized URLs discovered — skipping injection tests.")
            for entry in inj_candidates:
                if cancel.is_set():
                    break
                url = entry["url"]
                # EVERY discovered URL must pass scope + egress validation before
                # it is actively tested — crawl/auth_crawl can surface off-scope or
                # attacker-influenced URLs.
                host = _clean(url)
                if scope_list:
                    ok, _r = scope_mod.check(host, scope_list)
                    if not ok:
                        _plog(12, f"out of scope — skipping injection on {url}")
                        continue
                safe, _nr = _netguard.validate_target(host)
                if not safe:
                    _plog(12, f"blocked (egress guard) — skipping injection on {url}")
                    continue
                r = _drain(injection.stream(url, cancel=cancel), cancel, 12, queue, loop)
                if r:
                    # Annotate each finding with where the endpoint was discovered
                    # (authenticated vs. not) so the evidence is self-describing.
                    for f in (r.get("findings") or []):
                        ev = f.setdefault("evidence", {})
                        ev.setdefault("discovery_source", entry["source"])
                        ev.setdefault("http_method", entry["method"])
                        ev.setdefault("authenticated", entry["authenticated"])
                    inj_results.append(r)
                    ctx["all_findings"].extend(r.get("findings") or [])
                    do_persist("injection", r.get("target") or url, r)

            # Authenticated POST/form injection: test discovered forms' body
            # parameters (benign placeholder values; read-only sqlmap flags). GET
            # forms are already covered via parameterized URLs.
            for form in (ctx.get("forms") or [])[: config.max_injection_targets]:
                if cancel.is_set():
                    break
                action = form.get("action")
                fmethod = (form.get("method") or "GET").upper()
                inputs = [i for i in (form.get("inputs") or []) if i][:20]
                if fmethod == "GET" or not action or not inputs:
                    continue
                if not _host_allowed(action):
                    _plog(12, f"skipped (scope/egress) — form {action}")
                    continue
                body = "&".join(f"{n}=1" for n in inputs)
                r = _drain(
                    injection.stream(action, cancel=cancel, method=fmethod,
                                     data=body, content_type="form"),
                    cancel, 12, queue, loop,
                )
                if r:
                    for f in (r.get("findings") or []):
                        ev = f.setdefault("evidence", {})
                        ev.setdefault("discovery_source", "auth_crawl_form")
                        ev.setdefault("authenticated", True)
                    inj_results.append(r)
                    ctx["all_findings"].extend(r.get("findings") or [])
                    do_persist("injection", action, r)
            if cancel.is_set():
                return
            ctx["stage_results"][12] = inj_results
            if inj_results:
                emit_result(12, {"targets": inj_results})
            emit_stage(12, "done")

            # ---------------------------------------------------------------- #
            # Stage 13 — WAF Effectiveness Test
            # ---------------------------------------------------------------- #
            emit_stage(13, "started")
            waf_target = (ctx["live_urls"][:1] or [f"https://{domain}"])[0]
            waf_result = _drain(waf_test.stream(waf_target, cancel=cancel), cancel, 13, queue, loop)
            if not cancel.is_set():
                ctx["stage_results"][13] = waf_result
                if waf_result:
                    # WAF-effectiveness is a HARDENING signal, not a vulnerability —
                    # persist it (classified kind="hardening") but do NOT add it to
                    # the risk aggregation, so it never inflates the risk score.
                    emit_result(13, waf_result)
                    do_persist("waf", waf_target, waf_result)
                emit_stage(13, "done")

            # ---------------------------------------------------------------- #
            # Stage 14 — Subdomain Takeover (on discovered in-scope hosts)
            # ---------------------------------------------------------------- #
            emit_stage(14, "started")
            takeover_targets = ctx.get("subdomains", [])[: config.max_takeover_targets]
            takeover_results = []
            for host in takeover_targets:
                if cancel.is_set():
                    break
                # Defense in depth: re-run scope + egress guard before touching a
                # host (hosts were validated at stage 2, but DNS can change and a
                # takeover CNAME is exactly an SSRF-shaped risk).
                if scope_list:
                    ok, _r = scope_mod.check(host, scope_list)
                    if not ok:
                        continue
                safe, _nr = _netguard.validate_target(host)
                if not safe:
                    _plog(14, f"blocked (egress guard) — skipping {host}")
                    continue
                r = _drain(takeover.stream(host, cancel=cancel), cancel, 14, queue, loop)
                if r:
                    takeover_results.append(r)
                    ctx["all_findings"].extend(r.get("findings") or [])
                    do_persist("takeover", host, r)
            if cancel.is_set():
                return
            ctx["stage_results"][14] = takeover_results
            if takeover_results:
                emit_result(14, {"hosts": takeover_results})
            emit_stage(14, "done")

            # ---------------------------------------------------------------- #
            # Stage 15 — SSRF detection + safe reflective validation.
            # Tests SSRF-candidate parameters on discovered URLs; each URL passes
            # scope + netguard first and only in-scope canaries are ever used as
            # payloads (no internal-network probing).
            # ---------------------------------------------------------------- #
            emit_stage(15, "started")
            ssrf_urls, _seen = [], set()
            for e in ctx.get("param_entries", []):
                u = e.get("url")
                if not u or u in _seen:
                    continue
                _seen.add(u)
                q = parse_qsl(urlsplit(u).query, keep_blank_values=True)
                if any(ssrf._is_candidate(n, v) for n, v in q):
                    ssrf_urls.append(u)
            ssrf_results = []
            for u in ssrf_urls[: config.max_ssrf_targets]:
                if cancel.is_set():
                    break
                if not _host_allowed(u):
                    _plog(15, f"skipped (scope/egress) — {u}")
                    continue
                r = _drain(ssrf.stream(u, cancel=cancel), cancel, 15, queue, loop)
                if r:
                    ssrf_results.append(r)
                    ctx["all_findings"].extend(r.get("findings") or [])
                    do_persist("ssrf", u, r)
            if cancel.is_set():
                return
            ctx["stage_results"][15] = ssrf_results
            if ssrf_results:
                emit_result(15, {"targets": ssrf_results})
            emit_stage(15, "done")

            # ---------------------------------------------------------------- #
            # Stage 16 — IDOR / authorization (ONLY with >=2 authorized identities).
            # Read-only cross-user comparison on id-bearing in-scope URLs.
            # ---------------------------------------------------------------- #
            emit_stage(16, "started")
            identities = [
                i for i in (config.auth_identities or [])
                if isinstance(i, dict) and (i.get("cookie") or i.get("auth_header"))
            ]
            idor_results = []
            if len(identities) >= 2:
                cand, _seen_id = [], set()
                for u in ctx.get("discovered_urls", []):
                    if not u or u in _seen_id:
                        continue
                    _seen_id.add(u)
                    if idor._object_id(u) is not None and _host_allowed(u):
                        cand.append(u)
                    if len(cand) >= 15:
                        break
                if cand:
                    r = _drain(
                        idor.stream(",".join(cand), cancel=cancel, identities=identities),
                        cancel, 16, queue, loop,
                    )
                    if r:
                        idor_results.append(r)
                        ctx["all_findings"].extend(r.get("findings") or [])
                        do_persist("idor", cand[0], r)
                else:
                    _plog(16, "No id-bearing in-scope URLs discovered — skipping IDOR.")
            else:
                _plog(16, "IDOR needs ≥2 authorized identities — skipping.")
            if cancel.is_set():
                return
            ctx["stage_results"][16] = idor_results
            if idor_results:
                emit_result(16, {"targets": idor_results})
            emit_stage(16, "done")

            # ---------------------------------------------------------------- #
            # Stage 17 — JWT / API security (static token analysis + API-auth).
            # ---------------------------------------------------------------- #
            emit_stage(17, "started")
            auth_cfg = config.auth or {}
            api_eps, _seen_ep = [], set()
            for u in ctx.get("api_endpoints", []):
                if not u or u in _seen_ep:
                    continue
                _seen_ep.add(u)
                if _host_allowed(u):
                    api_eps.append(u)
                if len(api_eps) >= 15:
                    break
            has_token = bool(auth_cfg.get("token")) or "bearer" in (auth_cfg.get("auth_header") or "").lower()
            jwt_results = []
            if has_token or (api_eps and _has_auth(config.auth)):
                opts = {
                    "token": auth_cfg.get("token", ""),
                    "auth_header": auth_cfg.get("auth_header", ""),
                    "api_endpoints": api_eps,
                    "identity": {"cookie": auth_cfg.get("cookie", ""),
                                 "auth_header": auth_cfg.get("auth_header", "")},
                    # The token comes from the operator's active authorized session,
                    # so a weak config means the SERVER accepts it (validated).
                    "observed": True,
                }
                r = _drain(jwt_audit.stream(domain, cancel=cancel, **opts), cancel, 17, queue, loop)
                if r:
                    jwt_results.append(r)
                    ctx["all_findings"].extend(r.get("findings") or [])
                    do_persist("jwt", domain, r)
            else:
                _plog(17, "No token / authenticated API endpoints to audit — skipping JWT/API.")
            if cancel.is_set():
                return
            ctx["stage_results"][17] = jwt_results
            if jwt_results:
                emit_result(17, {"targets": jwt_results})
            emit_stage(17, "done")

            # ---------------------------------------------------------------- #
            # Stage 18 — CSRF (on discovered authenticated state-changing forms).
            # ---------------------------------------------------------------- #
            emit_stage(18, "started")
            csrf_id_headers = {}
            _ac = config.auth or {}
            if (_ac.get("cookie") or "").strip():
                csrf_id_headers["Cookie"] = _ac["cookie"].strip()
            if (_ac.get("auth_header") or "").strip():
                ah = _ac["auth_header"].strip()
                if ":" in ah:
                    _n, _, _v = ah.partition(":")
                    csrf_id_headers[_n.strip()] = _v.strip()
                else:
                    csrf_id_headers["Authorization"] = ah
            csrf_results = []
            for form in (ctx.get("forms") or [])[: config.max_injection_targets]:
                if cancel.is_set():
                    break
                action = form.get("action")
                fmethod = (form.get("method") or "GET").upper()
                if fmethod not in ("POST", "PUT", "PATCH", "DELETE") or not action:
                    continue
                if not _host_allowed(action):
                    _plog(18, f"skipped (scope/egress) — {action}")
                    continue
                r = _drain(
                    csrf.stream(action, cancel=cancel, method=fmethod,
                                inputs=form.get("inputs") or [], identity_headers=csrf_id_headers),
                    cancel, 18, queue, loop,
                )
                if r:
                    csrf_results.append(r)
                    ctx["all_findings"].extend(r.get("findings") or [])
                    do_persist("csrf", action, r)
            if cancel.is_set():
                return
            ctx["stage_results"][18] = csrf_results
            if csrf_results:
                emit_result(18, {"targets": csrf_results})
            emit_stage(18, "done")

            # ---------------------------------------------------------------- #
            # Stage 19 — Business-logic foundation (workflow model + SIGNALs).
            # Pure analysis of the discovered model — no network, no transactions.
            # ---------------------------------------------------------------- #
            emit_stage(19, "started")
            biz_model = bizlogic.build_model(ctx.get("bizlogic_sources") or [])
            biz_findings = bizlogic.analyze(biz_model)
            if biz_findings:
                ctx["all_findings"].extend(biz_findings)
                do_persist("bizlogic", domain, {"findings": biz_findings, "model": biz_model})
                _plog(19, f"{len(biz_findings)} business-logic signal(s) for review "
                          f"(informational — not risk-scored).")
            else:
                _plog(19, "No suspicious workflow patterns detected.")
            ctx["stage_results"][19] = {"model": biz_model, "findings": biz_findings}
            emit_result(19, {"model": biz_model, "findings": biz_findings})
            emit_stage(19, "done")

            # ---------------------------------------------------------------- #
            # Stage 20 — Summary
            # ---------------------------------------------------------------- #
            _finish(ctx, cancel, loop, queue)

        except Exception as exc:  # noqa: BLE001 — surface pipeline crashes
            logger.error("pipeline run crashed: %s", exc)
            # Human-readable log line AND a typed terminal error so the client (and
            # the persistence layer) can distinguish a crash from routine output
            # and from a user Stop.
            loop.call_soon_threadsafe(
                queue.put_nowait,
                {"type": "pipeline_log", "stage": 0, "data": f"Pipeline error: {exc}"},
            )
            loop.call_soon_threadsafe(
                queue.put_nowait,
                {"type": "error", "stage": 0, "data": f"Pipeline error: {exc}"},
            )
        finally:
            loop.call_soon_threadsafe(queue.put_nowait, sentinel)

    future = loop.run_in_executor(None, worker)
    try:
        while True:
            event = await queue.get()
            if event is sentinel:
                break
            yield event
    finally:
        cancel.set()
        await future


def _finish(ctx: dict, cancel: threading.Event, loop: asyncio.AbstractEventLoop, queue: asyncio.Queue) -> None:
    """Compute the risk score and emit the pipeline_done event."""
    emit_stage_fn = lambda stage, status: loop.call_soon_threadsafe(
        queue.put_nowait,
        {"type": "pipeline_stage", "stage": stage, "name": STAGE_NAMES.get(stage, "Summary"), "status": status},
    )
    emit_stage_fn(SUMMARY_STAGE, "started")

    findings = ctx.get("all_findings") or []
    severity_counts: dict[str, int] = {}
    for f in findings:
        sev = (f.get("severity") or "info").lower()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    # Unified scorer — the SAME function the /risk endpoint and pipeline_ws use,
    # so the pipeline summary and the workspace risk can never disagree. This is
    # a LIVE estimate over the in-memory findings; pipeline_ws recomputes the
    # authoritative score from the persisted, deduplicated findings when the run
    # is saved.
    _r = risk_mod.workspace_risk(findings)
    risk_score = _r["score"]
    risk_label = _r["rating"].upper()

    summary = {
        "target": ctx["domain"],
        "subdomains_found": len(ctx.get("subdomains", [])),
        "live_hosts": len(ctx.get("live_urls", [])),
        "total_findings": len(findings),
        "severity_counts": severity_counts,
        "risk_score": risk_score,
        "risk_label": risk_label,
        "finished_at": _now(),
    }

    loop.call_soon_threadsafe(
        queue.put_nowait,
        {"type": "pipeline_done", "risk_score": risk_score, "risk_label": risk_label, "summary": summary},
    )
    emit_stage_fn(SUMMARY_STAGE, "done")

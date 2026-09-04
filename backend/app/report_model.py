"""Reporting V2 — finding classification, correlation, coverage and QC.

This is a pure, side-effect-free layer that sits BETWEEN persisted findings and
the HTML renderer (:mod:`app.report`). It does NOT change detection: it only
reads the fields the scanners already produced — ``severity``, ``detection_tier``
(signal|validated|exploited), ``kind`` (vuln|hardening|recon|info),
``confidence`` (0-100), ``evidence`` — and turns them into an honest, deduplicated
assessment model.

Core principle enforced here:  SEVERITY != STATUS != CONFIDENCE.
A ``vuln`` finding at ``detection_tier="signal"`` (e.g. a "Possible IDOR" with a
single identity) is a **Potential** finding, never a Confirmed vulnerability —
regardless of its severity. Confirmation comes only from ``validated``/
``exploited`` tiers, exactly as the scanners assign them.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

SEV_ORDER = ["critical", "high", "medium", "low", "info"]
_SEV_RANK = {s: i for i, s in enumerate(SEV_ORDER)}

# ---- Status vocabulary (independent of severity) --------------------------- #
STATUS_CONFIRMED = "Confirmed"
STATUS_LIKELY = "Likely"
STATUS_POTENTIAL = "Potential"
STATUS_INCONCLUSIVE = "Inconclusive"
STATUS_HARDENING = "Hardening"
STATUS_INFORMATIONAL = "Informational"

# Which statuses count as a real (confirmed) vulnerability vs. an unconfirmed
# signal vs. a hardening/informational observation.
_CONFIRMED = {STATUS_CONFIRMED}
_UNCONFIRMED = {STATUS_LIKELY, STATUS_POTENTIAL, STATUS_INCONCLUSIVE}


def classify(f: dict) -> str:
    """Return the reporting STATUS for a finding from its kind/tier/confidence.

    Never infers confirmation from severity. Mirrors the scanners' own tiers:
    a ``vuln`` finding is Confirmed only when the scanner validated it.
    """
    kind = (f.get("kind") or "vuln").strip().lower()
    if kind in ("recon", "info"):
        return STATUS_INFORMATIONAL
    if kind == "hardening":
        return STATUS_HARDENING
    tier = (f.get("detection_tier") or "signal").strip().lower()
    if tier in ("validated", "exploited"):
        return STATUS_CONFIRMED
    conf = f.get("confidence")
    conf = 50 if conf is None else int(conf)
    if conf >= 70:
        return STATUS_LIKELY
    if conf >= 40:
        return STATUS_POTENTIAL
    return STATUS_INCONCLUSIVE


def is_confirmed_vuln(status: str) -> bool:
    return status in _CONFIRMED


def is_unconfirmed(status: str) -> bool:
    return status in _UNCONFIRMED


# --------------------------------------------------------------------------- #
# Evidence redaction — never leak secrets into a shareable report.
# --------------------------------------------------------------------------- #
_SECRET_KEY_RE = re.compile(r"(pass|secret|token|authorization|auth|cookie|api[-_]?key|private[-_]?key|bearer)", re.I)

# --- Secret redaction for captured text (e.g. an exposed-file response body). --- #
# A scanner may legitimately capture a response body as proof (nuclei's `response`
# field for an exposed /.env or db_backup.sql). The body itself carries the very
# secrets the finding is about, so the REPORT must scrub them while keeping the
# non-secret structure (which key leaked, what kind of file) as useful evidence.

# 1) KEY=VALUE / KEY: VALUE where the KEY NAME implies a secret — keep the key and
#    delimiter, redact only the value (covers .env / config / JSON / query-string).
_SECRET_ASSIGN_RE = re.compile(
    r"([A-Za-z0-9_.\-]*"
    r"(?:secret|passwd|password|api[_-]?key|access[_-]?key|private[_-]?key|"
    r"app[_-]?key|secret[_-]?key|client[_-]?secret|auth[_-]?token|session|apikey|token)"
    r"[A-Za-z0-9_.\-]*"
    r"\"?\s*[:=]\s*\"?)"
    r"([^\s\"',}&]{4,})",
    re.I,
)
# 2) High-confidence provider TOKEN SHAPES, redacted wherever they appear (even
#    with no key), plus JWTs and Authorization: Bearer headers.
_TOKEN_SHAPE_RE = re.compile(
    r"(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{6,}"       # Stripe-style keys
    r"|AKIA[0-9A-Z]{16}"                                 # AWS access key id
    r"|gh[pousr]_[A-Za-z0-9]{20,}"                       # GitHub tokens
    r"|xox[baprs]-[A-Za-z0-9-]{10,}"                     # Slack tokens
    r"|AIza[0-9A-Za-z_\-]{20,}"                          # Google API key
    r"|eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}",  # JWT
)
_BEARER_RE = re.compile(r"(authorization:\s*bearer\s+)[A-Za-z0-9._~+/=-]{8,}", re.I)
# 3) PEM private-key blocks — redact the whole block.
_PEM_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----", re.I
)
# 4) Plaintext credentials in a SQL dump: redact the quoted literals inside an
#    INSERT INTO an identity/credential table (usernames, passwords, emails). Kept
#    conservative — only fires for tables whose name implies accounts/credentials.
_SQL_CRED_RE = re.compile(
    r"(insert\s+into\s+`?\w*"
    r"(?:user|account|credential|member|login|admin|password|customer)\w*`?\b[^;]*?\bvalues\b)"
    r"([^;]*)",
    re.I,
)
_SQL_QUOTED_RE = re.compile(r"'(?:[^'\\]|\\.)*'")


def _redact_text(s: str) -> str:
    """Scrub secrets from a free-text string, preserving non-secret structure."""
    s = _PEM_RE.sub("[REDACTED]", s)
    s = _BEARER_RE.sub(lambda m: m.group(1) + "[REDACTED]", s)
    s = _SECRET_ASSIGN_RE.sub(lambda m: m.group(1) + "[REDACTED]", s)
    s = _TOKEN_SHAPE_RE.sub("[REDACTED]", s)
    s = _SQL_CRED_RE.sub(
        lambda m: m.group(1) + _SQL_QUOTED_RE.sub("'[REDACTED]'", m.group(2)), s
    )
    return s


def redact(value):
    """Redact obvious secrets from an evidence value (str/dict/list), recursively."""
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            if isinstance(k, str) and _SECRET_KEY_RE.search(k) and isinstance(v, (str, int)):
                out[k] = "[REDACTED]"
            else:
                out[k] = redact(v)
        return out
    if isinstance(value, list):
        return [redact(v) for v in value]
    if isinstance(value, str):
        return _redact_text(value)
    return value


def _asset(loc: str) -> str:
    """Host (netloc) of a finding location, for per-asset grouping."""
    loc = str(loc or "")
    try:
        p = urlsplit(loc if "://" in loc else "//" + loc)
        return (p.netloc or p.path.split("/")[0] or loc).lower()
    except Exception:
        return loc.lower()


# --------------------------------------------------------------------------- #
# Class-specific remediation (Phase 6) — keyed by CWE, with a name fallback.
# --------------------------------------------------------------------------- #
_REMEDIATION_BY_CWE = {
    "CWE-89": ("SQL injection", "Use parameterized queries / prepared statements (never string-concatenate SQL); "
               "prefer safe ORM query builders; run the DB account at least privilege. Verify with a re-scan and a "
               "unit test that a quote/UNION payload no longer alters the query."),
    "CWE-79": ("Cross-site scripting", "Apply context-aware output encoding at every sink, use an auto-escaping "
               "template engine, validate input where feasible, and add Content-Security-Policy as defence-in-depth. "
               "Verify the reflected payload no longer executes."),
    "CWE-639": ("IDOR / broken object-level authorization", "Enforce server-side authorization on every object access: "
                "check the authenticated principal owns / is a member of the tenant for the requested object; deny by "
                "default; never rely on unguessable IDs as authorization. Add an authorization regression test that a "
                "second account is denied (403/404)."),
    "CWE-284": ("Broken access control", "Enforce deny-by-default server-side access control for every function and "
                "object; verify role/tenant on each request. Add regression tests for cross-user and cross-role access."),
    "CWE-862": ("Missing authorization", "Add an explicit authorization check on the endpoint; verify the caller is "
                "permitted for the specific object/action; test unauthorized and cross-tenant access are denied."),
    "CWE-285": ("Improper authorization", "Enforce function/method-level authorization server-side; test each role "
                "against each privileged action."),
    "CWE-918": ("SSRF", "Restrict outbound requests to a strict allowlist; block private/loopback/link-local and "
                "cloud-metadata ranges; resolve-and-validate the destination IP and re-validate on redirects; restrict "
                "protocols to http/https. Verify a metadata/internal URL is refused."),
    "CWE-601": ("Open redirect", "Do not build redirects from unvalidated input; use a server-side allowlist of "
                "permitted destinations or relative paths only. Verify an off-site target is not honored."),
    "CWE-352": ("CSRF", "Require an anti-CSRF token on every state-changing request and/or set SameSite=Strict/Lax on "
                "session cookies; validate the Origin/Referer. Verify a cross-site forged request is rejected."),
    "CWE-200": ("Information / file exposure", "Remove the exposed file/endpoint from the web root or restrict access; "
                "rotate any secrets it revealed; ensure backups/VCS metadata are never web-served. Verify it now 403/404s."),
    "CWE-538": ("Exposed sensitive file", "Remove or access-restrict the file; rotate exposed credentials; block the "
                "path at the web server. Verify it is no longer retrievable."),
    "CWE-489": ("Exposed debug/console endpoint", "Disable debug mode and the interactive console in production; "
                "block the path; ensure the framework runs with debug off. Verify the console is no longer reachable."),
    "CWE-1021": ("Clickjacking / frame protection", "Set X-Frame-Options: DENY (or SAMEORIGIN) and a "
                 "Content-Security-Policy frame-ancestors directive. Verify the page can no longer be framed cross-origin."),
    "CWE-693": ("Missing security header", "Add the appropriate response header with a sound policy (HSTS with a long "
                "max-age over HTTPS; a restrictive Content-Security-Policy; X-Content-Type-Options: nosniff). Verify the "
                "header is present on every response."),
    "CWE-614": ("Insecure cookie", "Set Secure, HttpOnly and SameSite on session cookies. Verify the Set-Cookie flags."),
    "CWE-942": ("Permissive CORS", "Do not reflect arbitrary Origins with Access-Control-Allow-Credentials: true; use a "
                "strict origin allowlist and avoid wildcard with credentials. Verify a foreign Origin is not reflected."),
    "CWE-306": ("Missing authentication", "Require authentication on the endpoint; deny anonymous access to sensitive "
                "functions/data. Verify an unauthenticated request is rejected (401)."),
    "CWE-350": ("Subdomain takeover", "Remove the dangling DNS record or re-claim the resource at the provider; audit "
                "all CNAMEs for unclaimed targets. Verify the record no longer points at an unowned resource."),
}


def remediation_for(f: dict) -> str:
    """Best class-specific remediation for a finding, else a severity-appropriate default."""
    if (f.get("remediation") or "").strip():
        return f["remediation"].strip()
    for c in f.get("cwe") or []:
        key = str(c).upper().strip()
        if key in _REMEDIATION_BY_CWE:
            return _REMEDIATION_BY_CWE[key][1]
    # name-based fallback for common classes without a CWE on the finding
    name = (f.get("name") or "").lower()
    if "idor" in name or "object-level" in name or "object identifier" in name:
        return _REMEDIATION_BY_CWE["CWE-639"][1]
    if "ssrf" in name or "server-side request forgery" in name:
        return _REMEDIATION_BY_CWE["CWE-918"][1]
    if "xss" in name or "cross-site scripting" in name:
        return _REMEDIATION_BY_CWE["CWE-79"][1]
    if "sql" in name:
        return _REMEDIATION_BY_CWE["CWE-89"][1]
    if "header" in name or "clickjack" in name:
        return _REMEDIATION_BY_CWE["CWE-693"][1]
    return ("Review the finding, confirm exploitability in context, apply the appropriate configuration or code fix, "
            "and verify closure with a targeted re-test.")


# --------------------------------------------------------------------------- #
# Coverage matrix (Phase 10): which test areas actually ran.
# area -> (scanner registry key, required external tool or None)
# --------------------------------------------------------------------------- #
COVERAGE_AREAS = [
    ("SQL Injection", "injection", "sqlmap"),
    ("Cross-Site Scripting (XSS)", "injection", "dalfox"),
    ("IDOR / BOLA", "idor", None),
    ("Broken Access Control", "role_matrix", None),
    ("Authentication / JWT / API", "jwt", None),
    ("SSRF", "ssrf", None),
    ("Open Redirect", "open_redirect", None),
    ("CSRF", "csrf", None),
    ("Exposed Files / Secrets", "webaudit", None),
    ("Security Headers & Cookies", "webaudit", None),
    ("CORS", "webaudit", None),
    ("Content Discovery", "dirbuster", "ffuf"),
    ("Templated CVE / Misconfig (nuclei)", "nuclei", "nuclei"),
    ("Ports / Services", "nmap", "nmap"),
    ("Subdomain Enumeration", "subdomains", "subfinder"),
    ("DNS Zone Transfer", "dns_zt", None),
    ("Subdomain Takeover", "takeover", None),
    ("Origin Discovery", "origin", None),
    ("WAF Detection", "waf", None),
]


def _coverage(scanners_run: set, tools: dict | None, area_has_confirmed: dict,
              area_has_signal: dict, failed_scanners: set | None = None) -> list:
    tools = tools or {}
    failed_scanners = failed_scanners or set()
    rows = []
    for area, scanner, tool in COVERAGE_AREAS:
        if scanner not in scanners_run:
            rows.append({"area": area, "status": "NOT TESTED", "result": "Scanner not run",
                         "limitation": f"{scanner} stage did not run in this engagement"})
        elif tool is not None and tools and tools.get(tool) is False:
            rows.append({"area": area, "status": "NOT TESTED", "result": "Tool unavailable",
                         "limitation": f"{tool} not installed on the scan host"})
        elif area_has_confirmed.get(area):
            # A confirmed finding is proof the scanner did useful work here, even if
            # another run of it errored — so this wins over the failed-scan guard.
            rows.append({"area": area, "status": "TESTED", "result": "Finding(s) confirmed", "limitation": ""})
        elif area_has_signal.get(area):
            rows.append({"area": area, "status": "PARTIAL", "result": "Candidate(s) detected — not validated",
                         "limitation": "Requires manual/second-identity/OAST validation"})
        elif scanner in failed_scanners:
            # The scanner ran but every run errored AND produced no finding for this
            # area — results are unavailable, so it must NOT read as clean. Distinct
            # from "No finding".
            rows.append({"area": area, "status": "NOT TESTED", "result": "Scan failed",
                         "limitation": f"the {scanner} scan errored; results unavailable — treat as not tested"})
        else:
            rows.append({"area": area, "status": "TESTED", "result": "No finding", "limitation": ""})
    return rows


# Map a finding to the coverage area(s) it belongs to (best-effort, by CWE/name).
def _areas_for(f: dict) -> list:
    name = (f.get("name") or "").lower()
    cwe = {str(c).upper() for c in (f.get("cwe") or [])}
    out = []
    if "idor" in name or "object-identifier" in name or cwe & {"CWE-639", "CWE-284"}:
        out.append("IDOR / BOLA")
    if "ssrf" in name or "server-side request forgery" in name or "CWE-918" in cwe:
        out.append("SSRF")
    if "xss" in name or "cross-site scripting" in name or "CWE-79" in cwe:
        out.append("Cross-Site Scripting (XSS)")
    if "sql injection" in name or "CWE-89" in cwe:
        out.append("SQL Injection")
    if "open redirect" in name or "CWE-601" in cwe:
        out.append("Open Redirect")
    if "csrf" in name or "CWE-352" in cwe:
        out.append("CSRF")
    if "takeover" in name or "CWE-350" in cwe:
        out.append("Subdomain Takeover")
    if "zone transfer" in name:
        out.append("DNS Zone Transfer")
    if "cors" in name or "CWE-942" in cwe:
        out.append("CORS")
    if "header" in name or "clickjack" in name or cwe & {"CWE-693", "CWE-1021", "CWE-614"}:
        out.append("Security Headers & Cookies")
    if "exposed" in name or cwe & {"CWE-200", "CWE-538", "CWE-489"}:
        out.append("Exposed Files / Secrets")
    return out


def _dedupe_key(f: dict) -> tuple:
    return (
        (f.get("name") or "").strip().lower(),
        _asset(f.get("location")),
        (f.get("detection_tier") or "").lower(),
        tuple(sorted(str(c).upper() for c in (f.get("cwe") or []))),
    )


def build_model(project: dict, findings: list, scans: list,
                tools: dict | None = None,
                coverage: dict | None = None,
                triage: dict | None = None) -> dict:
    """Build the honest assessment model consumed by the renderer.

    ``tools`` is an optional tool-availability map (e.g. ``preflight.check_tools``'s
    ``required``+``optional`` merged) used only to mark coverage areas whose tool is
    absent as NOT TESTED. ``coverage`` is the purple ATT&CK payload (rendered only
    when it actually contains emulated techniques). ``triage`` is the AI-triage
    payload (rendered only when actually enabled).
    """
    from .severity import normalize_severity

    # Normalize + classify, dedupe within the report.
    seen = set()
    norm = []
    for f in findings or []:
        g = dict(f)
        g["severity"] = normalize_severity(g.get("severity"))
        g["_status"] = classify(g)
        key = _dedupe_key(g)
        if key in seen:
            continue
        seen.add(key)
        norm.append(g)

    confirmed, potential, hardening, informational = [], [], [], []
    for g in norm:
        st = g["_status"]
        if st == STATUS_CONFIRMED:
            confirmed.append(g)
        elif st in _UNCONFIRMED:
            potential.append(g)
        elif st == STATUS_HARDENING:
            hardening.append(g)
        else:
            informational.append(g)

    sevsort = lambda lst: sorted(lst, key=lambda x: _SEV_RANK.get(x.get("severity"), 9))
    confirmed, potential = sevsort(confirmed), sevsort(potential)

    def by_sev(lst):
        d = {s: 0 for s in SEV_ORDER}
        for x in lst:
            d[x.get("severity", "info")] = d.get(x.get("severity", "info"), 0) + 1
        return d

    # Coverage: which areas ran / were tested.
    scans_list = scans or []
    scanners_run = {(s.get("tool") or "").strip() for s in scans_list if s.get("tool")}
    # A scanner "succeeded" if it has >=1 run whose status is done/partial (or no
    # status at all — the DB default is 'done', and legacy callers omit it). A
    # scanner whose EVERY run errored/failed/is-still-running produced no usable
    # result, so its areas must not render as clean (false-clean guard).
    _OK_STATUS = {"done", "complete", "completed", "success", "ok", "partial", "finished"}
    scanner_ok: dict[str, bool] = {}
    for s in scans_list:
        t = (s.get("tool") or "").strip()
        if not t:
            continue
        st = (s.get("status") or "done").strip().lower()
        scanner_ok[t] = scanner_ok.get(t, False) or (st in _OK_STATUS)
    failed_scanners = {t for t in scanners_run if not scanner_ok.get(t, True)}
    area_conf, area_sig = {}, {}
    for g in confirmed:
        for a in _areas_for(g):
            area_conf[a] = True
    for g in potential:
        for a in _areas_for(g):
            area_sig[a] = True
    coverage_matrix = _coverage(scanners_run, tools, area_conf, area_sig, failed_scanners)
    not_tested = [r for r in coverage_matrix if r["status"] == "NOT TESTED"]

    # Aggregate hardening per (asset, finding-name) — one row per distinct condition.
    hard_agg = {}
    for g in hardening:
        k = (_asset(g.get("location")), (g.get("name") or "").strip())
        e = hard_agg.setdefault(k, {"asset": _asset(g.get("location")), "name": g.get("name", ""),
                                    "severity": g.get("severity", "low"), "cwe": g.get("cwe") or [],
                                    "count": 0, "remediation": remediation_for(g)})
        e["count"] += 1

    # Aggregate informational/recon per asset + name (attack-surface appendix).
    info_agg = {}
    for g in informational:
        k = (_asset(g.get("location")), (g.get("name") or "").strip())
        e = info_agg.setdefault(k, {"asset": _asset(g.get("location")), "name": g.get("name", ""), "count": 0})
        e["count"] += 1

    # Overall risk — from CONFIRMED vulnerabilities only (deterministic, documented).
    conf_counts = by_sev(confirmed)
    if conf_counts["critical"]:
        overall = "Critical"
    elif conf_counts["high"]:
        overall = "High"
    elif conf_counts["medium"]:
        overall = "Medium"
    elif conf_counts["low"]:
        overall = "Low"
    else:
        overall = "No confirmed findings"

    # ATT&CK present only if real emulated techniques exist.
    cov = coverage or {}
    attck_present = bool(cov.get("techniques"))
    # AI triage present only if it actually ran: either an explicit enabled flag,
    # or a persisted payload that carries prioritized items (the saved TriageOut
    # shape has items but no 'enabled' key). A disabled marker ({enabled:False,
    # reason:...}) with no items is treated as absent (section omitted).
    tri = triage or {}
    triage_present = bool(tri.get("enabled")) or bool(
        tri.get("top") or tri.get("findings") or tri.get("items")
    )

    # Scope honesty.
    scope = project.get("scope") or []

    # --- QC / contradiction checks (Phase 22) ------------------------------ #
    qc = []
    for g in confirmed:
        desc = (g.get("description") or "").lower()
        if any(p in desc for p in ("cannot be confirmed", "not proof", "unverified", "signal only", "possible ")):
            qc.append(f"Finding '{g.get('name','')}' is marked Confirmed but its description hedges — verify tier.")
        if g.get("cvss") is not None and not isinstance(g.get("cvss"), (int, float)):
            qc.append(f"Finding '{g.get('name','')}' has a non-numeric CVSS.")
    # confirmed count sanity
    return {
        "project": project,
        "scope": scope,
        "confirmed": confirmed,
        "potential": potential,
        "hardening": sorted(hard_agg.values(), key=lambda x: (_SEV_RANK.get(x["severity"], 9), x["asset"])),
        "informational": sorted(info_agg.values(), key=lambda x: (-x["count"], x["asset"])),
        "counts": {
            "confirmed": conf_counts,
            "potential": by_sev(potential),
            "confirmed_total": len(confirmed),
            "potential_total": len(potential),
            "hardening_total": len(hard_agg),
            "informational_total": len(info_agg),
            "informational_raw": len(informational),
            "not_tested_total": len(not_tested),
            "assets": len({_asset(g.get("location")) for g in norm if g.get("location")}),
            "scans": len(scans or []),
        },
        "coverage_matrix": coverage_matrix,
        "not_tested": not_tested,
        "overall_risk": overall,
        "attck_present": attck_present,
        "triage_present": triage_present,
        "qc_issues": qc,
    }

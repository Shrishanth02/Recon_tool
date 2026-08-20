"""Business-logic testing FOUNDATION — safe, signal-only.

Builds a WORKFLOW MODEL from crawl / auth_crawl output and flags SUSPICIOUS
patterns for human review. It performs NO network requests and NO transactions:
every finding is a SIGNAL with ``kind="info"`` so it NEVER inflates the
vulnerability risk score (``risk.workspace_risk`` only scores ``kind=="vuln"``).
Marking a business-logic issue VALIDATED requires concrete evidence (e.g. an
actual price change), which is deliberately NOT attempted here — that is a
future, human-gated step.
"""

import re
from urllib.parse import parse_qsl, urlsplit

# Parameter names whose value should not be trusted from the client.
_PRICE_PARAMS = {
    "price", "amount", "cost", "total", "subtotal", "qty", "quantity", "count",
    "discount", "fee", "tax", "balance", "credit", "points", "rate", "currency",
}
_PRIV_PARAMS = {
    "role", "is_admin", "isadmin", "admin", "approved", "is_approved", "verified",
    "is_verified", "premium", "plan", "tier", "level", "access", "permission",
    "grant", "owner", "status", "state",
}
_ID_PARAMS = {"user_id", "userid", "uid", "account", "account_id", "owner_id"}
_SENSITIVE_PARAMS = _PRICE_PARAMS | _PRIV_PARAMS | _ID_PARAMS | {"coupon", "voucher"}

# Path keywords that mark a workflow / state-transition step.
_WORKFLOW_KEYWORDS = (
    "checkout", "confirm", "approve", "reject", "redeem", "apply", "promote",
    "demote", "transfer", "withdraw", "deposit", "cancel", "activate", "deactivate",
    "verify", "upgrade", "downgrade", "refund", "order", "payment", "pay",
    "purchase", "subscribe", "grant", "revoke", "publish",
)


def _norm_path(url: str) -> str:
    p = urlsplit(url).path or "/"
    p = re.sub(r"/\d+", "/{id}", p.rstrip("/"))
    return p or "/"


def _params_of(url: str, extra=None) -> list[str]:
    names = {str(n) for n in (extra or [])}
    for n, _v in parse_qsl(urlsplit(url).query, keep_blank_values=True):
        names.add(n)
    return sorted(names)


def build_model(sources) -> dict:
    """Build a workflow model from a list of crawl/auth_crawl result dicts.

    Returns ``{"endpoints": [{url, path, method, params, authenticated, source}],
    "relationships": [...]}``.
    """
    endpoints: list[dict] = []
    seen = set()

    def _add(url, method, params, authenticated, source):
        if not url:
            return
        method = (method or "GET").upper()
        params = sorted({str(p) for p in (params or [])})
        key = (_norm_path(url), method, tuple(params), bool(authenticated))
        if key in seen:
            return
        seen.add(key)
        endpoints.append({
            "url": url, "path": _norm_path(url), "method": method, "params": params,
            "authenticated": bool(authenticated), "source": source,
        })

    for src in (sources or []):
        if not isinstance(src, dict):
            continue
        authed = bool(src.get("authenticated"))
        for ep in (src.get("endpoints") or []):
            _add(ep.get("url", ""), ep.get("method", "GET"),
                 ep.get("params") or _params_of(ep.get("url", "")),
                 ep.get("authenticated", authed), "endpoint")
        for f in (src.get("forms") or []):
            _add(f.get("action", ""), f.get("method", "GET"), f.get("inputs") or [], authed, "form")
        for p in (src.get("parameterized_urls") or []):
            _add(p.get("url", ""), "GET", p.get("params") or _params_of(p.get("url", "")), authed, "param_url")
        for u in (src.get("api_endpoints") or []):
            _add(u, "GET", _params_of(u), authed, "api")

    relationships = [
        {"node": e["path"], "method": e["method"], "type": "workflow_step"}
        for e in endpoints
        if any(k in e["path"].lower() for k in _WORKFLOW_KEYWORDS)
    ]
    return {"endpoints": endpoints, "relationships": relationships}


def _finding(severity, name, description, url, evidence) -> dict:
    return {
        "severity": severity, "name": name, "location": url,
        "cwe": ["CWE-840"],           # Business Logic Errors
        "detection_tier": "signal",   # never validated without concrete evidence
        "kind": "info",               # excluded from the vuln risk score
        "confidence": 30, "description": description, "evidence": evidence,
    }


def analyze(model: dict) -> list[dict]:
    """Return SIGNAL findings for suspicious workflow patterns (no network)."""
    findings: list[dict] = []
    endpoints = model.get("endpoints") or []

    # (1) Client-controlled security-sensitive parameters.
    for e in endpoints:
        sens = [p for p in e["params"] if p.lower() in _SENSITIVE_PARAMS]
        if not sens:
            continue
        if any(p.lower() in _PRICE_PARAMS for p in sens):
            label, sev = "price/quantity", "low"
        elif any(p.lower() in _PRIV_PARAMS for p in sens):
            label, sev = "privilege/state", "low"
        else:
            label, sev = "security-sensitive", "info"
        findings.append(_finding(
            sev,
            f"Client-controlled {label} parameter(s): {', '.join(sens)}",
            (f"The {e['method']} endpoint {e['path']} accepts client-controlled {label} "
             f"parameter(s) ({', '.join(sens)}). If the server trusts these values, "
             f"price/quantity manipulation or privilege/state tampering may be possible. "
             f"SIGNAL only — validate manually against an authorized test app."),
            e["url"],
            {"endpoint": e["url"], "path": e["path"], "method": e["method"],
             "parameters": e["params"], "sensitive_parameters": sens,
             "authenticated": e["authenticated"], "pattern": label, "source": e["source"]},
        ))

    # (2) Inconsistent authorization: same path+method reachable authed AND anon.
    by_key: dict = {}
    for e in endpoints:
        by_key.setdefault((e["path"], e["method"]), set()).add(e["authenticated"])
    for (path, method), auth_states in by_key.items():
        if True in auth_states and False in auth_states:
            findings.append(_finding(
                "info",
                f"Endpoint reachable authenticated and unauthenticated: {method} {path}",
                (f"{method} {path} was observed both with and without authentication — inconsistent "
                 f"authorization across the workflow may let an unauthenticated user reach an "
                 f"authenticated step. SIGNAL only."),
                path,
                {"path": path, "method": method, "pattern": "inconsistent_authorization",
                 "auth_contexts": sorted(str(a) for a in auth_states)},
            ))

    # (3) State-changing workflow steps (foundation for sequence checks).
    for e in endpoints:
        if e["method"] in ("POST", "PUT", "PATCH", "DELETE") and \
                any(k in e["path"].lower() for k in _WORKFLOW_KEYWORDS):
            findings.append(_finding(
                "info",
                f"State-changing workflow step: {e['method']} {e['path']}",
                (f"{e['method']} {e['path']} is a state-changing workflow step. Verify sequence "
                 f"enforcement, idempotency (repeated-action safety) and consistent authorization. "
                 f"SIGNAL only — modelled for review, not exploited."),
                e["url"],
                {"endpoint": e["url"], "path": e["path"], "method": e["method"],
                 "authenticated": e["authenticated"], "pattern": "state_transition"},
            ))
    return findings

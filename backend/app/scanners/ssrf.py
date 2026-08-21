"""Server-Side Request Forgery (SSRF) detection + safe reflective validation.

Identifies request parameters that may cause the server to make outbound
requests, and — where possible — confirms them WITHOUT any destructive or
internal-network probing:

  * DETECT (possible / SIGNAL): a parameter whose name or value is URL-shaped.
  * VALIDATE (reflective / VALIDATED): point the parameter at an IN-SCOPE canary
    (the target's own root) and confirm the canary's *content* (not the URL
    string) is reflected in the response but not in a benign baseline — proving
    the server fetched a user-supplied URL. Only in-scope URLs are ever used as
    payloads; no internal/RFC-1918/metadata address is ever requested here.
  * BLIND: cannot be confirmed without an OAST callback. :mod:`app.oast` has no
    provider yet, so blind cases stay POSSIBLE — never falsely validated.

All HTTP is read-only GET, bounded and timed out. Scope + netguard are enforced
by the caller (execution / pipeline) before this scanner runs, like every other
scanner; the only payloads used are in-scope canary URLs.
"""

import re
import threading
from typing import Iterator, Optional
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import requests

from .. import oast, safe_http
from .base import ensure_url, error, log, result

_TIMEOUT = 8
_MAX_PARAMS = 8
_UA = "RedOpsX-SSRF/1.0"
_BENIGN = "redopsx-ssrf-benign"

# Parameter names commonly used to pass a URL/host the server then fetches.
_SSRF_PARAM_NAMES = {
    "url", "uri", "link", "src", "source", "dest", "destination", "redirect",
    "redirect_uri", "redirect_url", "next", "target", "callback", "webhook",
    "feed", "host", "domain", "site", "page", "path", "file", "document", "doc",
    "img", "image", "load", "fetch", "proxy", "remote", "out", "view", "show",
    "data", "reference", "ref", "continue", "return", "returnto", "to", "forward",
    "open", "resource", "endpoint", "upstream", "origin",
}


def _looks_like_url(v: str) -> bool:
    v = (v or "").strip().lower()
    return v.startswith(("http://", "https://", "//", "ftp://"))


def _is_candidate(name: str, value: str) -> bool:
    return name.lower() in _SSRF_PARAM_NAMES or _looks_like_url(value)


def _http_get(url: str) -> Optional[tuple]:
    """Read-only GET; returns (status, text) or None on any request error."""
    try:
        r = safe_http.safe_request("GET", url, headers={"User-Agent": _UA}, timeout=_TIMEOUT,
                                   verify=False, allow_redirects=False)
        return r.status_code, (r.text or "")
    except requests.RequestException:
        return None


def _set_param(url: str, params_list: list, idx: int, value: str) -> str:
    new = list(params_list)
    new[idx] = (new[idx][0], value)
    p = urlsplit(url)
    return urlunsplit((p.scheme, p.netloc, p.path, urlencode(new), p.fragment))


def _marker_from(text: str) -> Optional[str]:
    """A distinctive CONTENT token from the canary body (not the URL) used to
    prove the server actually fetched it."""
    m = re.search(r"<title>(.*?)</title>", text or "", re.I | re.S)
    if m:
        t = re.sub(r"\s+", " ", m.group(1)).strip()
        if len(t) >= 8:
            return t[:80]
    tokens = sorted(re.findall(r"[A-Za-z0-9]{10,}", text or ""), key=len, reverse=True)
    return tokens[0][:80] if tokens else None


def stream(target: str, cancel: Optional[threading.Event] = None, **options) -> Iterator[dict]:
    try:
        url = ensure_url(target)
    except ValueError as exc:
        yield error(str(exc))
        return

    parts = urlsplit(url)
    params_list = parse_qsl(parts.query, keep_blank_values=True)
    if not params_list:
        yield log("No query parameters — nothing to test for SSRF.")
        yield result({"target": url, "tested_params": [], "findings": [],
                      "oast_available": oast.available()})
        return

    candidates = [
        (i, n, v) for i, (n, v) in enumerate(params_list) if _is_candidate(n, v)
    ][:_MAX_PARAMS]

    # In-scope canary = the target's OWN root; fetching it proves a server-side
    # request without ever touching an internal/external host.
    canary_url = urlunsplit((parts.scheme, parts.netloc, "/", "", ""))
    canary_resp = _http_get(canary_url)
    marker = _marker_from(canary_resp[1]) if canary_resp else None

    findings: list[dict] = []
    tested: list[str] = []
    for idx, name, value in candidates:
        if cancel is not None and cancel.is_set():
            break
        tested.append(name)
        yield log(f"SSRF-candidate parameter: {name}")
        base = _http_get(_set_param(url, params_list, idx, _BENIGN))
        ev = {"parameter": name, "method": "GET", "location": url, "canary": canary_url}
        validated = False
        if marker and base is not None:
            test = _http_get(_set_param(url, params_list, idx, canary_url))
            if test is not None and marker in (test[1] or "") and marker not in (base[1] or ""):
                validated = True
                ev.update({"reflected_marker": marker[:80],
                           "baseline_status": base[0], "test_status": test[0]})

        if validated:
            findings.append({
                "severity": "high",
                "name": f"Server-Side Request Forgery (reflective) in '{name}'",
                "location": url, "cwe": ["CWE-918"], "cvss": 8.6,
                "detection_tier": "validated", "confidence": 85,
                "description": (
                    f"The '{name}' parameter causes the server to fetch a user-supplied "
                    f"URL: pointing it at an in-scope canary caused the canary's CONTENT to "
                    f"be reflected in the response (absent from the baseline), confirming a "
                    f"server-side request. Non-destructive reflective test only."),
                "evidence": ev,
            })
            yield log(f"  🚨 reflective SSRF confirmed on '{name}'")
        else:
            note = ("blind SSRF cannot be confirmed without an OAST/callback provider"
                    if not oast.available() else "no reflection observed")
            findings.append({
                "severity": "medium",
                "name": f"Possible Server-Side Request Forgery in '{name}'",
                "location": url, "cwe": ["CWE-918"],
                "detection_tier": "signal", "confidence": 40,
                "description": (
                    f"The '{name}' parameter is a server-side-request candidate (URL-like "
                    f"name/value). Reflective validation did not confirm it ({note}). Treat "
                    f"as POSSIBLE until validated."),
                "evidence": {**ev, "note": note},
            })

    yield result({"target": url, "tested_params": tested, "findings": findings,
                  "oast_available": oast.available()})

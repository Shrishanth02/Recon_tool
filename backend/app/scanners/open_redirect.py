"""Open-redirect (unvalidated redirect / CWE-601) detection — read-only.

For each discovered query parameter that plausibly controls a redirect target,
inject a benign, NON-RESOLVING external canary URL and check whether the server
reflects it into a redirect that leaves the target's own origin.

Strictly read-only and non-destructive:
  * requests go ONLY to the in-scope, netguard-validated TARGET (GET, no body);
  * ``allow_redirects=False`` — the injected canary is NEVER fetched, so there is
    no SSRF and no external interaction. The canary host uses the RFC 2606
    ``.invalid`` TLD, which can never resolve, so even an app that DID follow it
    would reach nothing;
  * detection is header/body INSPECTION only: an HTTP 3xx ``Location`` pointing at
    the canary (server-side, primary), or — since the response body is already
    returned safely — a ``<meta http-equiv=refresh>`` / JavaScript ``location``
    assignment to the canary (client-side, secondary). No JavaScript is executed.

A redirect that stays same-origin (the target's own host, or a relative path) is
NOT reported. Scope + netguard are enforced by the caller before this scanner
runs, and again on every request via :mod:`app.safe_http`.
"""

import re
import threading
from typing import Iterator, Optional
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import requests

from .. import safe_http
from .base import ensure_url, error, log, result

_TIMEOUT = 8
_MAX_PARAMS = 8
_UA = "RedOpsX-OpenRedirect/1.0"

# RFC 2606 reserved TLD — guaranteed to never resolve, so the canary is safe even
# if an application were to follow the redirect (it cannot: allow_redirects=False).
_CANARY_HOST = "openredirect.invalid"
_CANARY_MARKERS = (f"https://{_CANARY_HOST}/", f"//{_CANARY_HOST}/")

# Parameter names commonly used to carry a redirect/return destination.
_REDIRECT_PARAM_NAMES = {
    "next", "url", "redirect", "redirect_uri", "redirect_url", "redirecturl",
    "return", "returnto", "return_to", "returnurl", "return_url", "returl",
    "dest", "destination", "continue", "goto", "go", "redir", "target", "to",
    "forward", "callback", "out", "view", "u", "link", "location", "back",
    "backurl", "success", "success_url", "failure", "cancel", "cancel_url",
    "checkout_url", "image_url", "rurl", "returnUrl",
}


def _looks_like_url(v: str) -> bool:
    v = (v or "").strip().lower()
    return v.startswith(("http://", "https://", "//"))


def _is_candidate(name: str, value: str) -> bool:
    return name.lower() in _REDIRECT_PARAM_NAMES or _looks_like_url(value)


def _probe(url: str) -> Optional[tuple]:
    """Read-only GET, NOT following redirects. Returns (status, location, body)
    or None on any request error. The Location header is captured but never
    followed (safe_http still validates the initial URL)."""
    try:
        r = safe_http.safe_request("GET", url, headers={"User-Agent": _UA},
                                   timeout=_TIMEOUT, verify=False, allow_redirects=False)
        return r.status_code, (r.headers.get("Location") or ""), (r.text or "")
    except requests.RequestException:
        return None


def _set_param(url: str, params_list: list, idx: int, value: str) -> str:
    new = list(params_list)
    new[idx] = (new[idx][0], value)
    p = urlsplit(url)
    return urlunsplit((p.scheme, p.netloc, p.path, urlencode(new), p.fragment))


def _redirect_host(location: str) -> str:
    """Host a Location header points at (absolute or protocol-relative), or ""
    for a relative/same-origin path."""
    loc = (location or "").strip()
    if not loc:
        return ""
    if loc.startswith("//"):
        loc = "http:" + loc
    try:
        return (urlsplit(loc).hostname or "").lower()
    except ValueError:
        return ""


def _body_redirect_method(body: str) -> Optional[str]:
    """If the body redirects to the canary via a meta-refresh or a JS location
    assignment, return the method; else None. Body inspection only — the canary
    must appear inside a redirect construct, not merely reflected somewhere."""
    if not body or _CANARY_HOST not in body:
        return None
    ch = re.escape(_CANARY_HOST)
    if re.search(
        r"<meta[^>]+http-equiv=['\"]?\s*refresh\s*['\"]?[^>]+content=['\"][^'\"]*url=[^'\"]*" + ch,
        body, re.I,
    ):
        return "meta-refresh"
    if re.search(
        r"(?:window\.)?location(?:\s*\.\s*(?:href|replace))?\s*[=(]\s*['\"][^'\"]*" + ch,
        body, re.I,
    ):
        return "js-location"
    return None


def stream(target: str, cancel: Optional[threading.Event] = None, **options) -> Iterator[dict]:
    try:
        url = ensure_url(target)
    except ValueError as exc:
        yield error(str(exc))
        return

    parts = urlsplit(url)
    params_list = parse_qsl(parts.query, keep_blank_values=True)
    if not params_list:
        yield log("No query parameters — nothing to test for open redirect.")
        yield result({"target": url, "tested_params": [], "findings": []})
        return

    candidates = [
        (i, n, v) for i, (n, v) in enumerate(params_list) if _is_candidate(n, v)
    ][:_MAX_PARAMS]

    findings: list[dict] = []
    tested: list[str] = []
    for idx, name, value in candidates:
        if cancel is not None and cancel.is_set():
            break
        tested.append(name)
        yield log(f"open-redirect candidate parameter: {name}")

        hit = None  # (payload, method, status, location)
        for marker in _CANARY_MARKERS:
            if cancel is not None and cancel.is_set():
                break
            resp = _probe(_set_param(url, params_list, idx, marker))
            if resp is None:
                continue
            status, location, body = resp
            # (1) Server-side 3xx to the canary (off-origin) — primary signal.
            if 300 <= status < 400 and _redirect_host(location) == _CANARY_HOST:
                hit = (marker, "3xx-location", status, location)
                break
            # (2) Client-side meta-refresh / JS redirect to the canary — secondary.
            m = _body_redirect_method(body)
            if m:
                hit = (marker, m, status, location)
                break

        if hit:
            payload, method, status, location = hit
            server_side = method == "3xx-location"
            via = (f"an HTTP {status} Location header" if server_side
                   else f"a client-side {method} redirect")
            findings.append({
                "severity": "medium",
                "name": f"Open redirect in '{name}'",
                "location": url, "cwe": ["CWE-601"], "cvss": 5.4,
                "detection_tier": "validated",
                "confidence": 80 if server_side else 65,
                "description": (
                    f"The '{name}' parameter controls a redirect destination that the "
                    f"application does not validate: setting it to an external URL caused an "
                    f"OFF-ORIGIN redirect to a non-resolving canary host via {via}. Unvalidated "
                    f"redirects (CWE-601) enable phishing and OAuth/token theft. Read-only "
                    f"check — the canary was never fetched and no data was modified."),
                "evidence": {
                    "parameter": name, "method": "GET", "location": url,
                    "redirect_via": method, "status": status,
                    "redirect_location": (location or "")[:200], "payload": payload,
                    "off_origin": True,
                },
            })
            yield log(f"  🚨 open redirect confirmed on '{name}' ({method})")
        # Same-origin / no redirect -> not an open redirect (nothing reported).

    yield result({"target": url, "tested_params": tested, "findings": findings})

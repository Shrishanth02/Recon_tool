"""CSRF detection — safe, non-destructive.

For state-changing forms/endpoints, checks whether cross-site request forgery is
prevented. It NEVER performs a real destructive action:

  * inspect the form for a CSRF-token field and the response for SameSite cookies
    — a state-changing form with NO token AND NO SameSite protection is a SIGNAL;
  * fetch the form twice and compare the token — a STATIC token is a SIGNAL;
  * VALIDATION: replay the state-changing request with a DELIBERATELY-INVALID CSRF
    token and an INVALID body — if the server does not reject it for CSRF (reaches
    the handler rather than 401/403 or a CSRF error), protection is not enforced
    (VALIDATED). The invalid body is rejected before anything is created.

Scope + netguard are enforced by the caller. Cookie VALUES are never stored —
only names/attributes (SameSite presence).
"""

import re
import threading
from typing import Iterator, Optional
from urllib.parse import urlsplit

import requests

from .. import safe_http
from .base import ensure_url, error, log, result

_TIMEOUT = 8
_UA = "RedOpsX-CSRF/1.0"
_STATE_METHODS = ("POST", "PUT", "PATCH", "DELETE")
_PROBE_HEADERS = {"X-RedOpsX-Test": "1"}
_INVALID_TOKEN = "redopsx-invalid-csrf-token"
#: Junk single-field body: reaches past a CSRF gate but is rejected by input
#: validation, so nothing is created/modified.
_INVALID_BODY = "redopsx_probe=1"

_CSRF_FIELD_NAMES = {
    "csrf", "csrftoken", "csrf_token", "_csrf", "_csrf_token", "xsrf", "xsrf_token",
    "_token", "authenticity_token", "__requestverificationtoken",
    "csrfmiddlewaretoken", "anticsrf", "anti_csrf", "requestverificationtoken",
}
_TOKEN_INPUT_RE = re.compile(
    r'<input[^>]*name=["\']([^"\']+)["\'][^>]*value=["\']([^"\']+)["\']', re.I)


def _http(method: str, url: str, headers: dict, data=None, ctype=None) -> Optional[tuple]:
    h = {"User-Agent": _UA, **(headers or {})}
    if ctype:
        h["Content-Type"] = ctype
    try:
        r = safe_http.safe_request(method, url, headers=h, data=data, timeout=_TIMEOUT,
                                   verify=False, allow_redirects=False)
        # requests.Response.raw exposes multiple Set-Cookie headers; fall back to
        # the (possibly-joined) header for a Set-Cookie SameSite scan.
        set_cookie = ""
        try:
            raw = r.raw.headers
            if hasattr(raw, "getlist"):
                set_cookie = " ; ".join(raw.getlist("Set-Cookie"))
        except Exception:  # noqa: BLE001
            set_cookie = ""
        if not set_cookie:
            set_cookie = r.headers.get("Set-Cookie", "")
        return r.status_code, (r.text or ""), set_cookie
    except requests.RequestException:
        return None


def _token_field(inputs) -> Optional[str]:
    for name in (inputs or []):
        if str(name).strip().lower() in _CSRF_FIELD_NAMES:
            return name
    return None


def _token_value_from_html(html: str) -> Optional[str]:
    for name, value in _TOKEN_INPUT_RE.findall(html or ""):
        if name.strip().lower() in _CSRF_FIELD_NAMES and value:
            return value
    return None


def _samesite_protected(set_cookie: str) -> bool:
    low = (set_cookie or "").lower()
    return "samesite=strict" in low or "samesite=lax" in low


def stream(target: str, cancel: Optional[threading.Event] = None, **options) -> Iterator[dict]:
    try:
        url = ensure_url(target)
    except ValueError as exc:
        yield error(str(exc))
        return

    method = (options.get("method") or "POST").upper()
    inputs = options.get("inputs") or []
    content_type = options.get("content_type") or "application/x-www-form-urlencoded"
    identity_headers = options.get("identity_headers") or {}

    if method not in _STATE_METHODS:
        yield log(f"{method} is not state-changing — no CSRF test needed.")
        yield result({"target": url, "method": method, "findings": []})
        return

    yield log(f"CSRF check: {method} {url}")
    r1 = _http("GET", url, identity_headers)
    r2 = _http("GET", url, identity_headers)
    token_field = _token_field(inputs)
    tok1 = _token_value_from_html(r1[1]) if r1 else None
    tok2 = _token_value_from_html(r2[1]) if r2 else None
    token_present = bool(token_field) or bool(tok1)
    set_cookie = r1[2] if r1 else ""
    samesite = _samesite_protected(set_cookie)

    findings: list[dict] = []
    base_ev = {
        "endpoint": url, "method": method, "content_type": content_type,
        "csrf_token_present": token_present, "csrf_field": token_field,
        "samesite_protection": samesite,
    }

    # (1) Missing CSRF protection entirely.
    if not token_present and not samesite:
        findings.append({
            "severity": "medium",
            "name": f"Possible CSRF: no token or SameSite on {urlsplit(url).path}",
            "location": url, "cwe": ["CWE-352"],
            "detection_tier": "signal", "confidence": 40,
            "description": (
                f"The {method} endpoint has no CSRF token field and no SameSite cookie "
                f"protection, so a cross-site request may be able to trigger it. Signal only — "
                f"validate before treating as exploitable."),
            "evidence": base_ev,
        })

    # (2) Static (non-rotating) token.
    if tok1 and tok2 and tok1 == tok2:
        findings.append({
            "severity": "medium",
            "name": f"CSRF token is static (not per-request): {urlsplit(url).path}",
            "location": url, "cwe": ["CWE-352"],
            "detection_tier": "signal", "confidence": 45,
            "description": ("The CSRF token was identical across two fresh requests — a static or "
                            "predictable token weakens CSRF protection."),
            "evidence": {**base_ev, "token_static": True},
        })

    # (3) VALIDATION: does an invalid-token request reach the handler (not rejected
    #     for CSRF)? Non-destructive: invalid token + invalid body.
    if cancel is None or not cancel.is_set():
        body = f"{(token_field or 'csrf')}={_INVALID_TOKEN}&{_INVALID_BODY}"
        probe = _http(method, url, {**identity_headers, **_PROBE_HEADERS},
                      data=body, ctype="application/x-www-form-urlencoded")
        if probe is not None:
            status, ptext = probe[0], probe[1]
            csrf_rejected = (
                status in (401, 403)
                or 300 <= status < 400
                or "csrf" in (ptext or "").lower()
                or "forbidden" in (ptext or "").lower()
            )
            if status == 405:
                pass  # method not allowed — inconclusive
            elif not csrf_rejected:
                findings.append({
                    "severity": "high",
                    "name": f"CSRF protection not enforced: {method} {urlsplit(url).path}",
                    "location": url, "cwe": ["CWE-352"], "cvss": 6.5,
                    "detection_tier": "validated", "confidence": 80,
                    "description": (
                        f"A {method} request with a DELIBERATELY-INVALID CSRF token reached the "
                        f"handler (HTTP {status}) instead of being rejected — CSRF is not enforced. "
                        f"A benign/invalid body was used so nothing was created or modified."),
                    "evidence": {**base_ev, "probe_status": status,
                                 "probe": "invalid CSRF token + invalid body (X-RedOpsX-Test)",
                                 "validation_result": "not_enforced"},
                })
                yield log(f"  🚨 CSRF not enforced ({method} -> HTTP {status})")
            else:
                yield log(f"  CSRF appears enforced ({method} -> HTTP {status})")

    yield result({"target": url, "method": method, "findings": findings})

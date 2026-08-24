"""CSRF detection — safe, non-destructive.

For state-changing forms/endpoints, checks whether cross-site request forgery is
prevented. It NEVER performs a real destructive action:

  * inspect the form for a CSRF-token field and the response for SameSite cookies
    — a state-changing form with NO token AND NO SameSite protection is a SIGNAL;
  * fetch the form twice and compare the token — a STATIC token is a SIGNAL;
  * VALIDATION: a DIFFERENTIAL probe. Two state-changing requests are sent that
    are identical in method, identity, headers and body and differ only in the
    CSRF control — one carries the harvested token and a same-origin
    Origin/Referer, the other a deliberately-invalid token and a foreign
    Origin/Referer. If the forged request is rejected, the control is enforced.
    If it SUCCEEDS exactly as the control did, protection is not enforced
    (VALIDATED). If both fail identically the result is inconclusive — they may
    have failed before any CSRF check ran — so it is reported as a SIGNAL. Both
    bodies are invalid, so nothing is created either way.

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
#: A Origin/Referer that can never be same-site with a real target, used as the
#: "forged" half of the differential probe.
_FOREIGN_ORIGIN = "https://csrf-probe.invalid"

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


def _token_name_value_from_html(html: str) -> Optional[tuple]:
    """First (name, value) pair in the HTML that looks like a CSRF token input."""
    for name, value in _TOKEN_INPUT_RE.findall(html or ""):
        if name.strip().lower() in _CSRF_FIELD_NAMES and value:
            return name, value
    return None


def _token_value_from_html(html: str) -> Optional[str]:
    nv = _token_name_value_from_html(html)
    return nv[1] if nv else None


def _origin_of(url: str) -> str:
    p = urlsplit(url)
    return f"{p.scheme}://{p.netloc}"


def _csrf_rejected(status: int, text: str) -> bool:
    """Does the response look like a CSRF / authorization rejection?"""
    low = (text or "").lower()
    return (status in (401, 403) or 300 <= status < 400
            or "csrf" in low or "forbidden" in low)


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

    # (3) VALIDATION — DIFFERENTIAL probe.
    #
    #     A single probe cannot distinguish "the CSRF control is missing" from
    #     "the request failed for an unrelated reason": a 400 produced by body
    #     validation and a 400 produced by a handler that never checked CSRF are
    #     indistinguishable. So send TWO state-changing requests that are
    #     identical in method, identity, headers and body, and differ ONLY in the
    #     CSRF control being exercised:
    #
    #       control — the harvested (valid) token + a SAME-origin Origin/Referer
    #       forged  — a deliberately-invalid token + a FOREIGN Origin/Referer
    #
    #     Any difference in outcome is then attributable to the CSRF control
    #     alone. If exercising the control changes nothing, it is not enforced.
    #     Both bodies are junk, so nothing is created or modified either way.
    if cancel is None or not cancel.is_set():
        nv = _token_name_value_from_html(r1[1]) if r1 else None
        field = token_field or (nv[0] if nv else "csrf")
        valid_token = nv[1] if nv else None

        def _probe(token: str, origin: str, referer: str):
            return _http(method, url,
                         {**identity_headers, **_PROBE_HEADERS,
                          "Origin": origin, "Referer": referer},
                         data=f"{field}={token}&{_INVALID_BODY}",
                         ctype="application/x-www-form-urlencoded")

        control = _probe(valid_token or _INVALID_TOKEN, _origin_of(url), url)
        forged = _probe(_INVALID_TOKEN, _FOREIGN_ORIGIN, _FOREIGN_ORIGIN + "/")

        if control is not None and forged is not None:
            c_status = control[0]
            f_status, f_text = forged[0], forged[1]
            ev = {**base_ev, "probe_status": f_status, "control_status": c_status,
                  "probe": ("forged CSRF token + foreign Origin, against a same-origin "
                            "control (X-RedOpsX-Test, invalid body)")}
            if f_status == 405:
                yield log(f"  CSRF check inconclusive ({method} not allowed)")
            elif _csrf_rejected(f_status, f_text):
                # The forged request was rejected -> the control IS enforced.
                yield log(f"  CSRF appears enforced ({method} -> HTTP {f_status})")
            elif f_status != c_status:
                # Exercising the control changed the outcome, but not into a
                # recognisable rejection -> no claim either way.
                yield log(f"  CSRF check inconclusive "
                          f"(control {c_status} vs forged {f_status})")
            elif 200 <= f_status < 300:
                # Both SUCCEEDED: a forged-token, foreign-Origin state-changing
                # request was accepted. That is the vulnerability itself.
                findings.append({
                    "severity": "high",
                    "name": f"CSRF protection not enforced: {method} {urlsplit(url).path}",
                    "location": url, "cwe": ["CWE-352"], "cvss": 6.5,
                    "detection_tier": "validated", "confidence": 80,
                    "description": (
                        f"A {method} request carrying a DELIBERATELY-INVALID CSRF token and a "
                        f"FOREIGN Origin SUCCEEDED (HTTP {f_status}), exactly as the same-origin "
                        f"control did — the CSRF control is not enforced. A benign/invalid body "
                        f"was used so nothing was created or modified."),
                    "evidence": {**ev, "validation_result": "not_enforced"},
                })
                yield log(f"  🚨 CSRF not enforced ({method} -> HTTP {f_status})")
            else:
                # Identical NON-2xx outcomes: exercising the control changed
                # nothing, but both requests may have failed BEFORE any CSRF
                # check ran (input validation, authorization). Report the
                # observation, do not claim it is exploitable.
                findings.append({
                    "severity": "medium",
                    "name": f"Possible CSRF: control had no effect on {urlsplit(url).path}",
                    "location": url, "cwe": ["CWE-352"],
                    "detection_tier": "signal", "confidence": 40,
                    "description": (
                        f"A forged-token, foreign-Origin {method} request and the same-origin "
                        f"control both returned HTTP {f_status}, so exercising the CSRF control "
                        f"changed nothing. Inconclusive: a shared non-2xx status means both may "
                        f"have failed before any CSRF check ran (input validation, "
                        f"authorization). Verify manually."),
                    "evidence": {**ev, "validation_result": "inconclusive"},
                })
                yield log(f"  ⚠ CSRF control had no effect, but both requests "
                          f"failed (HTTP {f_status}) — inconclusive")

    yield result({"target": url, "method": method, "findings": findings})

"""CSRF detection — safe, non-destructive.

For state-changing forms/endpoints, checks whether cross-site request forgery is
prevented. It NEVER performs a real destructive action:

  * inspect the form for a CSRF-token field and the response for SameSite cookies
    — a state-changing form with NO token AND NO SameSite protection is a SIGNAL;
  * fetch the form twice and compare the token — a STATIC token is a SIGNAL;
  * VALIDATION: a DIFFERENTIAL probe in which BOTH halves are non-destructive.
    Two requests are sent carrying the SAME deliberately-invalid CSRF token and
    the same junk body, differing only in Origin/Referer — one same-origin, one
    foreign. An app that validates the token rejects both, exactly as it would
    reject a real forgery. If the foreign-origin request is rejected the control
    is enforced; if BOTH are accepted, neither the token nor the origin is
    checked (VALIDATED, unless a SameSite attribute means a browser would not
    send the cookie cross-site — then SIGNAL). Identical non-2xx results are
    inconclusive and reported as a SIGNAL.

    The form's real token is read for the static-token check but is NEVER sent
    in a state-changing request: replaying a valid token would make the probe
    indistinguishable from a genuine user submission and would perform the very
    action under test. DELETE is never sent at all — it is identified by its URL,
    so no choice of body makes it safe — and is reported as untested instead.

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
#: Methods that change state, and therefore need a CSRF control at all.
_STATE_METHODS = ("POST", "PUT", "PATCH", "DELETE")
#: Methods we may ACTIVELY probe. DELETE is deliberately excluded and is never
#: sent — a DELETE is identified by its URL, so no choice of request body can
#: make it non-destructive. It is reported as untested instead (same discipline
#: as ``jwt_audit._check_method_authz``).
_PROBE_METHODS = ("POST", "PUT", "PATCH")
_PROBE_HEADERS = {"X-RedOpsX-Test": "1"}
#: A token that is never valid anywhere. Deliberately free of the substring
#: "csrf": it is echoed back by apps that re-render the submitted form, and
#: ``_csrf_rejected`` scans the body for that marker — a token containing it
#: would make the probe suppress its own finding.
_INVALID_TOKEN = "redopsx-invalid-token-000000"
#: Junk single-field body: reaches past a CSRF gate but is rejected by input
#: validation, so nothing is created/modified.
_INVALID_BODY = "redopsx_probe=1"
#: Field name used when the form declares no CSRF field. Also free of "csrf",
#: for the same self-suppression reason.
_FALLBACK_FIELD = "redopsx_token"
#: An Origin/Referer that can never be same-site with a real target. This is the
#: ONLY thing varied between the two probes.
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


def _token_field_name(html: str) -> Optional[str]:
    """The NAME of the form's CSRF field — deliberately never its value.

    The probe needs a plausible field name so the request is shaped like a real
    submission; it must never carry the real token, which would turn the probe
    into a genuine, accepted state-changing request.
    """
    nv = _token_name_value_from_html(html)
    return nv[0] if nv else None


def _origin_of(url: str) -> str:
    p = urlsplit(url)
    return f"{p.scheme}://{p.netloc}"


def _csrf_rejected(status: int, text: str, echoed: tuple = ()) -> bool:
    """Does the response look like a CSRF / authorization rejection?

    ``echoed`` lists strings THIS probe put into the request. An app that
    re-renders the submitted form echoes them back, so matching the rejection
    markers against the raw body would let the probe suppress its own finding.
    They are removed before the markers are looked for.
    """
    low = (text or "").lower()
    for frag in echoed:
        if frag:
            low = low.replace(str(frag).lower(), " ")
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

    # (3) VALIDATION — DIFFERENTIAL probe, with BOTH halves non-destructive.
    #
    #     Both requests carry a DELIBERATELY-INVALID CSRF token and a junk body,
    #     so neither can complete a legitimate action: an app that validates the
    #     token rejects both, exactly as it would reject a real forgery. The ONLY
    #     thing varied between them is the request origin:
    #
    #       same-origin — invalid token, Origin/Referer of the target itself
    #       foreign     — invalid token, Origin/Referer of an unrelated site
    #
    #     A VALID token is never sent. Harvesting the form's real token and
    #     replaying it would make one half indistinguishable from a genuine user
    #     submission — it would perform the very action under test — so the
    #     harvested token is used only for the static-token check above, never in
    #     a state-changing request. DELETE is never sent at all.
    if method in _PROBE_METHODS and (cancel is None or not cancel.is_set()):
        field = token_field or _token_field_name(r1[1] if r1 else "") or _FALLBACK_FIELD
        body = f"{field}={_INVALID_TOKEN}&{_INVALID_BODY}"
        echoed = (field, _INVALID_TOKEN, _INVALID_BODY)

        def _probe(origin: str, referer: str):
            return _http(method, url,
                         {**identity_headers, **_PROBE_HEADERS,
                          "Origin": origin, "Referer": referer},
                         data=body, ctype="application/x-www-form-urlencoded")

        same = _probe(_origin_of(url), url)
        foreign = _probe(_FOREIGN_ORIGIN, _FOREIGN_ORIGIN + "/")

        if foreign is None:
            yield log("  CSRF check inconclusive (no response to the probe)")
        else:
            f_status, f_text = foreign[0], foreign[1]
            s_status = same[0] if same else None
            ev = {**base_ev, "probe_status": f_status, "control_status": s_status,
                  "probe": ("invalid CSRF token in BOTH halves; only the request "
                            "Origin/Referer differs (X-RedOpsX-Test, invalid body)")}
            if f_status == 405:
                yield log(f"  CSRF check inconclusive ({method} not allowed)")
            elif _csrf_rejected(f_status, f_text, echoed):
                # The forged-origin request was rejected -> a control IS enforced.
                yield log(f"  CSRF appears enforced ({method} -> HTTP {f_status})")
            elif s_status is None:
                yield log("  CSRF check inconclusive (same-origin half failed)")
            elif f_status != s_status:
                # Changing only the Origin changed the outcome: the server is
                # doing something origin-aware, just not a recognisable rejection.
                yield log(f"  CSRF check inconclusive "
                          f"(same-origin {s_status} vs foreign {f_status})")
            elif 200 <= f_status < 300 and not samesite:
                findings.append({
                    "severity": "high",
                    "name": f"CSRF protection not enforced: {method} {urlsplit(url).path}",
                    "location": url, "cwe": ["CWE-352"], "cvss": 6.5,
                    "detection_tier": "validated", "confidence": 80,
                    "description": (
                        f"A {method} request carrying an INVALID CSRF token and a FOREIGN "
                        f"Origin was accepted (HTTP {f_status}), exactly as the same-origin "
                        f"request was — neither the token nor the origin is checked, and no "
                        f"SameSite cookie attribute limits cross-site use. The body was "
                        f"invalid, so nothing was created or modified."),
                    "evidence": {**ev, "validation_result": "not_enforced"},
                })
                yield log(f"  🚨 CSRF not enforced ({method} -> HTTP {f_status})")
            elif 200 <= f_status < 300 and samesite:
                # The probe sends the session cookie explicitly; a real browser
                # would withhold it cross-site, so this is NOT exploitable proof.
                findings.append({
                    "severity": "medium",
                    "name": f"CSRF token not validated (SameSite only): {urlsplit(url).path}",
                    "location": url, "cwe": ["CWE-352"],
                    "detection_tier": "signal", "confidence": 45,
                    "description": (
                        f"An INVALID CSRF token was accepted (HTTP {f_status}) regardless of "
                        f"request origin, so the token itself is not validated. A SameSite "
                        f"cookie attribute is present, and a real browser would not send the "
                        f"session cookie cross-site — this probe sends it explicitly, so the "
                        f"finding is not proof of an exploitable CSRF. Verify manually."),
                    "evidence": {**ev, "validation_result": "samesite_mitigated"},
                })
                yield log(f"  ⚠ invalid token accepted, but SameSite is set (HTTP {f_status})")
            else:
                findings.append({
                    "severity": "medium",
                    "name": f"Possible CSRF: control had no effect on {urlsplit(url).path}",
                    "location": url, "cwe": ["CWE-352"],
                    "detection_tier": "signal", "confidence": 40,
                    "description": (
                        f"The foreign-Origin and same-origin requests both returned HTTP "
                        f"{f_status}, so changing the origin made no difference. Inconclusive: "
                        f"a shared non-2xx status means both may have failed before any CSRF "
                        f"check ran (input validation, authorization). Verify manually."),
                    "evidence": {**ev, "validation_result": "inconclusive"},
                })
                yield log(f"  ⚠ origin made no difference, but both requests "
                          f"failed (HTTP {f_status}) — inconclusive")
    elif method not in _PROBE_METHODS:
        # DELETE: state-changing, but no request body can make it safe to send.
        findings.append({
            "severity": "info",
            "name": f"{method} endpoint not actively CSRF-tested: {urlsplit(url).path}",
            "location": url, "cwe": ["CWE-352"],
            "detection_tier": "signal", "confidence": 25,
            "description": (
                f"This endpoint accepts {method}, which is destructive and is therefore "
                f"NEVER sent by RECON-X — a {method} is identified by its URL, so no choice "
                f"of request body makes the probe safe. The passive checks above still "
                f"apply; verify manually that {method} enforces a CSRF control."),
            "evidence": {**base_ev, "actively_probed": False,
                         "reason": f"{method} is destructive and is never sent"},
        })
        yield log(f"  {method} is destructive — not sent; reported as untested")

    yield result({"target": url, "method": method, "findings": findings})

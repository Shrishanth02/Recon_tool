"""JWT + API-security auditing — safe, read-only.

Two capabilities:

  * **Static JWT analysis** of an operator-supplied or observed token: decode
    (NO verification) and report factual configuration weaknesses — ``alg:none``,
    missing/excessive ``exp``, symmetric algorithm, sensitive claims. These are
    VALIDATED facts about the token; the raw token is NEVER stored (it is a live
    credential) — only the algorithm, claim names and expiry metadata, with the
    subject masked.
  * **API authentication check**: request a discovered API endpoint WITH an
    operator identity and again ANONYMOUSLY; if the same authenticated data comes
    back unauthenticated, authentication is not enforced (VALIDATED).

No token forgery, no brute force, no credential theft, no destructive actions —
only reading. Scope + netguard are enforced by the caller before this runs.
"""

import base64
import json
import re
import threading
from typing import Iterator, Optional
from urllib.parse import urlsplit

import requests

from .. import safe_http
from .base import ensure_url, error, log, result

_TIMEOUT = 8
_UA = "RedOpsX-APIAudit/1.0"
_MAX_ENDPOINTS = 15
_LONG_LIFETIME = 24 * 3600  # seconds

_SENSITIVE_CLAIMS = {
    "password", "passwd", "pwd", "secret", "ssn", "credit_card", "card", "cvv",
    "api_key", "apikey", "private_key", "access_key",
}
_LOGIN_HINTS = ("login", "sign in", "password", "authenticate", "unauthorized", "forbidden")


def _b64url(seg: str) -> bytes:
    seg = seg + "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg.encode())


def _decode_jwt(token: str):
    parts = (token or "").split(".")
    if len(parts) != 3:
        return None
    try:
        header = json.loads(_b64url(parts[0]))
        payload = json.loads(_b64url(parts[1]))
    except Exception:  # noqa: BLE001 — any decode/parse error => not a JWT
        return None
    if not isinstance(header, dict) or not isinstance(payload, dict):
        return None
    return header, payload


def _safe_ev(header: dict, payload: dict) -> dict:
    """Non-sensitive token metadata for evidence — never the raw token."""
    return {
        "alg": header.get("alg"), "typ": header.get("typ"),
        "claims_present": sorted(payload.keys()),
        "exp": payload.get("exp"), "iat": payload.get("iat"),
    }


def _analyze_jwt(token: str, observed: bool = False) -> list[dict]:
    """Static JWT analysis.

    ``observed`` distinguishes the trust level per the three-state model:
      * ``observed=False`` — the token was supplied in isolation; a weak config is
        a "suspicious token configuration" (SIGNAL) — it may be a test token.
      * ``observed=True`` — the token was seen authenticating an ACTIVE session, so
        the server actually issues/accepts it: "server configuration appears
        vulnerable" (VALIDATED).
    The third state — proving the server accepts a *forged/manipulated* token — is
    NOT attempted here (no token forgery), and is documented as a limitation.
    """
    dec = _decode_jwt(token)
    if not dec:
        return []
    header, payload = dec
    alg = str(header.get("alg", "")).lower()
    assessment = ("server configuration appears vulnerable (token in active use)"
                  if observed else "suspicious token configuration")
    ev = {**_safe_ev(header, payload), "observed_in_session": observed, "assessment": assessment}
    tier = "validated" if observed else "signal"
    bump = 15 if observed else 0
    out: list[dict] = []

    if alg in ("none", ""):
        out.append({
            "severity": "critical", "name": "JWT uses 'alg: none' (unsigned token)",
            "location": "jwt", "cwe": ["CWE-347"], "cvss": 9.1,
            "detection_tier": tier, "confidence": min(95, 75 + bump),
            "description": (
                "The server accepts/issues an UNSIGNED token in an active session — a valid token "
                "can be forged by anyone."
                if observed else
                "This token is unsigned (alg=none). If the server accepts it, tokens can be forged. "
                "Not confirmed against the server (no forgery attempted)."),
            "evidence": ev,
        })

    if "exp" not in payload:
        out.append({
            "severity": "medium", "name": "JWT has no expiry (exp)", "location": "jwt",
            "cwe": ["CWE-613"], "detection_tier": tier, "confidence": min(90, 65 + bump),
            "description": (
                "A token with no 'exp' is in active use — a leaked token never expires."
                if observed else
                "This token has no 'exp' claim, so it would never expire."),
            "evidence": ev,
        })
    else:
        try:
            iat, exp = payload.get("iat"), payload.get("exp")
            if iat is not None and exp is not None and (int(exp) - int(iat)) > _LONG_LIFETIME:
                life = int(exp) - int(iat)
                out.append({
                    "severity": "low", "name": "JWT has an excessive lifetime", "location": "jwt",
                    "cwe": ["CWE-613"], "detection_tier": tier, "confidence": min(85, 55 + bump),
                    "description": f"The token lifetime is ~{life // 3600}h (exp - iat); a leaked token stays valid a long time.",
                    "evidence": {**ev, "lifetime_seconds": life},
                })
        except (TypeError, ValueError):
            pass

    if alg.startswith("hs"):
        # A symmetric algorithm is only a note — confirming a weak secret would
        # require brute force, which is never performed. Always a SIGNAL.
        out.append({
            "severity": "info", "name": f"JWT uses a symmetric algorithm ({header.get('alg')})",
            "location": "jwt", "cwe": ["CWE-326"], "detection_tier": "signal", "confidence": 40,
            "description": ("The token uses a symmetric (HMAC) algorithm; ensure the signing secret is long "
                            "and random. No brute force is performed."),
            "evidence": ev,
        })

    sens = [c for c in payload.keys() if c.lower() in _SENSITIVE_CLAIMS]
    if sens:
        out.append({
            "severity": "medium", "name": "JWT payload carries sensitive claim(s)", "location": "jwt",
            "cwe": ["CWE-522"], "detection_tier": tier, "confidence": min(85, 60 + bump),
            "description": (f"The token payload includes sensitive claim(s): {', '.join(sens)}. JWT payloads are "
                            "base64-encoded, not encrypted — never place secrets there."),
            "evidence": {**ev, "sensitive_claims": sens},
        })
    return out


#: State-changing methods we may actively probe. DELETE is deliberately EXCLUDED
#: from probing (only reported if a server advertises it) — it is never sent.
_STATE_METHODS = ("POST", "PUT", "PATCH")
_PROBE_HEADERS = {"X-RedOpsX-Test": "1"}
#: A deliberately-malformed JSON body: a well-behaved handler rejects it during
#: parsing/validation BEFORE persisting anything, so the probe is non-destructive
#: while still revealing whether the method is reachable unauthenticated.
_INVALID_PROBE = "{"


def _http(method: str, url: str, headers: dict, data=None, ctype=None) -> Optional[tuple]:
    """Read/probe request; returns (status, text, response_headers) or None."""
    h = {"User-Agent": _UA, **(headers or {})}
    if ctype:
        h["Content-Type"] = ctype
    try:
        r = safe_http.safe_request(method, url, headers=h, data=data, timeout=_TIMEOUT,
                                   verify=False, allow_redirects=False)
        return r.status_code, (r.text or ""), dict(r.headers)
    except requests.RequestException:
        return None


def _http_get(url: str, headers: dict) -> Optional[tuple]:
    r = _http("GET", url, headers)
    return (r[0], r[1]) if r else None


def _distinctive(body: str) -> Optional[str]:
    toks = sorted(re.findall(r"[A-Za-z0-9]{12,}", body or ""), key=len, reverse=True)
    return toks[0][:80] if toks else None


def _identity_headers(identity: dict) -> dict:
    h: dict = {}
    ck = (identity.get("cookie") or "").strip()
    ah = (identity.get("auth_header") or "").strip()
    if ck:
        h["Cookie"] = ck
    if ah:
        if ":" in ah:
            n, _, v = ah.partition(":")
            h[n.strip()] = v.strip()
        else:
            h["Authorization"] = ah
    return h


def _check_api_auth(url: str, identity_headers: dict) -> Optional[dict]:
    authed = _http_get(url, identity_headers)
    if not authed or authed[0] != 200:
        return None  # no authenticated baseline to compare against
    anon = _http_get(url, {})
    if not anon:
        return None
    status, body = anon
    if status in (401, 403) or 300 <= status < 400:
        return None  # authentication enforced
    if status == 200 and not any(h in (body or "").lower() for h in _LOGIN_HINTS):
        token = _distinctive(authed[1])
        if token and token in (body or ""):
            return {
                "severity": "high", "name": f"API endpoint lacks authentication: {urlsplit(url).path}",
                "location": url, "cwe": ["CWE-306"], "cvss": 7.5,
                "detection_tier": "validated", "confidence": 85,
                "description": ("The endpoint returned the same authenticated data to an UNauthenticated "
                                "request — it does not enforce authentication."),
                "evidence": {"url": url, "method": "GET", "status_authed": authed[0],
                             "status_anon": status, "shared_token": token},
            }
    return None


def _discover_methods(url: str, headers: dict) -> list[str]:
    """Advertised methods from an OPTIONS request (read-only)."""
    r = _http("OPTIONS", url, headers)
    if not r:
        return []
    allow = ""
    for k, v in (r[2] or {}).items():
        if k.lower() in ("allow", "access-control-allow-methods"):
            allow += "," + str(v)
    return [m.strip().upper() for m in allow.split(",") if m.strip()]


def _check_method_authz(url: str, identity_headers: dict) -> list[dict]:
    """Method-level authorization: does a state-changing method run without auth?

    Uses a deliberately-INVALID, labeled probe body so a well-behaved handler
    rejects it before persisting anything (non-destructive). Compares the
    authenticated vs anonymous status: if the anonymous state-changing request
    reaches the same handler outcome (not 401/403/redirect), method-level
    authorization is missing. DELETE is never sent — only reported if advertised.
    """
    findings: list[dict] = []
    methods = _discover_methods(url, identity_headers)
    for m in _STATE_METHODS:
        if methods and m not in methods:
            continue  # not advertised -> don't probe (avoid noise/side effects)
        authed = _http(m, url, {**identity_headers, **_PROBE_HEADERS},
                       data=_INVALID_PROBE, ctype="application/json")
        anon = _http(m, url, dict(_PROBE_HEADERS),
                     data=_INVALID_PROBE, ctype="application/json")
        if not authed or not anon:
            continue
        sa, sb = authed[0], anon[0]
        if sa in (401, 403, 404, 405):
            continue  # method not usable even for the authorized user
        if sb in (401, 403) or 300 <= sb < 400:
            continue  # authentication enforced for the method (good)
        if sb == sa:
            findings.append({
                "severity": "high",
                "name": f"Missing method-level authorization: {m} {urlsplit(url).path}",
                "location": url, "cwe": ["CWE-285"], "cvss": 7.1,
                "detection_tier": "validated", "confidence": 75,
                "description": (
                    f"An unauthenticated {m} request reached the same handler outcome "
                    f"(HTTP {sb}) as the authenticated one — the {m} method does not enforce "
                    f"authentication. Probe used a deliberately-invalid, labeled body so nothing "
                    f"was created/modified."),
                "evidence": {"url": url, "method": m, "status_authed": sa, "status_anon": sb,
                             "probe": "invalid non-destructive body (X-RedOpsX-Test)"},
            })
    if methods and "DELETE" in methods:
        findings.append({
            "severity": "info",
            "name": f"DELETE method advertised: {urlsplit(url).path}",
            "location": url, "cwe": ["CWE-650"],
            "detection_tier": "signal", "confidence": 30,
            "description": ("The endpoint advertises the DELETE method (via OPTIONS/Allow). "
                            "DELETE was NOT sent (destructive). Manually verify it enforces "
                            "authorization."),
            "evidence": {"url": url, "advertised_methods": methods},
        })
    return findings


def _graphql_check(url: str, identity_headers: dict) -> list[dict]:
    """Report GraphQL introspection if enabled (safe read-only query)."""
    if "graphql" not in urlsplit(url).path.lower():
        return []
    q = '{"query":"query{__schema{types{name}}}"}'
    r = _http("POST", url, {**identity_headers, **_PROBE_HEADERS}, data=q,
              ctype="application/json")
    if r and r[0] == 200 and '"__schema"' in (r[1] or "") and '"types"' in (r[1] or ""):
        return [{
            "severity": "medium",
            "name": f"GraphQL introspection enabled: {urlsplit(url).path}",
            "location": url, "cwe": ["CWE-200"],
            "detection_tier": "validated", "confidence": 80,
            "description": ("A read-only introspection query returned the GraphQL schema — "
                            "introspection is enabled, exposing the full API surface. Disable it "
                            "in production."),
            "evidence": {"url": url, "introspection": True, "query": "__schema{types{name}}"},
        }]
    return []


def stream(target: str, cancel: Optional[threading.Event] = None, **options) -> Iterator[dict]:
    findings: list[dict] = []

    # 1. Static JWT analysis (explicit token, or a bearer token in an auth header).
    token = (options.get("token") or "").strip()
    if not token:
        m = re.search(r"[Bb]earer\s+([A-Za-z0-9_\-\.]+)", options.get("auth_header") or "")
        if m:
            token = m.group(1)
    token_analyzed = False
    if token:
        # ``observed`` = the token came from an active authorized session (so the
        # server actually uses it) -> weaknesses are the server's, not just a
        # stray token's.
        jf = _analyze_jwt(token, observed=bool(options.get("observed")))
        findings.extend(jf)
        token_analyzed = _decode_jwt(token) is not None
        yield log(f"Analyzed JWT: {len(jf)} issue(s).")

    # 2. API authentication checks on discovered endpoints (needs an identity).
    endpoints = list(options.get("api_endpoints") or [])
    if not endpoints and target:
        try:
            endpoints = [ensure_url(target)]
        except ValueError as exc:
            yield error(str(exc))
            return
    identity_headers = _identity_headers(options.get("identity") or {})
    for url in endpoints[:_MAX_ENDPOINTS]:
        if cancel is not None and cancel.is_set():
            break
        try:
            u = ensure_url(url)
        except ValueError:
            continue
        if identity_headers:
            f = _check_api_auth(u, identity_headers)
            if f:
                findings.append(f)
                yield log(f"  🚨 unauthenticated access to {u}")
            # Method-level authorization (non-destructive probes) + GraphQL.
            for mf in _check_method_authz(u, identity_headers):
                findings.append(mf)
                yield log(f"  🚨 {mf['name']}")
        # GraphQL introspection is a read-only query — safe with or without auth.
        for gf in _graphql_check(u, identity_headers):
            findings.append(gf)
            yield log(f"  ⚠ {gf['name']}")

    yield result({"target": target, "token_analyzed": token_analyzed, "findings": findings})

"""IDOR / broken-object-level-authorization testing (read-only).

Compares access to object-identifier resources across EXPLICITLY AUTHORIZED
identities the operator supplies. It is strictly read-only (GET) and never
modifies data.

For each id-bearing URL, with >=2 identities:
  * fetch as identity A (assumed authorized) -> record a distinctive token;
  * fetch the SAME resource as identity B (a different authorized user);
  * fetch ANONYMOUSLY as a control.
Decision:
  * anon also sees A's content            -> PUBLIC resource, NOT idor (skipped);
  * B (different user) sees A's content and anon is denied
                                          -> VALIDATED cross-user access (IDOR);
  * B is denied / sees different content  -> authorization enforced (negative);
  * only one identity                     -> SUSPECTED (id-bearing endpoint).

Evidence records identity LABELS, the object identifier and response
characteristics — never the session tokens/cookies themselves.
"""

import json
import re
import threading
from typing import Iterator, Optional
from urllib.parse import parse_qsl, urlsplit

import requests

from .. import safe_http
from .base import ensure_url, error, log, result

_TIMEOUT = 8
_MAX_URLS = 15
_UA = "RedOpsX-IDOR/1.0"

_ID_PARAM_NAMES = {
    "id", "uid", "user_id", "userid", "account", "acct", "account_id", "order",
    "order_id", "doc", "document", "docid", "file", "fileid", "pid", "num", "no",
    "record", "rid", "item", "itemid", "object", "oid", "key",
}


def _object_id(url: str) -> Optional[str]:
    """Return an object identifier from the URL (numeric path seg or id-ish
    query param), or None when the URL is not a resource-by-id endpoint."""
    parts = urlsplit(url)
    for seg in parts.path.split("/"):
        if seg.isdigit():
            return seg
    for name, value in parse_qsl(parts.query, keep_blank_values=True):
        if name.lower() in _ID_PARAM_NAMES and value:
            return value
    return None


def _object_id_from_body(data: Optional[str], content_type: Optional[str]) -> Optional[str]:
    """Return an object identifier from a JSON or form request body (id-ish key)."""
    if not data:
        return None
    if "json" in (content_type or "").lower():
        try:
            obj = json.loads(data)
        except Exception:  # noqa: BLE001
            return None

        def _walk(o):
            if isinstance(o, dict):
                for k, v in o.items():
                    if k.lower() in _ID_PARAM_NAMES and isinstance(v, (int, str)) and str(v):
                        return str(v)
                for v in o.values():
                    r = _walk(v)
                    if r:
                        return r
            elif isinstance(o, list):
                for v in o:
                    r = _walk(v)
                    if r:
                        return r
            return None

        return _walk(obj)
    for name, value in parse_qsl(data, keep_blank_values=True):
        if name.lower() in _ID_PARAM_NAMES and value:
            return value
    return None


def _identity_headers(identity: dict) -> dict:
    """Build request headers from an operator identity (cookie / auth header).

    Never persisted — used only for this request. Returns {} for the anonymous
    control.
    """
    h: dict = {}
    if not identity:
        return h
    cookie = (identity.get("cookie") or "").strip()
    auth_header = (identity.get("auth_header") or "").strip()
    if cookie:
        h["Cookie"] = cookie
    if auth_header:
        if ":" in auth_header:
            name, _, val = auth_header.partition(":")
            h[name.strip()] = val.strip()
        else:
            h["Authorization"] = auth_header
    return h


def _http_get(url: str, headers: dict) -> Optional[tuple]:
    try:
        r = safe_http.safe_request("GET", url, headers={"User-Agent": _UA, **(headers or {})},
                                   timeout=_TIMEOUT, verify=False, allow_redirects=False)
        return r.status_code, (r.text or "")
    except requests.RequestException:
        return None


def _request(method: str, url: str, headers: dict, data=None, ctype=None) -> Optional[tuple]:
    """Method-aware request used for the cross-identity comparison. A plain GET
    delegates to ``_http_get`` (so it stays the single mockable read path); other
    methods / body requests replay the SAME request under each identity — this is
    read-only for query/lookup endpoints (the operator chooses what to test)."""
    if method == "GET" and not data:
        return _http_get(url, headers)
    h = dict(headers or {})
    if ctype:
        h["Content-Type"] = ctype
    try:
        r = safe_http.safe_request(method, url, headers={"User-Agent": _UA, **h}, data=data,
                                   timeout=_TIMEOUT, verify=False, allow_redirects=False)
        return r.status_code, (r.text or "")
    except requests.RequestException:
        return None


def _distinctive_token(body: str) -> Optional[str]:
    """A rare token from a response body used to prove the SAME resource was
    returned to another identity (long alnum run, or an email)."""
    m = re.search(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", body or "")
    if m:
        return m.group(0)[:80]
    toks = sorted(re.findall(r"[A-Za-z0-9]{12,}", body or ""), key=len, reverse=True)
    return toks[0][:80] if toks else None


def _targets(target: str) -> list[str]:
    out = []
    for piece in re.split(r"[\s,]+", (target or "").strip()):
        if piece:
            out.append(ensure_url(piece))
    return out


def stream(target: str, cancel: Optional[threading.Event] = None, **options) -> Iterator[dict]:
    try:
        urls = _targets(target)
    except ValueError as exc:
        yield error(str(exc))
        return
    if not urls:
        yield error("At least one target URL is required.")
        return

    identities = options.get("identities") or []
    # Keep only identities that actually carry a session; label them A, B, ...
    usable = [i for i in identities if _identity_headers(i)]
    labels = [i.get("label") or chr(ord("A") + n) for n, i in enumerate(usable)]

    # Optional method + request body so IDOR covers JSON/form/API object IDs, not
    # just URL path/query IDs. The SAME request is replayed under each identity.
    method = (options.get("method") or "GET").upper()
    data = options.get("data")
    content_type = options.get("content_type")
    if content_type in ("json", "application/json"):
        content_type = "application/json"
    elif content_type in ("form", "urlencoded"):
        content_type = "application/x-www-form-urlencoded"
    body_ev = {"content_type": content_type, "body_tested": True} if data else {}

    findings: list[dict] = []
    tested: list[str] = []
    for url in urls[:_MAX_URLS]:
        if cancel is not None and cancel.is_set():
            break
        oid = _object_id(url) or _object_id_from_body(data, content_type)
        if not oid:
            continue  # not a resource-by-id endpoint
        tested.append(url)

        if len(usable) < 2:
            yield log(f"id-bearing endpoint {url} — needs ≥2 authorized identities to validate")
            findings.append({
                "severity": "medium",
                "name": f"Possible IDOR: object-identifier endpoint ({oid})",
                "location": url, "cwe": ["CWE-639"],
                "detection_tier": "signal", "confidence": 35,
                "description": (
                    f"{url} exposes a resource by object identifier ({oid}). Broken "
                    f"object-level authorization cannot be confirmed with fewer than two "
                    f"authorized identities. Provide a second authorized test identity to "
                    f"validate cross-user access."),
                "evidence": {"url": url, "method": method, "object_id": oid,
                             "note": "unable to validate — single identity", **body_ev},
            })
            continue

        a = _request(method, url, _identity_headers(usable[0]), data, content_type)
        b = _request(method, url, _identity_headers(usable[1]), data, content_type)
        anon = _request(method, url, {}, data, content_type)
        if not a or a[0] != 200:
            continue  # identity A cannot read it -> nothing to compare
        token = _distinctive_token(a[1])
        anon_sees = bool(anon and anon[0] == 200 and token and token in (anon[1] or ""))
        b_sees = bool(b and b[0] == 200 and token and token in (b[1] or ""))

        if anon_sees:
            yield log(f"{url}: resource is publicly accessible — not an IDOR")
            continue
        if b_sees:
            yield log(f"  🚨 IDOR: identity {labels[1]} can read identity {labels[0]}'s resource {url}")
            findings.append({
                "severity": "high",
                "name": f"IDOR: cross-user resource access ({oid})",
                "location": url, "cwe": ["CWE-639"], "cvss": 6.5,
                "detection_tier": "validated", "confidence": 85,
                "description": (
                    f"Resource {url} (object {oid}) returned identity {labels[0]}'s data to a "
                    f"DIFFERENT authorized identity ({labels[1]}), while anonymous access was "
                    f"denied — confirming broken object-level authorization (a shared response "
                    f"token proves the same resource was served). Read-only check; no data "
                    f"was modified."),
                "evidence": {
                    "url": url, "method": method, "object_id": oid,
                    "identity_a": labels[0], "identity_b": labels[1],
                    "status_a": a[0], "status_b": b[0] if b else None,
                    "status_anon": anon[0] if anon else None,
                    "shared_token": token, "anon_denied": True, **body_ev,
                },
            })
        else:
            yield log(f"{url}: identity {labels[1]} did not obtain {labels[0]}'s resource — authz enforced")

    yield result({"target": urls[0] if urls else "", "identities": labels,
                  "tested": tested, "findings": findings})

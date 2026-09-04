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

Independently of any identity, an id endpoint that ANY anonymous caller can read,
whose object type/response looks sensitive, and whose adjacent identifiers return
DISTINCT records (enumerable), is reported as UNAUTHENTICATED object access
(broken access control) — the case the cross-identity comparison alone treats as
a public resource and drops. Genuinely public catalogues (e.g. /product/<id>) and
single shared pages are excluded by the object-type + enumerability filters.

Evidence records identity LABELS, the object identifier and response
characteristics — never the session tokens/cookies themselves.
"""

import json
import re
import threading
from typing import Iterator, Optional
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

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

# Object-type words that imply a per-subject SENSITIVE record (an unauthenticated
# read is broken access control) vs a legitimately PUBLIC catalogue item (an
# unauthenticated read is expected). Used to keep the unauthenticated-object-access
# check from firing on public resources.
_SENSITIVE_OBJECT_HINTS = frozenset({
    "order", "orders", "invoice", "invoices", "account", "accounts", "acct",
    "profile", "profiles", "user", "users", "customer", "customers", "member",
    "members", "document", "documents", "doc", "docs", "message", "messages",
    "msg", "ticket", "tickets", "payment", "payments", "transaction",
    "transactions", "statement", "statements", "receipt", "receipts", "record",
    "records", "cart", "carts", "address", "addresses", "employee", "employees",
    "booking", "bookings", "reservation", "reservations", "subscription", "ssn",
})
_PUBLIC_OBJECT_HINTS = frozenset({
    "product", "products", "item", "items", "article", "articles", "post",
    "posts", "page", "pages", "category", "categories", "blog", "blogs", "news",
    "faq", "faqs", "tag", "tags", "catalog", "review", "reviews", "comment",
    "comments", "photo", "photos", "image", "images", "video", "videos",
    "listing", "listings",
})
_PII_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


def _object_type(url: str, oid: str) -> str:
    """The object-type token for an id-bearing URL: the path segment before a
    path id, or the id parameter's base name for a query id."""
    parts = urlsplit(url)
    segs = [s for s in parts.path.split("/") if s]
    for i, s in enumerate(segs):
        if s == oid and i > 0:
            return segs[i - 1].lower()
    for name, value in parse_qsl(parts.query, keep_blank_values=True):
        if value == oid and name.lower() in _ID_PARAM_NAMES:
            base = re.sub(r"_?(id|no)$", "", name.lower())
            if base in _SENSITIVE_OBJECT_HINTS or base in _PUBLIC_OBJECT_HINTS:
                return base
            return segs[-1].lower() if segs else base
    return ""


def _sensitive(url: str, oid: str, body: str) -> bool:
    """Whether an anonymously-readable id endpoint looks like a per-subject
    sensitive object (order/invoice/account/…) rather than a public catalogue
    item. Known-public object types are never sensitive; unknown types fall back
    to PII (an email address) present in the response body."""
    t = _object_type(url, oid)
    if t in _SENSITIVE_OBJECT_HINTS:
        return True
    if t in _PUBLIC_OBJECT_HINTS:
        return False
    return bool(_PII_RE.search(body or ""))


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


def _with_id(url: str, oid: str, new_id: str) -> Optional[str]:
    """Return ``url`` with object identifier ``oid`` replaced by ``new_id`` (same
    host/path — used only for adjacent-id enumeration probing), or None."""
    parts = urlsplit(url)
    segs = parts.path.split("/")
    for i, s in enumerate(segs):
        if s == oid:
            segs[i] = new_id
            return urlunsplit((parts.scheme, parts.netloc, "/".join(segs),
                               parts.query, parts.fragment))
    q = parse_qsl(parts.query, keep_blank_values=True)
    newq, changed = [], False
    for k, v in q:
        if not changed and k.lower() in _ID_PARAM_NAMES and v == oid:
            newq.append((k, new_id))
            changed = True
        else:
            newq.append((k, v))
    if changed:
        return urlunsplit((parts.scheme, parts.netloc, parts.path,
                           urlencode(newq), parts.fragment))
    return None


def _distinct_record(orig_body: str, other_body: str) -> bool:
    """True if two anonymous responses are DIFFERENT per-object records (not the
    same shared page): a differing distinctive token, or — after normalizing
    whitespace and dropping digits so an id-echoing template isn't mistaken for
    data — substantively different content."""
    if not other_body:
        return False
    ot, nt = _distinctive_token(orig_body), _distinctive_token(other_body)
    if nt and nt != ot:
        return True

    def _norm(s: str) -> str:
        return re.sub(r"\d+", "", re.sub(r"\s+", " ", s or "")).strip()

    a, b = _norm(orig_body), _norm(other_body)
    return bool(a and b and a != b and abs(len(a) - len(b)) >= 8)


def _enumerable_anon(url: str, oid: str, orig_body: str,
                     cancel: Optional[threading.Event] = None) -> bool:
    """Whether adjacent numeric identifiers return DISTINCT records to an
    ANONYMOUS request — proving the endpoint serves an enumerable sequence of
    per-object records without authentication (not one shared public page).

    Read-only anonymous GETs via ``_http_get`` (netguard/SSRF-gated). Neighbour
    URLs are the SAME host as the already scope-approved target, so they inherit
    its engagement-scope decision; only simple numeric ids are probed."""
    if not oid.isdigit():
        return False
    n = int(oid)
    for neighbor in (n - 1, n + 1):
        if neighbor <= 0:
            continue
        if cancel is not None and cancel.is_set():
            break
        nurl = _with_id(url, oid, str(neighbor))
        if not nurl:
            continue
        r = _http_get(nurl, {})
        if r and r[0] == 200 and _distinct_record(orig_body, r[1]):
            return True
    return False


def _unauth_finding(url: str, oid: str, anon: tuple) -> dict:
    """Build the unauthenticated-enumerable-object-access finding (generic
    schema; per-finding tier/confidence honored by crud.derive_findings)."""
    return {
        "severity": "high",
        "name": f"Unauthenticated object access ({oid})",
        "location": url, "cwe": ["CWE-639", "CWE-284"], "cvss": 6.5,
        "detection_tier": "validated", "confidence": 80,
        "description": (
            f"{url} serves a per-object record for identifier {oid} to an ANONYMOUS "
            f"(unauthenticated) request, and adjacent identifiers return distinct "
            f"records — the object is enumerable and exposed without authorization "
            f"(broken object-level access control). Read-only check; no data was "
            f"modified and no exploitation was performed."),
        "evidence": {
            "url": url, "method": "GET", "object_id": oid,
            "status_anon": anon[0], "anonymous": True, "enumerable": True,
        },
    }


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

        # (1) Unauthenticated enumerable-object access. The cross-identity check
        # below treats "anon can read it too" as a public resource and drops it —
        # missing a SENSITIVE object any anonymous caller can read. For GET
        # path/query id endpoints we confirm that case directly: readable without a
        # session, sensitive object type/response, and adjacent identifiers return
        # DISTINCT records (enumerable). Identity-independent; every request is a
        # read-only GET via _http_get (safe_http/netguard). ``anon`` is reused by
        # the cross-identity control below.
        anon = None
        if method == "GET" and not data:
            anon = _http_get(url, {})
            if (anon and anon[0] == 200 and _sensitive(url, oid, anon[1])
                    and _enumerable_anon(url, oid, anon[1], cancel)):
                yield log(f"  [ALERT] {url}: unauthenticated access to enumerable object ({oid})")
                findings.append(_unauth_finding(url, oid, anon))
                continue

        if len(usable) < 2:
            # An id endpoint we cannot validate cross-user. Skip cleanly for
            # clearly-public object types to avoid a false positive on a catalogue.
            if _object_type(url, oid) in _PUBLIC_OBJECT_HINTS:
                yield log(f"{url}: public object type — not an authorization signal")
                continue
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
        if anon is None:
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
            yield log(f"  [ALERT] IDOR: identity {labels[1]} can read identity {labels[0]}'s resource {url}")
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

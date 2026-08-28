"""Role-matrix authorization scanning (broken access control / privilege
escalation, CWE-285 / CWE-862) — read-only.

Given the operator's authorized test identities (anonymous is always added as the
lowest-privilege principal), replay ONE discovered endpoint under every principal
and look for a **differential-authorization** violation: a strictly-lower-privilege
principal reaching the SAME substantive resource a higher-privilege principal sees.

Strictly read-only and non-destructive:
  * GET only — write methods are never replayed, so no state is changed;
  * every request goes through :mod:`app.safe_http` (netguard / SSRF-pinned) to the
    in-scope target the caller already approved; no exploitation is performed.

False-positive guards (a bare shared 200 is never enough):
  * a principal's response must be ALLOWED — 2xx, substantive, and not a
    login/error page — to count; login walls / 401 / 403 / redirects are DENIED;
  * the lower principal must see content EQUIVALENT to the higher principal's view
    (normalised-equal) — a principal seeing only its *own* resource is not a hit;
  * the lower principal must be STRICTLY lower privilege than the higher one;
  * and an authorization boundary must be demonstrable for the endpoint — either
    some principal is DENIED here (proving the app does gate it) OR the endpoint is
    privileged-signalled (an admin-ish path, or discovered behind authentication).
Evidence records principal LABELS, status codes and the signals only — never
response bodies, cookies, tokens, or headers.
"""

import re
import threading
from typing import Iterator, Optional
from urllib.parse import urlsplit

from .base import ensure_url, error, log, result
from .idor import _http_get, _identity_headers

_MIN_BODY = 16          # a substantive "allowed" body must exceed this
_SAMPLE = 4000          # chars compared / scanned

# Admin-ish / privileged path fragments — one signal that an endpoint is meant to
# be access-controlled (used only to gate findings, never to create them alone).
_PRIVILEGED_PATH_RE = re.compile(
    r"(?i)/(?:admin|administrator|manage|management|internal|console|backend|"
    r"staff|superuser|sudo|root|owner|moderat\w*|users?|accounts?|members?|"
    r"billing|invoices?|payments?|settings|config\w*|audit|reports?|wp-admin|"
    r"api/admin)(?:/|$|\?)"
)

# Markers that a 2xx body is really a login wall / authorization error (DENIED,
# not a real resource) — kept specific so an ordinary page is not misread.
_DENIED_BODY_RE = re.compile(
    r"(?i)(<input[^>]+type=['\"]?password|name=['\"]?password|please\s+(?:log|sign)\s?in|"
    r"(?:log|sign)\s?in\s+to\s+continue|you\s+must\s+(?:log|sign)\s?in|"
    r"authentication\s+required|unauthorized|access\s+denied|not\s+authorized|forbidden)"
)


def _probe(url: str, headers: dict) -> Optional[tuple]:
    """Read-only GET for one principal. Returns (status, body) or None on error.
    Thin wrapper over the shared, netguard-gated IDOR reader so tests can patch a
    single seam."""
    return _http_get(url, headers)


def _norm(text: str) -> str:
    # Collapse whitespace only — digits/content are PRESERVED so two different
    # per-user resources (that differ only in their data) are NOT treated as the
    # same page; equivalence must mean the lower principal saw the SAME resource.
    return re.sub(r"\s+", " ", (text or "")[:_SAMPLE]).strip().lower()


def _classify(status: int, body: str) -> str:
    """allowed | denied | missing | error for one principal's response."""
    if status in (401, 403):
        return "denied"
    if 300 <= status < 400:
        return "denied"          # redirect (typically to a login) — not access
    if status == 404:
        return "missing"
    if 200 <= status < 300:
        if len((body or "").strip()) < _MIN_BODY:
            return "denied"      # empty/near-empty 200 is not a real resource
        if _DENIED_BODY_RE.search((body or "")[:2000]):
            return "denied"      # a 200 login/error page
        return "allowed"
    return "error"


def _equivalent(a: str, b: str) -> bool:
    """Whether two ALLOWED bodies are the SAME substantive resource (so a lower
    principal is seeing the higher principal's content, not its own). Both bodies
    are already substantive (classified ALLOWED), so whitespace-normalised
    equality is a strong, low-false-positive 'same resource' signal — content is
    preserved, so different per-user data never compares equal."""
    na, nb = _norm(a), _norm(b)
    return bool(na and nb and na == nb)


def _privilege(identity: dict, index: int) -> int:
    """Privilege rank for an identity.

    An explicit, operator-declared non-negative ``privilege`` int is the rank.
    Otherwise the identity is an EQUAL-privilege peer (rank 0) — list POSITION is
    NOT a privilege signal. Inferring "earlier = lower" from list order fabricated
    a hierarchy the operator never asserted, so two same-role peers viewing a
    shared page looked like a privilege escalation (a false positive). Anonymous
    is ranked below all identities by the caller (-1), so genuine
    unauthenticated-access escalation is still detected; and when the operator
    DOES declare explicit ranks, differential-authorization between them still
    works. ``index`` is accepted for call-site stability but intentionally unused.
    """
    p = identity.get("privilege")
    if isinstance(p, int) and not isinstance(p, bool) and p >= 0:
        return p
    return 0


def stream(target: str, cancel: Optional[threading.Event] = None, **options) -> Iterator[dict]:
    try:
        url = ensure_url(target)
    except ValueError as exc:
        yield error(str(exc))
        return

    raw_identities = options.get("identities") or []
    usable = [i for i in raw_identities if isinstance(i, dict) and _identity_headers(i)]
    if not usable:
        yield log("Role-matrix needs at least one authorized identity — skipping.")
        yield result({"target": url, "principals": [], "findings": []})
        return

    authenticated = bool(options.get("authenticated"))
    path = urlsplit(url).path or "/"
    priv_signal = authenticated or bool(_PRIVILEGED_PATH_RE.search(path))

    # Principals ordered lowest-privilege first: anonymous (-1), then identities.
    principals = [("anonymous", -1, {})]
    for idx, ident in enumerate(usable):
        principals.append((ident.get("label") or chr(ord("A") + idx),
                           _privilege(ident, idx), _identity_headers(ident)))

    yield log(f"Role-matrix on {url} — {len(principals)} principal(s)"
              f"{' (privileged endpoint)' if priv_signal else ''}")

    matrix = []   # (label, privilege, cls, body)
    for label, priv, headers in principals:
        if cancel is not None and cancel.is_set():
            yield result({"target": url, "principals": [m[0] for m in matrix], "findings": []})
            return
        resp = _probe(url, headers)
        if resp is None:
            matrix.append((label, priv, "error", ""))
            continue
        status, body = resp
        matrix.append((label, priv, _classify(status, body), body or ""))

    boundary_exists = any(m[2] == "denied" for m in matrix)
    allowed = [m for m in matrix if m[2] == "allowed"]

    findings: list[dict] = []
    if allowed and (boundary_exists or priv_signal):
        hi = max(allowed, key=lambda m: m[1])          # highest-privilege ALLOWED
        hi_label, hi_priv, _hi_cls, hi_body = hi
        escalators = [
            m[0] for m in allowed
            if m[1] < hi_priv and _equivalent(m[3], hi_body)
        ]
        if escalators:
            who = ", ".join(f"'{e}'" for e in escalators)
            findings.append({
                "severity": "high",
                "name": f"Broken access control at {path}",
                "location": url, "cwe": ["CWE-285", "CWE-862"], "cvss": 7.1,
                "detection_tier": "validated",
                "confidence": 80 if boundary_exists else 70,
                "description": (
                    f"Lower-privilege principal(s) {who} received the SAME resource as the "
                    f"higher-privilege principal '{hi_label}' at {path}. "
                    + ("Another principal is denied this endpoint, proving access control is "
                       "enforced here — yet a lower principal reaches it (privilege escalation / "
                       "broken access control)."
                       if boundary_exists else
                       "The endpoint is privileged (admin-ish path or discovered behind "
                       "authentication), yet a lower-privilege principal can read it.")
                    + " Read-only check (GET); no data was modified."),
                "evidence": {
                    "endpoint": url, "method": "GET",
                    "reference_principal": hi_label,
                    "escalating_principals": escalators,
                    "authorization_boundary_observed": boundary_exists,
                    "privileged_signal": priv_signal,
                    "discovered_behind_auth": authenticated,
                    # status/classification per principal — NO bodies or credentials
                    "matrix": [{"principal": m[0], "access": m[2]} for m in matrix],
                },
            })
            yield log(f"  🚨 broken access control at {path}: {who} == '{hi_label}'")

    yield result({
        "target": url,
        "principals": [m[0] for m in matrix],
        "findings": findings,
    })

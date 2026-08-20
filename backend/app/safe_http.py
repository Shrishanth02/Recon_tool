"""Redirect-safe HTTP — one SSRF rule enforced at every network boundary.

The scanners point ``requests`` at attacker-influenced hosts. Letting the HTTP
client auto-follow redirects re-opens SSRF: a public in-scope target can 3xx a
probe straight to ``127.0.0.1`` / an RFC-1918 host / the cloud-metadata endpoint,
and ``requests`` would connect there without re-validation.

:func:`safe_request` closes that: it follows redirects MANUALLY
(``allow_redirects=False``) and validates EVERY destination — the initial URL and
every redirect hop — through the existing :func:`app.netguard.validate_target`
(the one SSRF implementation; this module never reimplements it) plus an optional
scope predicate. A destination that fails validation is NEVER contacted — the
request to it is not made; a :class:`BlockedDestination` is raised instead, which
is a :class:`requests.exceptions.RequestException` subclass so a scanner's
existing ``except requests.RequestException`` handles it as a skipped fetch.

Security invariant: ``requester(method, u)`` is only ever called for a ``u`` that
has already passed :func:`check_destination`.
"""

from __future__ import annotations

import logging
from typing import Callable, Optional
from urllib.parse import urljoin, urlsplit

import requests

from . import netguard

logger = logging.getLogger("reconx.safe_http")

#: Default maximum number of redirect hops to follow.
DEFAULT_MAX_REDIRECTS = 5

#: HTTP status codes that carry a redirect.
_REDIRECT_CODES = frozenset({301, 302, 303, 307, 308})

#: Schemes a redirect is allowed to move to. Anything else (``file:``,
#: ``gopher:``, ``ftp:``, ``data:`` …) is refused rather than followed.
_ALLOWED_SCHEMES = frozenset({"http", "https"})

#: Callable that validates a URL/host for scope, returning ``(allowed, reason)``.
ScopeCheck = Callable[[str], "tuple[bool, str]"]


class BlockedDestination(requests.exceptions.RequestException):
    """A destination (initial URL or redirect hop) failed SSRF/scope validation.

    Subclasses :class:`requests.exceptions.RequestException` so existing scanner
    error handling treats a blocked destination as a failed request (skipped),
    never as a crash. The blocked URL was NOT contacted.
    """

    def __init__(self, url: str, reason: str):
        self.blocked_url = url
        self.reason = reason
        super().__init__(f"blocked destination {url!r}: {reason}")


def check_destination(url: str, *, scope_check: Optional[ScopeCheck] = None) -> "tuple[bool, str]":
    """The single gate: netguard (always) + an optional scope predicate.

    Delegates SSRF validation to :func:`app.netguard.validate_target` — it strips
    scheme/path/port, checks literal IPs directly, and resolves hostnames to vet
    every A/AAAA address (IPv4/IPv6, private/loopback/link-local/reserved/
    metadata). ``scope_check`` (when supplied) additionally enforces engagement
    scope. Returns ``(allowed, reason)``; never raises.
    """
    allowed, reason = netguard.validate_target(url)
    if not allowed:
        return False, reason
    if scope_check is not None:
        try:
            ok, sreason = scope_check(url)
        except Exception as exc:  # noqa: BLE001 - a scope hook must never crash the guard
            return False, f"scope check error: {exc}"
        if not ok:
            return False, sreason
    return True, "ok"


def safe_request(
    method: str,
    url: str,
    *,
    session: Optional[requests.Session] = None,
    max_redirects: int = DEFAULT_MAX_REDIRECTS,
    scope_check: Optional[ScopeCheck] = None,
    **kwargs,
) -> requests.Response:
    """Perform ``method url``, following redirects only after validating each hop.

    Every destination — the initial URL and each redirect target — must pass
    :func:`check_destination` BEFORE any connection to it is attempted. On
    failure, raises :class:`BlockedDestination` (the blocked URL is never
    contacted). ``allow_redirects=False`` in ``kwargs`` performs a single guarded
    request without following (the initial URL is still validated). Other kwargs
    (``timeout``, ``headers``, ``verify`` …) pass through to ``requests``.

    Returns the final :class:`requests.Response`. Raises
    :class:`requests.exceptions.TooManyRedirects` past ``max_redirects``.
    """
    follow = kwargs.pop("allow_redirects", True)
    requester = session.request if session is not None else requests.request

    # 1. Validate the initial URL BEFORE issuing any request.
    ok, reason = check_destination(url, scope_check=scope_check)
    if not ok:
        logger.warning("safe_http: initial destination blocked (%s): %s", reason, url)
        raise BlockedDestination(url, reason)

    resp = requester(method, url, allow_redirects=False, **kwargs)
    if not follow:
        return resp

    seen = {url}
    hops = 0
    while resp.status_code in _REDIRECT_CODES and resp.headers.get("Location"):
        if hops >= max_redirects:
            raise requests.exceptions.TooManyRedirects(
                f"exceeded {max_redirects} redirects starting from {url}"
            )
        # Resolve the next hop against the CURRENT url (handles absolute,
        # relative-path, and scheme-relative "//host/..." Location values).
        nxt = urljoin(resp.url or url, resp.headers["Location"])
        scheme = urlsplit(nxt).scheme.lower()
        if scheme not in _ALLOWED_SCHEMES:
            logger.warning("safe_http: refusing non-http redirect scheme %r: %s", scheme, nxt)
            raise BlockedDestination(nxt, f"disallowed redirect scheme '{scheme}'")
        if nxt in seen:
            logger.warning("safe_http: redirect loop detected at %s", nxt)
            raise BlockedDestination(nxt, "redirect loop")

        # 2. Validate the next hop BEFORE connecting to it. If blocked, we raise
        #    here and NEVER issue the request to `nxt`.
        ok, reason = check_destination(nxt, scope_check=scope_check)
        if not ok:
            logger.warning("safe_http: redirect blocked (%s): %s -> %s", reason, resp.url, nxt)
            raise BlockedDestination(nxt, reason)

        seen.add(nxt)
        hops += 1
        resp = requester(method, nxt, allow_redirects=False, **kwargs)

    return resp


def safe_get(url: str, **kwargs) -> requests.Response:
    """Convenience wrapper for a guarded ``GET``."""
    return safe_request("GET", url, **kwargs)

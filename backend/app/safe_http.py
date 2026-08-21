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

import ipaddress
import logging
import socket
import threading
from contextlib import contextmanager
from typing import Callable, Optional
from urllib.parse import urljoin, urlsplit

import requests

from . import netguard

logger = logging.getLogger("reconx.safe_http")

# --------------------------------------------------------------------------- #
# DNS-rebinding defense — pin the socket to the pre-vetted IP set.
#
# netguard resolves + vets a host, but requests/urllib3 open the connection by
# re-resolving the hostname, so a low-TTL attacker record can answer a public IP
# at validation time and a private/metadata IP at connect time (TOCTOU). We close
# that by installing a pin-aware ``getaddrinfo`` shim: while a request is in
# flight the calling thread pins ``host -> [vetted ips]``, so the connection's
# re-resolution returns ONLY those vetted addresses. The URL keeps its hostname,
# so the Host header and TLS SNI/cert validation are unchanged. When no pin is
# active the shim delegates verbatim to the real resolver, so non-scanner traffic
# (DB, Redis, SSO, …) is completely unaffected.
# --------------------------------------------------------------------------- #
_pin_state = threading.local()
_orig_getaddrinfo = socket.getaddrinfo
_MISSING = object()


def _guarded_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):  # noqa: A002
    pins = getattr(_pin_state, "pins", None)
    key = host.lower() if isinstance(host, str) else host
    if pins and key in pins:
        entries = []
        for ip in pins[key]:
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                continue
            fam = socket.AF_INET6 if addr.version == 6 else socket.AF_INET
            if family not in (0, socket.AF_UNSPEC) and family != fam:
                continue
            sockaddr = (ip, port) if fam == socket.AF_INET else (ip, port, 0, 0)
            entries.append((fam, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", sockaddr))
        if entries:
            return entries
        # Host is pinned but nothing matches the requested family: fail closed
        # rather than fall through to an unpinned (rebinding-capable) lookup.
        raise socket.gaierror(
            getattr(socket, "EAI_NONAME", -2),
            f"pinned host {host!r} has no vetted address for family {family}",
        )
    return _orig_getaddrinfo(host, port, family, type, proto, flags)


def _install_guarded_resolver() -> None:
    """Install the pin-aware ``getaddrinfo`` shim exactly once (idempotent)."""
    if getattr(socket, "_reconx_pin_installed", False):
        return
    socket.getaddrinfo = _guarded_getaddrinfo
    socket._reconx_pin_installed = True  # type: ignore[attr-defined]


_install_guarded_resolver()


@contextmanager
def _pinned(host: Optional[str], ips):
    """Pin ``host`` to ``ips`` for the current thread while a request runs."""
    if not host or not ips:
        yield
        return
    key = host.lower()
    pins = getattr(_pin_state, "pins", None)
    if pins is None:
        pins = _pin_state.pins = {}
    prev = pins.get(key, _MISSING)
    pins[key] = list(ips)
    try:
        yield
    finally:
        if prev is _MISSING:
            pins.pop(key, None)
        else:
            pins[key] = prev


#: Public alias: pin a host to an ALREADY-VETTED IP set for a raw socket call
#: (e.g. a TLS handshake) that can't go through :func:`safe_request`. The caller
#: MUST have validated the IPs via :func:`app.netguard.resolve_and_validate`
#: first. Example::
#:
#:     ok, _why, vips = netguard.resolve_and_validate(host)
#:     if ok:
#:         with safe_http.pinned(host, vips):
#:             sock = socket.create_connection((host, port))
pinned = _pinned

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


def _guard(url: str, scope_check: Optional[ScopeCheck]) -> "tuple[bool, str, str, list[str]]":
    """netguard (resolve+vet, returning IPs) + optional scope. Never raises.

    Returns ``(allowed, reason, host, ips)`` where ``ips`` is the vetted address
    set to pin the connection to. On refusal ``host``/``ips`` are empty.
    """
    allowed, reason, ips = netguard.resolve_and_validate(url)
    if not allowed:
        return False, reason, "", []
    if scope_check is not None:
        try:
            ok, sreason = scope_check(url)
        except Exception as exc:  # noqa: BLE001 - a scope hook must never crash the guard
            return False, f"scope check error: {exc}", "", []
        if not ok:
            return False, sreason, "", []
    host = urlsplit(url).hostname or netguard._bare_host(url)
    return True, "ok", host, ips


def check_destination(url: str, *, scope_check: Optional[ScopeCheck] = None) -> "tuple[bool, str]":
    """The single gate: netguard (always) + an optional scope predicate.

    Delegates SSRF validation to :func:`app.netguard.resolve_and_validate` — it
    strips scheme/path/port, checks literal IPs directly, and resolves hostnames
    to vet every A/AAAA address (IPv4/IPv6, private/loopback/link-local/reserved/
    CGNAT/metadata incl. IPv4-mapped & NAT64 forms). ``scope_check`` (when
    supplied) additionally enforces engagement scope. Returns ``(allowed,
    reason)``; never raises.
    """
    ok, reason, _host, _ips = _guard(url, scope_check)
    return ok, reason


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

    # 1. Validate the initial URL BEFORE issuing any request, and capture the
    #    vetted IP set so the connection is PINNED to it (no rebinding).
    ok, reason, host, ips = _guard(url, scope_check)
    if not ok:
        logger.warning("safe_http: initial destination blocked (%s): %s", reason, url)
        raise BlockedDestination(url, reason)

    with _pinned(host, ips):
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

        # 2. Validate the next hop BEFORE connecting to it, pinning its vetted
        #    IPs. If blocked, we raise here and NEVER issue the request to `nxt`.
        ok, reason, host, ips = _guard(nxt, scope_check)
        if not ok:
            logger.warning("safe_http: redirect blocked (%s): %s -> %s", reason, resp.url, nxt)
            raise BlockedDestination(nxt, reason)

        seen.add(nxt)
        hops += 1
        with _pinned(host, ips):
            resp = requester(method, nxt, allow_redirects=False, **kwargs)

    return resp


def safe_get(url: str, **kwargs) -> requests.Response:
    """Convenience wrapper for a guarded ``GET``."""
    return safe_request("GET", url, **kwargs)

"""SSRF / egress safety guard for scan targets.

The RECON-X scanners are, by design, pointed at arbitrary attacker-supplied
hosts — that is the whole point of a recon tool. That same power makes the
service a textbook Server-Side Request Forgery (SSRF) primitive if a tenant can
aim it at ``localhost``, an internal RFC 1918 range, or a cloud metadata
endpoint. :func:`validate_target` is the choke point that refuses those before a
single packet leaves the box.

Design notes:

* Dependency-light — only the standard library (:mod:`socket`,
  :mod:`ipaddress`, :mod:`re`) is used, so importing this module can never fail
  for want of a third-party package.
* DNS-aware — a hostname is resolved and **every** returned address is checked,
  which defeats DNS-rebinding style ``foo.example.com -> 127.0.0.1`` tricks.
* Toggleable — when :data:`settings.BLOCK_PRIVATE_TARGETS` is ``False`` the
  private/loopback checks are skipped (for on-prem installs deliberately
  scanning internal ranges), but unresolvable hosts and cloud-metadata IPs are
  *always* rejected.
"""

from __future__ import annotations

import ipaddress
import re
import socket

from .config import settings

# --------------------------------------------------------------------------- #
# Cloud metadata endpoints — always blocked, regardless of BLOCK_PRIVATE_TARGETS
# --------------------------------------------------------------------------- #
#: Well-known link-local metadata service addresses (AWS/GCP/Azure IPv4 + the
#: AWS IPv6 endpoint). Exposed as a module constant for tests and callers.
METADATA_IPS: frozenset[str] = frozenset({"169.254.169.254", "fd00:ec2::254"})

_METADATA_IP_OBJS = {ipaddress.ip_address(ip) for ip in METADATA_IPS}

_SCHEME = re.compile(r"^[a-z][a-z0-9+.\-]*://", re.I)
_SPLIT = re.compile(r"[\s,]+")


def _bare_host(target: str) -> str:
    """Reduce a raw target to a bare host (no scheme, path, or port).

    Mirrors :func:`app.scope._normalize` but is IPv6-aware: a bracketed
    ``[::1]:80`` literal keeps its address, and only a single-colon
    ``host:port`` form has its port stripped (so unbracketed IPv6 literals are
    left intact rather than being truncated at the first colon).
    """
    host = (target or "").strip().lower()
    host = _SCHEME.sub("", host)
    host = host.split("/")[0]  # drop any path/query
    if host.startswith("[") and "]" in host:  # [ipv6] or [ipv6]:port
        host = host[1 : host.index("]")]
    elif host.count(":") == 1:  # host:port or ipv4:port
        host = host.split(":")[0]
    return host.strip()


def _ip_is_dangerous(ip: ipaddress._BaseAddress) -> bool:
    """Return ``True`` if ``ip`` is in a range scans must never reach."""
    if ip in _METADATA_IP_OBJS:
        return True
    if not settings.BLOCK_PRIVATE_TARGETS:
        # Operator opted into internal scanning; only metadata stays blocked.
        return False
    return bool(
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def validate_target(target: str) -> tuple[bool, str]:
    """Validate a single target host for SSRF safety.

    Returns ``(allowed, reason)``. ``allowed`` is ``True`` only when the host
    resolves exclusively to public, routable addresses (or the private checks
    are disabled and it is neither unresolvable nor a metadata endpoint).

    A literal IP is checked directly with no DNS lookup; a hostname is resolved
    via :func:`socket.getaddrinfo` and *every* resulting address must pass.
    """
    host = _bare_host(target)
    if not host:
        return False, "empty target"

    if host == "localhost" or host.endswith(".localhost"):
        if settings.BLOCK_PRIVATE_TARGETS:
            return False, "localhost is not an allowed target"
        # BLOCK_PRIVATE_TARGETS=false → operator opted into internal scanning

    # Literal IP: check directly, skip DNS.
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None

    if literal is not None:
        if _ip_is_dangerous(literal):
            return False, f"target resolves to a blocked address ({host})"
        return True, "ok"

    # Hostname: resolve to all A/AAAA records and vet each one.
    try:
        infos = socket.getaddrinfo(host, None)
    except (socket.gaierror, socket.herror, UnicodeError, OSError):
        return False, "could not resolve host"

    addresses = {info[4][0] for info in infos}
    if not addresses:
        return False, "could not resolve host"

    for addr in addresses:
        addr = addr.split("%")[0]  # strip any IPv6 zone id
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            continue
        if _ip_is_dangerous(ip):
            return False, f"target resolves to a blocked address ({addr})"

    return True, "ok"


def validate_targets(raw: str) -> tuple[bool, str]:
    """Validate a comma/space separated list of targets; every item must pass.

    A tool such as ``httpx``/``nuclei`` may be handed several targets at once.
    The first failing item short-circuits and its reason is returned.
    """
    items = [t for t in _SPLIT.split((raw or "").strip()) if t]
    if not items:
        return False, "empty target"
    for item in items:
        allowed, reason = validate_target(item)
        if not allowed:
            return False, reason
    return True, "ok"

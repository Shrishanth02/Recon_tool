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
#: Cloud-metadata service addresses — ALWAYS blocked, regardless of
#: BLOCK_PRIVATE_TARGETS. AWS/GCP/Azure link-local IPv4, the AWS IPv6 endpoint,
#: and Alibaba Cloud's metadata IP (100.100.100.200, which lives inside the CGNAT
#: 100.64.0.0/10 range and is therefore NOT caught by is_private/is_reserved).
METADATA_IPS: frozenset[str] = frozenset(
    {"169.254.169.254", "fd00:ec2::254", "100.100.100.200"}
)

_METADATA_IP_OBJS = {ipaddress.ip_address(ip) for ip in METADATA_IPS}

#: Carrier-grade NAT / shared address space (RFC 6598). Python's ``is_private``
#: does NOT flag this range on all interpreters, yet it routes to internal/cloud
#: NAT infrastructure (and contains the Alibaba metadata IP), so we block it
#: explicitly under BLOCK_PRIVATE_TARGETS.
_CGNAT_NET = ipaddress.ip_network("100.64.0.0/10")

#: NAT64 well-known prefix (RFC 6052). The low 32 bits embed an IPv4 address, so
#: ``64:ff9b::a9fe:a9fe`` is really 169.254.169.254 — unwrap and re-check.
_NAT64_NET = ipaddress.ip_network("64:ff9b::/96")


def _embedded_ipv4(ip: "ipaddress._BaseAddress"):
    """Return the IPv4 address embedded in an IPv6 wrapper form, else ``None``.

    Covers IPv4-mapped (``::ffff:a.b.c.d``), 6to4 (``2002:V4::``), and NAT64
    (``64:ff9b::/96``) so a dangerous IPv4 address cannot be smuggled past the
    checks by expressing it as IPv6.
    """
    if ip.version != 6:
        return None
    mapped = ip.ipv4_mapped
    if mapped is not None:
        return mapped
    sixto = ip.sixtofour
    if sixto is not None:
        return sixto
    if ip in _NAT64_NET:
        return ipaddress.ip_address(int(ip) & 0xFFFFFFFF)
    return None

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
    """Return ``True`` if ``ip`` is in a range scans must never reach.

    Policy (explicit, so legitimate public scanning is not broken):

    * **Always blocked** (even when ``BLOCK_PRIVATE_TARGETS`` is False): cloud
      metadata endpoints (incl. their IPv4-mapped / NAT64 / 6to4 IPv6 forms).
    * **Blocked only when ``BLOCK_PRIVATE_TARGETS`` is True** (the default):
      private (RFC 1918), loopback, link-local, reserved, multicast, unspecified,
      and CGNAT/shared-address-space (RFC 6598, ``100.64.0.0/10``) — plus any
      IPv6 wrapper that embeds such an IPv4 address.
    * Everything else (public, globally-routable) is allowed.
    """
    # Unwrap IPv4-mapped / 6to4 / NAT64 IPv6 forms and apply the SAME policy to
    # the embedded IPv4 — a dangerous v4 address can't hide inside an IPv6 form.
    embedded = _embedded_ipv4(ip)
    if embedded is not None and _ip_is_dangerous(embedded):
        return True

    if ip in _METADATA_IP_OBJS:
        return True
    if not settings.BLOCK_PRIVATE_TARGETS:
        # Operator opted into internal scanning; only metadata stays blocked.
        return False
    if ip.version == 4 and ip in _CGNAT_NET:
        return True
    return bool(
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def resolve_and_validate(target: str) -> tuple[bool, str, list[str]]:
    """Validate a target AND return the exact vetted IP set to connect to.

    Returns ``(allowed, reason, ips)``. ``ips`` is the de-duplicated list of
    resolved, individually-vetted addresses (a single-element list for a literal
    IP). This is the anti-DNS-rebinding primitive: the host is resolved **once**
    here, every address is checked, and the caller is expected to PIN the
    connection to exactly these IPs (see :mod:`app.safe_http`) so the subsequent
    HTTP request cannot re-resolve to a different (private/metadata) address.

    A literal IP is checked directly with no DNS lookup; a hostname is resolved
    via :func:`socket.getaddrinfo` and *every* resulting address must pass or the
    whole target is refused (``ips`` empty on refusal).
    """
    host = _bare_host(target)
    if not host:
        return False, "empty target", []

    if host == "localhost" or host.endswith(".localhost"):
        if settings.BLOCK_PRIVATE_TARGETS:
            return False, "localhost is not an allowed target", []
        # BLOCK_PRIVATE_TARGETS=false → operator opted into internal scanning

    # Literal IP: check directly, skip DNS.
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None

    if literal is not None:
        if _ip_is_dangerous(literal):
            return False, f"target resolves to a blocked address ({host})", []
        return True, "ok", [str(literal)]

    # Hostname: resolve ONCE to all A/AAAA records and vet each one.
    try:
        infos = socket.getaddrinfo(host, None)
    except (socket.gaierror, socket.herror, UnicodeError, OSError):
        return False, "could not resolve host", []

    ips: list[str] = []
    seen: set[str] = set()
    for info in infos:
        addr = str(info[4][0]).split("%")[0]  # strip any IPv6 zone id
        if addr in seen:
            continue
        seen.add(addr)
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            continue
        if _ip_is_dangerous(ip):
            return False, f"target resolves to a blocked address ({addr})", []
        ips.append(str(ip))

    if not ips:
        return False, "could not resolve host", []
    return True, "ok", ips


def validate_target(target: str) -> tuple[bool, str]:
    """Validate a single target host for SSRF safety (``(allowed, reason)``).

    Thin wrapper over :func:`resolve_and_validate` for callers that only need the
    boolean decision (scope gates, pre-flight checks). Callers that make the
    actual outbound connection should use :func:`resolve_and_validate` and pin
    the returned IPs, or go through :mod:`app.safe_http`, to close the
    resolve-then-connect (DNS-rebinding) gap.
    """
    allowed, reason, _ips = resolve_and_validate(target)
    return allowed, reason


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

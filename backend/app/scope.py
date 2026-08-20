"""Scope enforcement — the legal/ethical guardrail.

A project may declare in-scope targets as domains, wildcard domains, IPs, or
CIDR ranges. When a scope is set, scans are refused for anything that doesn't
match. An empty scope means "unrestricted" (a clear warning is surfaced in the
UI), so the tool is usable for ad-hoc testing but encourages defining scope.
"""

import ipaddress
import re

_SCHEME = re.compile(r"^[a-z]+://", re.I)


def _normalize(target: str) -> str:
    target = (target or "").strip().lower()
    target = _SCHEME.sub("", target)
    target = target.split("/")[0]      # drop path
    target = target.split(":")[0]      # drop port
    return target.strip()


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _match_entry(target: str, entry: str) -> bool:
    entry = (entry or "").strip().lower()
    if not entry:
        return False

    # Global wildcard — the operator explicitly authorizes ANY target. This is
    # the "engagement scope = everything" declaration; it is recorded on the
    # workspace and referenced by the audit log, so the authorization is still
    # attributable even though it permits all hosts.
    if entry in ("*", "*.*", "0.0.0.0/0"):
        return True

    # CIDR range
    if "/" in entry:
        try:
            net = ipaddress.ip_network(entry, strict=False)
            return _is_ip(target) and ipaddress.ip_address(target) in net
        except ValueError:
            return False

    # Wildcard domain: *.example.com  ->  matches example.com and any subdomain
    if entry.startswith("*."):
        base = entry[2:]
        return target == base or target.endswith("." + base)

    # Exact IP / domain, or subdomain of an in-scope domain
    if _is_ip(entry):
        return target == entry
    return target == entry or target.endswith("." + entry)


def check(target: str, scope) -> tuple:
    """Return (allowed: bool, reason: str)."""
    scope = scope or []
    if not scope:
        return True, "No scope defined (unrestricted)."
    host = _normalize(target)
    # A target may be a comma/space separated list — every item must be in scope.
    items = [t for t in re.split(r"[\s,]+", host) if t]
    for item in items or [host]:
        if not any(_match_entry(item, e) for e in scope):
            return False, f"'{item}' is not in this engagement's scope."
    return True, "In scope."

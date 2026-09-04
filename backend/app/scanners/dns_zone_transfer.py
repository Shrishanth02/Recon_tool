"""DNS Zone Transfer attempt — checks if any nameserver exposes full zone data.

A successful zone transfer (AXFR) lets an attacker enumerate every DNS record
in the domain, which is a significant information-disclosure vulnerability.

This scanner uses :mod:`dnspython` (a pure-Python DNS library) rather than the
``dig`` CLI, so it works on any host without external tooling on ``PATH``.
``dnspython`` is imported lazily inside the helper functions so that merely
*importing* this module never fails — if the library is somehow absent the
scanner degrades gracefully with a clear log line instead of an ImportError.

The generator contract is unchanged from the previous ``dig``-based version:
it yields ``log`` / ``error`` / ``result`` events, and the ``result`` payload
keeps the exact same shape::

    {
        "domain": str,
        "vulnerable": bool,
        "vulnerable_nameservers": [str, ...],
        "nameservers": [str, ...],
        "records": [str, ...],     # capped at 200
        "record_count": int,
    }
"""

import threading
from typing import Iterator, Optional

from .base import clean_target, error, log, result

# AXFR socket timeout (seconds) per nameserver attempt.
_XFR_TIMEOUT = 8
# Hard cap on stored record strings to avoid huge WebSocket payloads.
_MAX_RECORDS = 200


def _get_nameservers(domain: str) -> list[str]:
    """Return the authoritative nameservers for *domain* using dnspython.

    dnspython is imported lazily so importing this module never requires it.
    Returns an empty list on any resolution failure (NXDOMAIN, no NS records,
    timeout, or the library being unavailable).
    """
    try:
        import dns.resolver  # lazy import — keeps the module import-safe
    except Exception:  # noqa: BLE001 — degrade gracefully if dnspython is absent
        return []
    try:
        answer = dns.resolver.resolve(domain, "NS")
    except Exception:  # noqa: BLE001 — NXDOMAIN, NoAnswer, Timeout, etc.
        return []
    return sorted({str(rdata.target).rstrip(".") for rdata in answer})


def _resolve_ips(nameserver: str) -> list[str]:
    """Resolve a nameserver hostname to its A/AAAA IP addresses.

    A bare IP is returned as-is. Returns an empty list if nothing resolves.
    """
    try:
        import dns.resolver
    except Exception:  # noqa: BLE001
        return []

    ips: list[str] = []
    for rrtype in ("A", "AAAA"):
        try:
            answer = dns.resolver.resolve(nameserver, rrtype)
        except Exception:  # noqa: BLE001 — no record of this type / timeout
            continue
        ips.extend(str(rdata) for rdata in answer)
    # De-duplicate while preserving order (A records first).
    seen: set[str] = set()
    unique: list[str] = []
    for ip in ips:
        if ip not in seen:
            seen.add(ip)
            unique.append(ip)
    return unique


def stream(target: str, cancel: Optional[threading.Event] = None, **_) -> Iterator[dict]:
    """Attempt an AXFR zone transfer against every nameserver of *target*.

    Yields ``log`` events for progress, an ``error`` event for a bad target,
    and exactly one terminal ``result`` event with the aggregated outcome.
    Respects the ``cancel`` :class:`threading.Event` between nameservers.
    """
    domain = clean_target(target)
    if not domain:
        yield error("A target domain is required.")
        return

    # Verify dnspython is importable up front so we can degrade with a clear
    # message rather than silently finding "no nameservers".
    try:
        import dns.query  # noqa: F401
        import dns.zone  # noqa: F401
        import dns.resolver  # noqa: F401
    except Exception as exc:  # noqa: BLE001
        yield log(f"[WARN] dnspython is not available ({exc}) — skipping DNS zone transfer check.")
        yield result({
            "domain": domain,
            "vulnerable": False,
            "vulnerable_nameservers": [],
            "nameservers": [],
            "records": [],
            "record_count": 0,
        })
        return

    yield log(f"Attempting DNS zone transfer for {domain}")

    nameservers = _get_nameservers(domain)
    if not nameservers:
        yield log("[WARN] No nameservers found (domain does not resolve or has no NS records).")
        yield result({
            "domain": domain,
            "vulnerable": False,
            "vulnerable_nameservers": [],
            "nameservers": [],
            "records": [],
            "record_count": 0,
        })
        return

    yield log(f"Found {len(nameservers)} nameserver(s): {', '.join(nameservers)}")

    import dns.query
    import dns.zone

    vulnerable_ns: list[str] = []
    all_records: list[str] = []

    for ns in nameservers:
        if cancel is not None and cancel.is_set():
            return

        ns_ips = _resolve_ips(ns)
        if not ns_ips:
            yield log(f"[WARN] Could not resolve an IP for {ns} — skipping.")
            continue

        transferred = False
        for ns_ip in ns_ips:
            if cancel is not None and cancel.is_set():
                return
            yield log(f"Trying AXFR from {ns} ({ns_ip})...")
            try:
                zone = dns.zone.from_xfr(
                    dns.query.xfr(ns_ip, domain, timeout=_XFR_TIMEOUT)
                )
            except Exception as exc:  # noqa: BLE001 — refused, timeout, connreset, etc.
                yield log(f"[OK] {ns} ({ns_ip}) refused zone transfer (expected). [{exc}]")
                continue

            # Success — flatten the zone into printable record strings.
            records: list[str] = []
            for name, node in zone.nodes.items():
                for rdataset in node.rdatasets:
                    for rdata in rdataset:
                        records.append(
                            f"{name} {rdataset.ttl} "
                            f"{dns.rdataclass.to_text(rdataset.rdclass)} "
                            f"{dns.rdatatype.to_text(rdataset.rdtype)} {rdata}"
                        )

            transferred = True
            if ns not in vulnerable_ns:
                vulnerable_ns.append(ns)
            all_records.extend(records)
            # CRITICAL log line — preserved verbatim for alerting/detection.
            yield log(
                f"[WARN] ZONE TRANSFER SUCCEEDED via {ns} ({ns_ip})! "
                f"Got {len(records)} record(s)."
            )
            break  # one successful IP is enough for this nameserver

        if not transferred and ns_ips:
            # Already logged per-IP refusals above; nothing more to add.
            pass

    if cancel is not None and cancel.is_set():
        return

    vulnerable = bool(vulnerable_ns)
    if vulnerable:
        yield log(
            f"[ALERT] CRITICAL: Zone transfer is possible via: {', '.join(vulnerable_ns)}\n"
            f"   This exposes ALL DNS records to any external attacker."
        )
    else:
        yield log("[OK] No nameserver allowed zone transfer.")

    yield result({
        "domain": domain,
        "vulnerable": vulnerable,
        "vulnerable_nameservers": vulnerable_ns,
        "nameservers": nameservers,
        "records": all_records[:_MAX_RECORDS],  # cap to avoid huge payloads
        "record_count": len(all_records),
    })

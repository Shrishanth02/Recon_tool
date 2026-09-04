"""WHOIS lookup via python-whois."""

import threading
from typing import Iterator, Optional

import whois

from .base import clean_target, error, log, result


def _as_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v) for v in value]
    return [str(value)]


def lookup(domain: str) -> dict:
    data = whois.whois(domain)
    return {
        "domain": domain,
        "registrar": str(data.registrar),
        "whois_server": str(getattr(data, "whois_server", "")),
        "creation_date": str(data.creation_date),
        "updated_date": str(data.updated_date),
        "expiration_date": str(data.expiration_date),
        "name_servers": _as_list(data.name_servers),
        "status": _as_list(data.status),
        "org": str(getattr(data, "org", "")),
        "country": str(getattr(data, "country", "")),
        "emails": _as_list(data.emails),
        "dnssec": str(getattr(data, "dnssec", "")),
    }


def stream(target: str, cancel: Optional[threading.Event] = None, **_) -> Iterator[dict]:
    domain = clean_target(target)
    if not domain:
        yield error("A target domain is required.")
        return

    yield log(f"Querying WHOIS registry for {domain} ...")
    try:
        data = lookup(domain)
    except Exception as exc:  # noqa: BLE001 - whois raises a variety of errors
        yield error(f"WHOIS lookup failed: {exc}")
        return

    yield log(f"[OK] Registrar: {data['registrar']}")
    yield result(data)

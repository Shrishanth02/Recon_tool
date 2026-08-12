"""Reverse IP lookup via the hackertarget.com API."""

import threading
from typing import Iterator, Optional

import requests

from .base import clean_target, error, log, result


def stream(target: str, cancel: Optional[threading.Event] = None, **_) -> Iterator[dict]:
    ip = clean_target(target)
    if not ip:
        yield error("A target IP or host is required.")
        return

    yield log(f"Looking up domains hosted on {ip} ...")
    try:
        response = requests.get(
            f"https://api.hackertarget.com/reverseiplookup/?q={ip}",
            timeout=15,
        )
    except requests.RequestException as exc:
        yield error(f"Request failed: {exc}")
        return

    text = response.text.strip()
    if not text or "error" in text.lower() or "API count exceeded" in text:
        yield error(text or "No results returned.")
        return

    domains = [line.strip() for line in text.splitlines() if line.strip()]
    for domain in domains:
        yield log(domain)

    yield log(f"✔ Found {len(domains)} domain(s).")
    yield result({"ip": ip, "count": len(domains), "domains": domains})

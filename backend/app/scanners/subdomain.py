"""Subdomain enumeration via subfinder — streams each host as it is found."""

import threading
from typing import Iterator, Optional

from .base import clean_target, error, log, result, stream_command


def stream(target: str, cancel: Optional[threading.Event] = None, **_) -> Iterator[dict]:
    domain = clean_target(target)
    if not domain:
        yield error("A target domain is required.")
        return

    yield log(f"Enumerating subdomains for {domain}")

    found = []
    cmd = ["subfinder", "-d", domain, "-silent"]
    for ev in stream_command(cmd, cancel=cancel):
        if ev["type"] == "log":
            line = ev["data"]
            # The command echo line starts with "$ "; pass it through but only
            # collect real hostnames as results.
            if not line.startswith("$ ") and "." in line and " " not in line:
                found.append(line)
        if ev["type"] != "returncode":
            yield ev

    if cancel is not None and cancel.is_set():
        return

    found = sorted(set(found))
    yield log(f"✔ Found {len(found)} subdomain(s).")
    yield result({"domain": domain, "count": len(found), "subdomains": found})

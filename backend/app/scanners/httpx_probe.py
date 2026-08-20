"""HTTP probing via httpx — resolves which hosts are alive and fingerprints them.

Accepts one target or a list (comma / whitespace / newline separated), which
makes it a natural second stage after subdomain enumeration.
"""

import json
import os
import re
import tempfile
import threading
from typing import Iterator, Optional

from .base import error, log, result, stream_command

_SPLIT = re.compile(r"[\s,]+")


def _targets(raw: str):
    from .base import reject_optionlike

    out = []
    for t in _SPLIT.split(raw or ""):
        t = t.strip()
        if not t:
            continue
        host = t.split("://", 1)[-1].split("/")[0]
        reject_optionlike(host)  # refuse option-like targets (arg-injection guard)
        out.append(t)
    return out


def stream(target: str, cancel: Optional[threading.Event] = None, **_) -> Iterator[dict]:
    targets = _targets(target)
    if not targets:
        yield error("At least one target host/URL is required.")
        return

    yield log(f"Probing {len(targets)} target(s) with httpx ...")

    fd, list_path = tempfile.mkstemp(suffix=".txt", prefix="reconx_httpx_")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write("\n".join(targets))

    rows = []
    try:
        cmd = [
            "httpx",
            "-l", list_path,
            "-json",
            "-silent",
            "-no-color",
            "-title",
            "-status-code",
            "-tech-detect",
            "-web-server",
            "-content-length",
            "-follow-redirects",
            "-timeout", "10",
        ]
        for ev in stream_command(cmd, cancel=cancel, merge_stderr=False):
            if ev["type"] == "log" and not ev["data"].startswith("$ "):
                try:
                    obj = json.loads(ev["data"])
                except json.JSONDecodeError:
                    yield ev
                    continue
                row = {
                    "url": obj.get("url"),
                    "status": obj.get("status_code"),
                    "title": obj.get("title", ""),
                    "webserver": obj.get("webserver", ""),
                    "tech": obj.get("tech", []),
                    "content_length": obj.get("content_length"),
                    "host": obj.get("host", ""),
                }
                rows.append(row)
                tech = ", ".join(row["tech"]) if row["tech"] else ""
                yield log(
                    f"[{row['status']}] {row['url']}  {row['title']}"
                    + (f"  ({tech})" if tech else "")
                )
            elif ev["type"] != "returncode":
                yield ev

        if cancel is not None and cancel.is_set():
            return

        rows.sort(key=lambda r: (r["status"] or 0))
        yield log(f"✔ {len(rows)} live host(s).")
        yield result({"probed": len(targets), "alive": len(rows), "rows": rows})
    finally:
        try:
            os.unlink(list_path)
        except OSError:
            pass

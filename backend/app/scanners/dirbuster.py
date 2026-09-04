"""Directory brute-forcing via ffuf — streams hits live, returns a table."""

import json
import os
import tempfile
import threading
from typing import Iterator, Optional

from .. import config
from .base import ensure_url, error, log, reachable, result, stream_command


def stream(target: str, cancel: Optional[threading.Event] = None, **_) -> Iterator[dict]:
    url = ensure_url(target)
    if not url:
        yield error("A target URL is required.")
        return

    wordlist = config.WORDLIST
    if not wordlist.exists():
        yield error(
            f"Wordlist not found at {wordlist}. Set RECONX_WORDLIST to a valid path."
        )
        return

    # Pre-flight: fuzzing thousands of paths against a dead host just times out
    # on every request for a very long time. Fail fast if it doesn't answer.
    yield log("Checking target reachability ...")
    if not reachable(url):
        yield error(
            f"{url} did not respond — the host appears to be down or blocking "
            "connections, so there is nothing to fuzz."
        )
        return

    yield log(f"Fuzzing {url}/FUZZ with {wordlist.name}")

    fd, json_path = tempfile.mkstemp(suffix=".json", prefix="reconx_ffuf_")
    os.close(fd)
    try:
        cmd = [
            "ffuf",
            "-u", f"{url}/FUZZ",
            "-w", str(wordlist),
            "-mc", "200,204,301,302,307,401,403",
            "-fs", "0",
            # Auto-calibration: ffuf probes random non-existent paths up front and
            # filters responses matching that baseline. Without it, a SPA / soft-404
            # site that serves 200 + the same index.html for EVERY path (very
            # common: Angular/React apps, custom 404s) makes every wordlist entry a
            # "hit" — thousands of false "discovered path" findings. -ac keeps only
            # genuinely distinct responses (e.g. a real /ftp of a different size),
            # so a normal 404-ing site is unaffected while SPA catch-alls stop
            # flooding false positives.
            "-ac",
            "-of", "json",
            "-o", json_path,
        ]
        rc = 0
        # ffuf draws a progress bar on stderr with carriage returns; keep stdout
        # only so the live feed stays clean (one found path per line).
        for ev in stream_command(cmd, cancel=cancel, merge_stderr=False):
            if ev["type"] == "returncode":
                rc = ev["data"]
            else:
                yield ev

        if cancel is not None and cancel.is_set():
            return

        try:
            with open(json_path, "r", encoding="utf-8", errors="replace") as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError):
            yield error(f"ffuf produced no parseable results (exit code {rc}).")
            return

        rows = []
        for item in data.get("results", []):
            rows.append({
                "path": item.get("input", {}).get("FUZZ", ""),
                "status": item.get("status"),
                "size": item.get("length"),
                "words": item.get("words"),
                "lines": item.get("lines"),
                "url": item.get("url"),
            })

        rows.sort(key=lambda r: (r["status"] or 0, r["path"]))
        yield log(f"[OK] Found {len(rows)} path(s).")
        yield result({"target": url, "found": len(rows), "rows": rows})
    finally:
        try:
            os.unlink(json_path)
        except OSError:
            pass

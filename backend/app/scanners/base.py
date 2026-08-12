"""Shared helpers for streaming scanners.

Every scanner is a generator that ``yield``s small event dicts so the
WebSocket layer can forward them to the browser the instant they are
produced. Events have a ``type``:

    {"type": "log",        "data": "<a line of console output>"}
    {"type": "result",     "data": <structured JSON-able result>}
    {"type": "error",      "data": "<human readable error>"}
    {"type": "returncode", "data": <int>}   # internal, not forwarded

Long-running external commands are run with ``subprocess.Popen`` and read
line-by-line so output appears live. A ``threading.Event`` can be passed in
to cancel a scan (e.g. the user hit "Stop" or closed the tab).
"""

import subprocess
import threading
import time
from typing import Iterator, List, Optional

import requests

from .. import config


def log(message: str) -> dict:
    return {"type": "log", "data": message}


def result(data) -> dict:
    return {"type": "result", "data": data}


def error(message) -> dict:
    return {"type": "error", "data": str(message)}


def stream_command(
    cmd: List[str],
    cancel: Optional[threading.Event] = None,
    merge_stderr: bool = True,
    max_seconds: Optional[float] = None,
) -> Iterator[dict]:
    """Run ``cmd``, yielding a ``log`` event per output line.

    Ends with a ``returncode`` event. If ``cancel`` is set while running,
    the process is terminated. A wall-clock ceiling (``max_seconds``, defaulting
    to ``config.SCAN_TIMEOUT``) guarantees no scan can run forever — e.g. a tool
    stuck timing out against an unresponsive host.
    """
    if max_seconds is None:
        max_seconds = config.SCAN_TIMEOUT
    yield log(f"$ {' '.join(cmd)}")

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT if merge_stderr else subprocess.DEVNULL,
            text=True,
            bufsize=1,
            encoding="utf-8",
            errors="replace",
        )
    except FileNotFoundError:
        yield error(
            f"'{cmd[0]}' was not found. Make sure it is installed and on your PATH."
        )
        yield {"type": "returncode", "data": 127}
        return

    # A blocking read on proc.stdout will not notice a cancel request until the
    # next line arrives — which may be never for a quiet process. A watcher
    # thread terminates the process promptly when cancel is set, which unblocks
    # the read loop with EOF.
    watcher_stop = threading.Event()
    timed_out = threading.Event()
    started = time.monotonic()

    def watch():
        while not watcher_stop.wait(0.2):
            if cancel is not None and cancel.is_set():
                if proc.poll() is None:
                    proc.terminate()
                return
            if max_seconds and (time.monotonic() - started) > max_seconds:
                timed_out.set()
                if proc.poll() is None:
                    proc.terminate()
                return

    watcher = threading.Thread(target=watch, daemon=True)
    watcher.start()

    cancelled = False
    try:
        for line in proc.stdout:
            if cancel is not None and cancel.is_set():
                cancelled = True
                break
            line = line.rstrip("\r\n")
            if line:
                yield log(line)
    finally:
        watcher_stop.set()
        if cancel is not None and cancel.is_set():
            cancelled = True
            if proc.poll() is None:
                proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()

    if timed_out.is_set():
        yield log(f"⏱ Scan exceeded the {int(max_seconds)}s time limit and was stopped.")
    elif cancelled:
        yield log("⏹ Scan cancelled by user.")

    yield {"type": "returncode", "data": proc.returncode}


def reachable(target: str, timeout: float = 4.0) -> bool:
    """Return True if the host answers an HTTP(S) request at all.

    A scanner shouldn't grind for minutes/hours against a genuinely dead host,
    but the check must not false-negative a *live* one. Probing over HTTP (the
    same path a browser/curl uses) — rather than a raw TCP connect — is the
    reliable signal: **any** response, even a 403/500, means the host is up and
    worth scanning. Only a connection error or timeout on every candidate URL
    counts as unreachable. This avoids blocking CDN-fronted sites whose raw
    SYN probes are filtered or whose IPv6 addresses are unrouted.
    """
    if "://" in target:
        candidates = [target]
    else:
        candidates = [f"https://{target}", f"http://{target}"]
    headers = {"User-Agent": "Mozilla/5.0 (RECON-X reachability check)"}
    for url in candidates:
        try:
            # Any HTTP response — even 403/500/redirect — proves the host is up.
            # No redirect-following (keeps it to one round-trip) and a short
            # timeout so an unreachable host is ruled out in a few seconds.
            requests.head(url, timeout=timeout, allow_redirects=False, headers=headers)
            return True
        except requests.RequestException:
            continue
    return False


def clean_target(value: str) -> str:
    """Strip scheme and path, leaving a bare host/domain/ip."""
    value = (value or "").strip()
    value = value.replace("https://", "").replace("http://", "")
    return value.split("/")[0].strip()


def ensure_url(value: str) -> str:
    """Guarantee the value has an http(s) scheme."""
    value = (value or "").strip()
    if not value.startswith(("http://", "https://")):
        value = "https://" + value
    return value

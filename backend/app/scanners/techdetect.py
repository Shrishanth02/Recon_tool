"""Technology fingerprinting via HTTP headers + builtwith."""

import threading
from typing import Iterator, Optional

import requests
from builtwith import builtwith

from .base import ensure_url, error, log, result


def stream(target: str, cancel: Optional[threading.Event] = None, **_) -> Iterator[dict]:
    url = ensure_url(target)
    if not url:
        yield error("A target URL is required.")
        return

    yield log(f"Requesting {url} ...")
    try:
        response = requests.head(
            url,
            headers={"User-Agent": "Mozilla/5.0 (RECON-X)"},
            timeout=15,
            allow_redirects=True,
        )
    except requests.RequestException as exc:
        yield error(f"Request failed: {exc}")
        return

    header_lines = [f"HTTP/1.1 {response.status_code} {response.reason}"]
    for key, value in response.headers.items():
        header_lines.append(f"{key}: {value}")
        yield log(f"{key}: {value}")

    yield log("Fingerprinting technology stack ...")
    # builtwith fetches the page with urllib and has NO timeout of its own, so a
    # slow/unresponsive page would hang the scan forever. Run it in a worker
    # thread and give up after a bound — the HTTP-header result is still returned.
    tech = {}
    box: dict = {}

    def _fingerprint():
        try:
            box["tech"] = builtwith(url)
        except Exception as exc:  # noqa: BLE001 - builtwith can raise broadly
            box["error"] = str(exc)

    worker = threading.Thread(target=_fingerprint, daemon=True)
    worker.start()
    worker.join(timeout=20)
    if worker.is_alive():
        yield log("(technology fingerprinting timed out — reporting HTTP headers only)")
    elif "error" in box:
        yield log(f"(builtwith could not analyse the page: {box['error']})")
    else:
        tech = box.get("tech") or {}

    yield log(f"✔ Detected {len(tech)} technology categor(ies).")
    yield result({
        "url": url,
        "status_code": response.status_code,
        "terminal_output": "\n".join(header_lines),
        "detected_tech": tech,
    })

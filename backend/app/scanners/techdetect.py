"""Technology fingerprinting via HTTP headers + builtwith."""

import threading
from typing import Iterator, Optional

import requests
from builtwith import builtwith

from .. import safe_http
from .base import ensure_url, error, log, result


def stream(target: str, cancel: Optional[threading.Event] = None, **_) -> Iterator[dict]:
    url = ensure_url(target)
    if not url:
        yield error("A target URL is required.")
        return

    yield log(f"Requesting {url} ...")
    try:
        # GET (not HEAD) so we capture the body ONCE through the netguard-pinned,
        # redirect-guarded safe client, then hand that already-vetted HTML to
        # builtwith below — builtwith must never do its OWN urllib fetch (see the
        # _fingerprint note).
        response = safe_http.safe_request(
            "GET",
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
    # SSRF/rebinding: builtwith(url) would do its OWN urllib fetch — with its own
    # DNS resolution and redirect-following, on a worker thread where the safe_http
    # DNS pin (thread-local) does NOT apply — so it could reach a private/metadata
    # IP that netguard already vetted the safe GET away from. Feed it the HTML we
    # ALREADY fetched safely instead, so it parses that and never touches the
    # network. (A bounded worker thread is kept as belt-and-suspenders for a
    # pathological parse.)
    _safe_html = response.text or ""
    _safe_headers = dict(response.headers)
    tech = {}
    box: dict = {}

    def _fingerprint():
        try:
            box["tech"] = builtwith(url, headers=_safe_headers, html=_safe_html)
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

"""The generic HTTP detection connector (Purple-Team P3).

:class:`HttpConnector` targets any SIEM/log platform that exposes a search over
HTTP returning JSON with a hit count — the lowest-common-denominator integration
before a first-class Splunk/Elastic connector is wired up. It POSTs (or GETs) a
templated query to a search URL and reads a hit count out of the JSON response;
a non-zero count means the emulated technique was detected.

Config
------
``{
    "search_url": "https://siem.example/api/search",
    "method": "POST",                       # or "GET"; default POST
    "headers": {"Authorization": "Bearer ..."},
    "body_template": "... {technique_id} ... {marker} ... {since} ...",
    "count_path": "total",                  # dot-path into the JSON; default "total"
    "auth": ["user", "pass"]                # optional HTTP basic auth pair
}``

``body_template`` supports ``{technique_id}``, ``{marker}`` and ``{since}``
placeholders. On GET the rendered template is sent as the ``q`` query parameter;
on POST it is sent as the request body (JSON if it parses as JSON, else raw).

``requests`` is imported lazily inside :meth:`query_detections` so importing this
module never requires the dependency, and every network failure is swallowed
into a ``detected=False`` result (the connector never raises).
"""

from __future__ import annotations

import json
from typing import Any

from .base import Connector

# Short timeout: a detection query must never hang a validation run.
_TIMEOUT_SECONDS: float = 8.0


def _dig(obj: Any, dot_path: str) -> Any:
    """Walk a dotted ``dot_path`` into nested dicts/lists; ``None`` if absent.

    ``"hits.total.value"`` descends dict keys; numeric segments index into lists
    (``"results.0.count"``). Any misstep (missing key, wrong type, bad index)
    yields ``None`` rather than raising.
    """
    cur = obj
    for part in (dot_path or "").split("."):
        if part == "":
            continue
        if isinstance(cur, dict):
            cur = cur.get(part)
        elif isinstance(cur, list):
            try:
                cur = cur[int(part)]
            except (ValueError, IndexError):
                return None
        else:
            return None
        if cur is None:
            return None
    return cur


def _as_count(value: Any) -> int:
    """Coerce a JSON count value to a non-negative int (0 on anything odd)."""
    if isinstance(value, bool):  # bool is an int subclass — treat True as 1 hit
        return 1 if value else 0
    if isinstance(value, (int, float)):
        return max(0, int(value))
    if isinstance(value, list):
        return len(value)
    try:
        return max(0, int(str(value).strip()))
    except (TypeError, ValueError):
        return 0


class HttpConnector(Connector):
    """A generic JSON-over-HTTP SIEM search connector."""

    ctype = "http"

    def _render(self, template: str, technique_id: str, marker: str, since_iso: str) -> str:
        """Fill the ``{technique_id}/{marker}/{since}`` placeholders in ``template``."""
        text = str(template or "")
        return (
            text.replace("{technique_id}", str(technique_id or ""))
            .replace("{marker}", str(marker or ""))
            .replace("{since}", str(since_iso or ""))
        )

    def query_detections(
        self,
        technique_id: str,
        marker: str,
        since_iso: str,
        target: str,
    ) -> dict[str, Any]:
        """POST/GET a templated search and read the hit count out of the JSON."""
        search_url = (self.config.get("search_url") or "").strip()
        if not search_url:
            return self._result(False, evidence="http: no search_url configured")

        method = (self.config.get("method") or "POST").upper()
        headers = self.config.get("headers") or {}
        count_path = self.config.get("count_path") or "total"
        auth = self.config.get("auth")
        auth_tuple = tuple(auth) if isinstance(auth, (list, tuple)) and len(auth) == 2 else None
        rendered = self._render(
            self.config.get("body_template") or "", technique_id, marker, since_iso
        )

        try:
            import requests  # lazy: importing this module must not require requests
        except Exception as exc:  # pragma: no cover - requests is a hard dep in prod
            return self._result(False, evidence=f"http: requests unavailable ({exc})")

        try:
            if method == "GET":
                resp = requests.get(
                    search_url,
                    params={"q": rendered},
                    headers=headers,
                    auth=auth_tuple,
                    timeout=_TIMEOUT_SECONDS,
                )
            else:
                # Send JSON when the rendered template parses as JSON, else raw text.
                json_body = None
                data_body = None
                try:
                    json_body = json.loads(rendered) if rendered.strip() else None
                except (ValueError, TypeError):
                    data_body = rendered
                resp = requests.post(
                    search_url,
                    json=json_body,
                    data=data_body,
                    headers=headers,
                    auth=auth_tuple,
                    timeout=_TIMEOUT_SECONDS,
                )
        except Exception as exc:
            return self._result(False, evidence=f"http: request failed ({exc})")

        status_code = getattr(resp, "status_code", 0)
        if status_code >= 400:
            return self._result(
                False, evidence=f"http: search returned HTTP {status_code}"
            )

        try:
            payload = resp.json()
        except Exception as exc:
            return self._result(False, evidence=f"http: non-JSON response ({exc})")

        count = _as_count(_dig(payload, count_path))
        detected = count > 0
        evidence = (
            f"http: {count} hit(s) at '{count_path}' (HTTP {status_code})"
            if detected
            else f"http: 0 hits at '{count_path}' (HTTP {status_code})"
        )
        return self._result(detected, count=count, evidence=evidence)

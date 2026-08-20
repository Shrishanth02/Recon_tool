"""The Splunk detection connector (Purple-Team P3).

:class:`SplunkConnector` runs a *oneshot* search against a Splunk deployment's
REST API and reports whether the emulated technique surfaced any events. It is a
real implementation — it activates the moment valid credentials are supplied —
but needs a live Splunk to actually return hits, so in this environment it is
import-safe and selectable rather than exercised.

Config
------
``{"base_url": "https://splunk.example:8089", "token": "<bearer>", "index": "main"}``

The search is a blocking oneshot job::

    POST {base_url}/services/search/jobs
        search=search index={index} "{marker}" "{technique_id}"
               earliest={since} | head 1
        output_mode=json
        exec_mode=oneshot

Detection is ``results`` being non-empty. ``requests`` is imported lazily and
**every** error path (missing config, network, auth, parse) collapses to
``detected=False`` — the connector never raises.
"""

from __future__ import annotations

from typing import Any

from .base import Connector

_TIMEOUT_SECONDS: float = 15.0


class SplunkConnector(Connector):
    """A real Splunk REST oneshot-search connector (needs live creds to hit)."""

    ctype = "splunk"

    def query_detections(
        self,
        technique_id: str,
        marker: str,
        since_iso: str,
        target: str,
    ) -> dict[str, Any]:
        """Run a Splunk oneshot search filtered by marker + technique + time."""
        base_url = (self.config.get("base_url") or "").strip().rstrip("/")
        token = (self.config.get("token") or "").strip()
        index = (self.config.get("index") or "main").strip() or "main"
        if not base_url or not token:
            return self._result(
                False, evidence="splunk: base_url and token are required"
            )

        # A conservative, injection-safe-ish search string. The marker and
        # technique id are quoted literals; earliest bounds the window.
        search = (
            f'search index={index} "{marker}" "{technique_id}" '
            f'earliest="{since_iso}" | head 1'
        )

        try:
            import requests  # lazy: SIEM libs must not be required at import time
        except Exception as exc:  # pragma: no cover
            return self._result(False, evidence=f"splunk: requests unavailable ({exc})")

        try:
            resp = requests.post(
                f"{base_url}/services/search/jobs",
                data={
                    "search": search,
                    "output_mode": "json",
                    "exec_mode": "oneshot",
                },
                headers={"Authorization": f"Bearer {token}"},
                timeout=_TIMEOUT_SECONDS,
                verify=self.config.get("verify", True),
            )
        except Exception as exc:
            return self._result(False, evidence=f"splunk: request failed ({exc})")

        status_code = getattr(resp, "status_code", 0)
        if status_code >= 400:
            return self._result(
                False, evidence=f"splunk: search returned HTTP {status_code}"
            )

        try:
            payload = resp.json()
        except Exception as exc:
            return self._result(False, evidence=f"splunk: non-JSON response ({exc})")

        results = payload.get("results") if isinstance(payload, dict) else None
        count = len(results) if isinstance(results, list) else 0
        detected = count > 0
        return self._result(
            detected,
            count=count,
            evidence=(
                f"splunk: {count} event(s) in index={index}"
                if detected
                else f"splunk: no events in index={index}"
            ),
        )

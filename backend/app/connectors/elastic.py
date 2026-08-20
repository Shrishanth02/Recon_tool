"""The Elasticsearch detection connector (Purple-Team P3).

:class:`ElasticConnector` queries an Elasticsearch index for events matching the
emulation marker within the emulation window and reports whether any were found.
Like the Splunk connector it is a real implementation gated on live credentials:
it imports cleanly and is selectable everywhere, but only returns true hits
against a running cluster.

Config
------
``{"base_url": "https://es.example:9200", "api_key": "<key>", "index": "logs-*"}``

The query is a bool filter on the marker (multi-field ``query_string``) plus a
``@timestamp >= since`` range::

    POST {base_url}/{index}/_search
    {"size": 1, "query": {"bool": {"filter": [
        {"query_string": {"query": "<marker> AND <technique_id>"}},
        {"range": {"@timestamp": {"gte": "<since>"}}}
    ]}}}

Detection is ``hits.total.value > 0``. ``requests`` is imported lazily and every
error path collapses to ``detected=False`` — the connector never raises.
"""

from __future__ import annotations

from typing import Any

from .base import Connector

_TIMEOUT_SECONDS: float = 15.0


class ElasticConnector(Connector):
    """A real Elasticsearch ``_search`` connector (needs live creds to hit)."""

    ctype = "elastic"

    def query_detections(
        self,
        technique_id: str,
        marker: str,
        since_iso: str,
        target: str,
    ) -> dict[str, Any]:
        """Search an index for marker+technique events since the emulation start."""
        base_url = (self.config.get("base_url") or "").strip().rstrip("/")
        api_key = (self.config.get("api_key") or "").strip()
        index = (self.config.get("index") or "").strip()
        if not base_url or not index:
            return self._result(
                False, evidence="elastic: base_url and index are required"
            )

        timestamp_field = self.config.get("timestamp_field") or "@timestamp"
        query_string = f'"{marker}" AND "{technique_id}"'
        body = {
            "size": 1,
            "track_total_hits": True,
            "query": {
                "bool": {
                    "filter": [
                        {"query_string": {"query": query_string}},
                        {"range": {timestamp_field: {"gte": since_iso}}},
                    ]
                }
            },
        }

        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"ApiKey {api_key}"

        try:
            import requests  # lazy: SIEM libs must not be required at import time
        except Exception as exc:  # pragma: no cover
            return self._result(False, evidence=f"elastic: requests unavailable ({exc})")

        try:
            resp = requests.post(
                f"{base_url}/{index}/_search",
                json=body,
                headers=headers,
                timeout=_TIMEOUT_SECONDS,
                verify=self.config.get("verify", True),
            )
        except Exception as exc:
            return self._result(False, evidence=f"elastic: request failed ({exc})")

        status_code = getattr(resp, "status_code", 0)
        if status_code >= 400:
            return self._result(
                False, evidence=f"elastic: search returned HTTP {status_code}"
            )

        try:
            payload = resp.json()
        except Exception as exc:
            return self._result(False, evidence=f"elastic: non-JSON response ({exc})")

        total = 0
        if isinstance(payload, dict):
            hits = payload.get("hits", {})
            total_obj = hits.get("total") if isinstance(hits, dict) else None
            if isinstance(total_obj, dict):
                total = int(total_obj.get("value", 0) or 0)
            elif isinstance(total_obj, (int, float)):  # ES <7 returned a bare int
                total = int(total_obj)

        detected = total > 0
        return self._result(
            detected,
            count=total,
            evidence=(
                f"elastic: {total} hit(s) in index={index}"
                if detected
                else f"elastic: no hits in index={index}"
            ),
        )

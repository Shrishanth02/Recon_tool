"""Observability primitives: request ids, structured logging, and metrics.

This module is deliberately dependency-light. Logging and request-id helpers use
only the standard library. Prometheus metrics are *optional*: ``prometheus_client``
is imported lazily and, when it is not installed, every metric operation degrades
to a cheap no-op and :func:`render_metrics` returns a small plain-text stub. The
module therefore imports cleanly with or without ``prometheus_client`` present,
which keeps the app (and the existing test suite) working unchanged.

Public surface
--------------
* :func:`request_id` — generate a short, URL-safe correlation id.
* :func:`configure_logging` — install a plain or JSON access-log formatter.
* :func:`record_request` — count an HTTP request and observe its latency.
* :func:`record_scan` — count a scanner execution by tool/status.
* :func:`render_metrics` — render the Prometheus exposition, ``(body, content_type)``.
"""

from __future__ import annotations

import json
import logging
import sys
import time
import uuid
from typing import Any

__all__ = [
    "request_id",
    "configure_logging",
    "record_request",
    "record_scan",
    "render_metrics",
    "prometheus_available",
]

# --------------------------------------------------------------------------- #
# Correlation ids
# --------------------------------------------------------------------------- #
def request_id() -> str:
    """Return a fresh short correlation id (32 hex chars, no dashes)."""
    return uuid.uuid4().hex


# --------------------------------------------------------------------------- #
# Structured / plain logging
# --------------------------------------------------------------------------- #
_ACCESS_LOGGER_NAME = "reconx.access"


class _JsonLogFormatter(logging.Formatter):
    """Format a log record as a single-line JSON object.

    Any keys attached to the record via ``logger.info(msg, extra={...})`` under
    the reserved ``extra`` mapping are merged into the emitted object, so access
    logs can carry structured fields (method, path, status, duration, ...).
    """

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": time.strftime(
                "%Y-%m-%dT%H:%M:%S", time.gmtime(record.created)
            ),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        fields = getattr(record, "fields", None)
        if isinstance(fields, dict):
            payload.update(fields)
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str, separators=(",", ":"))


def configure_logging(json_logs: bool = False) -> logging.Logger:
    """Configure and return the RECON-X access logger.

    ``json_logs`` selects a structured (JSON) formatter; otherwise a compact
    plain-text formatter is used. The logger is idempotently (re)configured with
    a single stdout handler and does not propagate to the root logger, so it
    will not double-emit under uvicorn/pytest.
    """
    logger = logging.getLogger(_ACCESS_LOGGER_NAME)
    logger.setLevel(logging.INFO)
    logger.propagate = False

    # Reset handlers so repeated calls (e.g. reload) don't stack duplicates.
    for handler in list(logger.handlers):
        logger.removeHandler(handler)

    handler = logging.StreamHandler(stream=sys.stdout)
    if json_logs:
        handler.setFormatter(_JsonLogFormatter())
    else:
        handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")
        )
    logger.addHandler(handler)
    return logger


def access_logger() -> logging.Logger:
    """Return the shared access logger, configuring it lazily if needed."""
    logger = logging.getLogger(_ACCESS_LOGGER_NAME)
    if not logger.handlers:
        configure_logging(json_logs=False)
    return logger


# --------------------------------------------------------------------------- #
# Prometheus metrics (optional)
# --------------------------------------------------------------------------- #
# The real objects are created only if prometheus_client imports successfully.
# Everything below treats their absence as a no-op so callers never branch.
prometheus_available: bool = False
REGISTRY: Any = None
_HTTP_REQUESTS: Any = None
_SCANS: Any = None
_HTTP_LATENCY: Any = None
_CONTENT_TYPE_LATEST: str = "text/plain; version=0.0.4; charset=utf-8"

try:  # pragma: no cover - exercised indirectly depending on the environment
    import prometheus_client as _prom

    prometheus_available = True
    REGISTRY = _prom.CollectorRegistry()
    _HTTP_REQUESTS = _prom.Counter(
        "reconx_http_requests_total",
        "Total HTTP requests processed by the RECON-X API.",
        ["method", "path", "status"],
        registry=REGISTRY,
    )
    _SCANS = _prom.Counter(
        "reconx_scans_total",
        "Total scanner executions by tool and terminal status.",
        ["tool", "status"],
        registry=REGISTRY,
    )
    _HTTP_LATENCY = _prom.Histogram(
        "reconx_http_request_seconds",
        "HTTP request latency in seconds.",
        ["method", "path"],
        registry=REGISTRY,
    )
    _CONTENT_TYPE_LATEST = _prom.CONTENT_TYPE_LATEST
except Exception:  # ImportError, or any init failure -> stay in no-op mode.
    prometheus_available = False


def record_request(
    method: str, path: str, status: int, duration_seconds: float
) -> None:
    """Record one HTTP request's method/path/status and its latency.

    No-op when ``prometheus_client`` is unavailable. ``path`` should be a
    low-cardinality route template (or a coarse bucket) rather than a raw URL to
    avoid unbounded label growth.
    """
    if not prometheus_available:
        return
    try:
        _HTTP_REQUESTS.labels(
            method=method, path=path, status=str(status)
        ).inc()
        _HTTP_LATENCY.labels(method=method, path=path).observe(
            max(0.0, float(duration_seconds))
        )
    except Exception:
        # Metrics must never break request handling.
        pass


def record_scan(tool: str, status: str) -> None:
    """Record one scanner execution by ``tool`` and terminal ``status``.

    No-op when ``prometheus_client`` is unavailable.
    """
    if not prometheus_available:
        return
    try:
        _SCANS.labels(tool=tool or "unknown", status=status or "unknown").inc()
    except Exception:
        pass


def render_metrics() -> tuple[bytes, str]:
    """Render the Prometheus exposition format.

    Returns ``(body, content_type)``. When ``prometheus_client`` is not
    installed a small plain-text stub is returned so the ``/metrics`` endpoint
    still responds (documenting that metrics are disabled) instead of 500-ing.
    """
    if not prometheus_available:
        body = b"# RECON-X metrics disabled (prometheus_client not installed)\n"
        return body, "text/plain; version=0.0.4; charset=utf-8"
    try:
        return _prom.generate_latest(REGISTRY), _CONTENT_TYPE_LATEST
    except Exception:
        return b"# RECON-X metrics unavailable\n", _CONTENT_TYPE_LATEST

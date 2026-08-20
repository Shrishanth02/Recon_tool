"""Detection correlation engine (Purple-Team P3, BLUE side).

This is the join between the RED and BLUE halves of the platform. The SAFE
emulation engine (P2) recorded, per :class:`~app.models.EmulationRun`, which
ATT&CK techniques it fired and how each one landed
(:class:`~app.models.TechniqueResult`). Here we take that run plus a
:class:`~app.connectors.base.Connector` and ask the defender's SIEM/EDR, for each
technique, "did you detect it?" — then roll the answers into a detection-coverage
summary.

The single entry point is :func:`validate_emulation`. It is deliberately
persistence-free: it reads the ORM run object and calls the connector, but never
touches the database. The router persists the returned results as
:class:`~app.models.DetectionResult` rows.

Only techniques that were actually exercised count toward coverage. A
``TechniqueResult`` whose emulated ``status`` is ``executed`` (telemetry was
generated) or ``blocked`` (the target refused it — still a detectable event) is
in scope; ``skipped``/``failed`` techniques never produced attributable traffic
and are excluded entirely.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .connectors.base import DEFAULT_MARKER, Connector

# The marker header the emulation engine stamps and the connectors search for.
MARKER: str = DEFAULT_MARKER

# Emulated statuses that produced attributable telemetry and thus *should* have
# been detectable. Everything else (skipped/failed) is excluded from scoring.
_COUNTED_STATUSES: frozenset[str] = frozenset({"executed", "blocked"})


def _since_iso(run: Any) -> str:
    """Return the run's start time as an ISO-8601 string (now-UTC fallback).

    ``EmulationRun.started_at`` is a timezone-aware datetime, but be defensive:
    accept a datetime, a preformatted string, or nothing at all.
    """
    started = getattr(run, "started_at", None)
    if isinstance(started, datetime):
        return started.isoformat()
    if isinstance(started, str) and started.strip():
        return started.strip()
    return datetime.now(timezone.utc).isoformat()


def validate_emulation(
    db: Any,
    run: Any,
    connector: Connector,
    window_seconds: int = 600,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Correlate an emulation run against a SIEM/EDR connector.

    For every counted :class:`~app.models.TechniqueResult` of ``run`` this calls
    ``connector.query_detections(technique_id, marker=MARKER, since=<run start>,
    target=run.target)`` and builds a per-technique detection dict. It then
    computes an aggregate coverage summary.

    Parameters
    ----------
    db:
        The database session. Accepted for interface symmetry with the rest of
        the CRUD/engine layer and possible future lookups; this function performs
        **no** writes and no queries (it reads ``run.technique_results``).
    run:
        The :class:`~app.models.EmulationRun` to validate. Its
        ``technique_results`` relationship is consumed in order.
    connector:
        A resolved :class:`~app.connectors.base.Connector`. Its
        ``query_detections`` never raises, so this function won't either.
    window_seconds:
        Advisory detection window length (seconds) from the run start. Recorded
        in the summary as ``window_seconds`` for the caller/UI; the lower time
        bound handed to the connector is the run's ``started_at``.

    Returns
    -------
    tuple[list[dict], dict]
        ``(results, summary)`` where each ``results`` entry is::

            {"technique_id", "technique_name", "tactic", "emulated_status",
             "detected": bool, "count": int, "source": str, "evidence": str}

        and ``summary`` is::

            {"total": n, "detected": d, "missed": n - d,
             "coverage_pct": round(100 * d / n),   # 0 when n == 0
             "window_seconds": window_seconds, "source": <connector ctype>}
    """
    since = _since_iso(run)
    target = getattr(run, "target", "") or ""
    source = getattr(connector, "ctype", "") or "connector"

    results: list[dict[str, Any]] = []
    detected_count = 0

    for tr in getattr(run, "technique_results", []) or []:
        emulated_status = getattr(tr, "status", "") or ""
        # Only score techniques that actually generated attributable telemetry.
        if emulated_status not in _COUNTED_STATUSES:
            continue

        technique_id = getattr(tr, "technique_id", "") or ""
        outcome = connector.query_detections(
            technique_id,
            MARKER,
            since,
            target,
        )
        detected = bool(outcome.get("detected", False))
        if detected:
            detected_count += 1

        results.append(
            {
                "technique_id": technique_id,
                "technique_name": getattr(tr, "technique_name", "") or "",
                "tactic": getattr(tr, "tactic", "") or "",
                "emulated_status": emulated_status,
                "detected": detected,
                "count": int(outcome.get("count", 0) or 0),
                "source": outcome.get("source") or source,
                "evidence": outcome.get("evidence", "") or "",
            }
        )

    total = len(results)
    missed = total - detected_count
    coverage_pct = round(100 * detected_count / total) if total else 0
    summary = {
        "total": total,
        "detected": detected_count,
        "missed": missed,
        "coverage_pct": coverage_pct,
        "window_seconds": int(window_seconds or 0),
        "source": source,
    }
    return results, summary

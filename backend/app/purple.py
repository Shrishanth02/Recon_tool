"""Continuous purple-loop orchestration + drift alerting (Purple-Team P4).

This module fuses the RED and BLUE halves of the platform into a single,
one-call *purple run*: it fires the SAFE ATT&CK emulation engine (P2) at an
authorized target, persists the run, and — when a detection connector is
supplied — immediately validates it against the defender's SIEM/EDR (P3) and
records the detected/missed verdicts. It then compares the fresh coverage to the
previous purple run for the same workspace and, on a regression, dispatches a
``detection_drift`` alert to the org's notification channels.

Public surface
--------------
* :func:`run_purple` — emulate (+ optionally validate) in one shot.

Everything is persistence-aware but **commit-free**: like the emulation and
detection engines it flushes rows into the caller's session and leaves the commit
to the router/worker that owns the transaction. Scope + SSRF/netguard + billing
gating is the caller's job (the router and the scheduler both do it before
calling in here). Nothing at module scope imports a third-party SIEM SDK, so this
module — and therefore ``app.main`` / ``app.worker`` — stays import-safe.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import exists, select

from . import connectors, crud, detection, models, notify

__all__ = ["run_purple", "chain_triage", "DRIFT_EVENT_TYPE"]

#: Severity ordering used to rank triaged findings for the compact ``top`` list.
_SEV_RANK: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}

#: The notification event type emitted when coverage regresses between purple
#: runs. Channels subscribe to it (or to ``"*"``) to receive drift alerts.
DRIFT_EVENT_TYPE: str = "detection_drift"


def _live_connector(connector: Any) -> Any | None:
    """Resolve ``connector`` to a live :class:`~app.connectors.base.Connector`.

    Accepts either an already-instantiated connector (anything exposing
    ``query_detections``) or a :class:`~app.models.DetectionConnector` ORM row,
    from which a live connector is built via :func:`app.connectors.get_connector`.
    Returns ``None`` when a connector can't be constructed (unknown ``ctype`` or a
    missing row) so a broken connector degrades to "no validation" rather than
    raising into the run.
    """
    if connector is None:
        return None
    if hasattr(connector, "query_detections"):
        return connector
    ctype = getattr(connector, "ctype", None)
    if not ctype:
        return None
    config = getattr(connector, "config", None) or {}
    try:
        return connectors.get_connector(ctype, config)
    except Exception:  # noqa: BLE001 - bad ctype/config -> skip validation safely
        return None


def run_purple(
    db: Any,
    workspace: Any,
    target: str,
    connector: Any,
    created_by: int | None,
    technique_ids: list[str] | None = None,
) -> tuple[models.EmulationRun, list[models.DetectionResult], dict[str, Any]]:
    """Run one continuous purple loop: emulate, then optionally validate.

    Parameters
    ----------
    db:
        The database session. Rows are flushed but **not** committed — the caller
        owns the transaction.
    workspace:
        The :class:`~app.models.Workspace` ORM object (its ``id``/``org_id`` are
        used). Scope + netguard + billing must already be checked by the caller.
    target:
        The authorized target host/URL to emulate against.
    connector:
        The detection connector to validate with, or ``None`` to skip validation.
        May be a :class:`~app.models.DetectionConnector` ORM row (its ``id`` is
        recorded on the persisted results) or a pre-built live connector.
    created_by:
        The acting user id recorded on the emulation run (nullable).
    technique_ids:
        Optional subset of emulation ids (``["E1", "E4"]``); ``None`` runs the
        whole registry.

    Returns
    -------
    tuple
        ``(emulation_run, detection_results, summary)``. ``detection_results`` is
        the list of persisted :class:`~app.models.DetectionResult` rows (empty
        when no connector was given). ``summary`` carries the emulation tallies
        plus, when validated, ``detected``/``missed``/``coverage_pct`` (all
        ``None`` when unvalidated) and a ``drift`` key holding the dispatched
        drift event (or ``None``).
    """
    from . import emulation  # local import keeps app.purple cheap to import

    # --- RED: emulate + persist. ------------------------------------------- #
    run = crud.create_emulation_run(db, workspace.id, created_by, target)
    outcome = emulation.run_emulation(target, technique_ids)
    for result in outcome["results"]:
        crud.save_technique_result(db, run.id, result)
    crud.finish_emulation_run(
        db,
        run,
        executed=outcome["executed"],
        blocked=outcome["blocked"],
        failed=outcome["failed"],
        summary=outcome,
    )
    # Reload so the ``technique_results`` relationship reflects the just-flushed
    # child rows when the detection engine iterates them.
    db.flush()
    db.refresh(run)

    summary: dict[str, Any] = {
        "emulation_run_id": run.id,
        "target": target,
        "executed": outcome["executed"],
        "blocked": outcome["blocked"],
        "failed": outcome["failed"],
        "validated": False,
        "detected": None,
        "missed": None,
        "coverage_pct": None,
        "drift": None,
    }

    detection_results: list[models.DetectionResult] = []

    # --- BLUE: validate + persist (only when a usable connector is given). -- #
    live = _live_connector(connector)
    if live is not None:
        det_results, det_summary = detection.validate_emulation(db, run, live)
        connector_id = getattr(connector, "id", None)
        crud.save_detection_results(db, run.id, connector_id, det_results)
        db.flush()
        detection_results = crud.list_detection_results(db, run.id)

        summary.update(
            {
                "validated": True,
                "total": det_summary["total"],
                "detected": det_summary["detected"],
                "missed": det_summary["missed"],
                "coverage_pct": det_summary["coverage_pct"],
                "window_seconds": det_summary["window_seconds"],
                "source": det_summary["source"],
            }
        )

        # --- Drift: compare to the previous purple run; alert on regression. - #
        summary["drift"] = _evaluate_drift(
            db, workspace, run, det_summary, det_results
        )

    # --- AI triage auto-chain: prioritize the workspace's findings. --------- #
    # Always present (enabled False when AI is unavailable or there are no
    # findings). Commit-free — chain_triage only flushes.
    summary["triage"] = chain_triage(db, workspace)

    return run, detection_results, summary


def chain_triage(db: Any, workspace: Any) -> dict[str, Any]:
    """Gather findings, run AI triage, persist it, and return a compact summary.

    This chains the deterministic scanners into the optional Claude triage layer
    (:func:`app.ai.triage_findings`): it collects the workspace's findings as
    compact dicts, asks the AI to prioritize them, and — when the AI is enabled and
    returned a structured result — persists it via :func:`app.crud.save_triage`.

    It is **fully exception-guarded and never raises**, and it is **commit-free**
    (``save_triage`` flushes; the caller owns the transaction). When AI is disabled
    (the expected path with no ``ANTHROPIC_API_KEY``), it returns
    ``{"enabled": False, "reason": ...}`` gracefully.

    Returns a compact dict::

        {"enabled": bool, "reason"?: str, "count": int,
         "top": [{"id", "name", "severity", "priority"}, ... up to 5]}

    where ``count`` is the number of findings sent for triage and ``top`` lists up
    to five triaged findings ordered by severity then priority.
    """
    from . import ai  # deferred import keeps app.purple import-safe without the SDK

    try:
        findings = crud.list_findings(db, workspace.id)
    except Exception:  # noqa: BLE001 - a read failure degrades to "disabled"
        return {"enabled": False, "reason": "could not load findings", "count": 0, "top": []}

    finding_dicts = [
        {
            "id": f.id,
            "severity": f.severity,
            "name": f.name,
            "location": f.location,
            "description": f.description,
            "cve": f.cve or [],
            "cwe": f.cwe or [],
            "cvss": f.cvss,
        }
        for f in findings
    ]
    name_by_id = {f.id: f.name for f in findings}
    sev_by_id = {f.id: (f.severity or "info") for f in findings}

    try:
        result = ai.triage_findings(finding_dicts)
    except Exception as exc:  # noqa: BLE001 - triage must never break the run
        return {
            "enabled": False,
            "reason": f"triage error: {exc}",
            "count": len(finding_dicts),
            "top": [],
        }

    if not (isinstance(result, dict) and result.get("enabled") and "result" in result):
        reason = (
            (result or {}).get("reason")
            or ("refused" if (result or {}).get("refused") else None)
            or "AI triage unavailable"
        )
        return {
            "enabled": False,
            "reason": reason,
            "count": len(finding_dicts),
            "top": [],
        }

    triage_dict = result["result"] or {}

    # Persist (best-effort; a persistence failure must not raise into the run).
    try:
        crud.save_triage(
            db,
            workspace.id,
            None,
            result.get("model", ""),
            triage_dict,
        )
    except Exception:  # noqa: BLE001 - keep the run alive even if the save fails
        pass

    # --- Build the compact `top` list, robust to the triage payload shape. --- #
    # ai.TriageOut exposes per-finding verdicts under `items`
    # (finding_id/suggested_severity); tolerate a `findings` shape too.
    rows = triage_dict.get("findings") or triage_dict.get("items") or []
    normalized: list[dict[str, Any]] = []
    for r in rows:
        if not isinstance(r, dict):
            continue
        fid = r.get("id", r.get("finding_id"))
        severity = (
            r.get("severity")
            or r.get("suggested_severity")
            or sev_by_id.get(fid)
            or "info"
        )
        normalized.append(
            {
                "id": fid,
                "name": r.get("name") or name_by_id.get(fid, "") or "",
                "severity": severity,
                "priority": r.get("priority"),
            }
        )

    def _rank(row: dict[str, Any]) -> tuple[int, Any]:
        sev = _SEV_RANK.get((row.get("severity") or "info").lower(), 5)
        pr = row.get("priority")
        pr_key = pr if isinstance(pr, (int, float)) else 999
        return (sev, pr_key)

    normalized.sort(key=_rank)
    return {
        "enabled": True,
        "count": len(finding_dicts),
        "top": normalized[:5],
    }


def _previous_validated_run(
    db: Any, workspace_id: int, before_run_id: int
) -> models.EmulationRun | None:
    """Return the most recent *validated* emulation run before ``before_run_id``.

    A run is "validated" (a prior purple run) when it has at least one
    :class:`~app.models.DetectionResult`. Returns ``None`` when there is no
    earlier validated run to compare against.
    """
    return db.scalars(
        select(models.EmulationRun)
        .where(
            models.EmulationRun.workspace_id == workspace_id,
            models.EmulationRun.id < before_run_id,
            exists().where(
                models.DetectionResult.emulation_run_id == models.EmulationRun.id
            ),
        )
        .order_by(models.EmulationRun.id.desc())
        .limit(1)
    ).first()


def _evaluate_drift(
    db: Any,
    workspace: Any,
    run: models.EmulationRun,
    summary: dict[str, Any],
    results: list[dict[str, Any]],
) -> dict[str, Any] | None:
    """Detect detection drift vs. the previous purple run and alert on it.

    Drift is either a **regression** (a technique detected in the previous run is
    now missed) or an **overall coverage drop** (this run's ``coverage_pct`` is
    below the previous run's). On drift, a ``detection_drift`` event is dispatched
    to the org's subscribed notification channels and returned; otherwise
    ``None`` is returned. Never raises — any failure degrades to ``None`` so drift
    handling can never break a purple run.
    """
    try:
        prev = _previous_validated_run(db, workspace.id, run.id)
        if prev is None:
            return None

        prev_results = crud.list_detection_results(db, prev.id)
        prev_total = len(prev_results)
        prev_detected = sum(1 for r in prev_results if r.detected)
        coverage_before = (
            round(100 * prev_detected / prev_total) if prev_total else None
        )
        coverage_after = summary.get("coverage_pct")

        detected_before = {r.technique_id for r in prev_results if r.detected}
        missed_now = {
            r.get("technique_id")
            for r in results
            if not r.get("detected") and r.get("technique_id")
        }
        regressed_ids = detected_before & missed_now

        # Metadata for the regressed techniques (name/tactic) from this run.
        now_by_id = {r.get("technique_id"): r for r in results}
        regressions = [
            {
                "technique_id": tid,
                "technique_name": now_by_id.get(tid, {}).get("technique_name", ""),
                "tactic": now_by_id.get(tid, {}).get("tactic", ""),
            }
            for tid in sorted(regressed_ids)
        ]

        coverage_dropped = (
            coverage_before is not None
            and coverage_after is not None
            and coverage_after < coverage_before
        )
        if not regressions and not coverage_dropped:
            return None

        event: dict[str, Any] = {
            "type": DRIFT_EVENT_TYPE,
            "workspace_id": workspace.id,
            "emulation_run_id": run.id,
            "previous_run_id": prev.id,
            "regressions": regressions,
            "coverage_before": coverage_before,
            "coverage_after": coverage_after,
            "message": _drift_message(regressions, coverage_before, coverage_after),
        }
        _dispatch_drift(db, getattr(workspace, "org_id", None), event)
        return event
    except Exception:  # noqa: BLE001 - drift handling must never break the run
        return None


def _drift_message(
    regressions: list[dict[str, Any]],
    coverage_before: int | None,
    coverage_after: int | None,
) -> str:
    """Render a short human line summarizing the drift for channel messages."""
    parts: list[str] = []
    if regressions:
        ids = ", ".join(r["technique_id"] for r in regressions)
        parts.append(f"{len(regressions)} detection regression(s): {ids}")
    if coverage_before is not None and coverage_after is not None:
        parts.append(f"coverage {coverage_before}% -> {coverage_after}%")
    return "; ".join(parts) or "detection drift"


def _dispatch_drift(db: Any, org_id: int | None, event: dict[str, Any]) -> None:
    """Best-effort dispatch of a drift event to the org's channels.

    Mirrors the worker's new-finding notification path: only enabled channels
    subscribed to :data:`DRIFT_EVENT_TYPE` (or ``"*"``) receive the event, and
    :func:`app.notify.dispatch` is itself failure-safe.
    """
    if org_id is None:
        return
    for ch in crud.list_channels(db, org_id):
        if not getattr(ch, "enabled", True):
            continue
        channel = {
            "ctype": ch.ctype,
            "config": ch.config or {},
            "events": ch.events or [],
        }
        if not notify.should_notify(channel, DRIFT_EVENT_TYPE):
            continue
        notify.dispatch(channel, event)

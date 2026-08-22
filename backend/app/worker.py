"""Out-of-process arq worker entrypoint for queued scans.

When ``settings.EXECUTION_BACKEND == "queue"`` a scan is no longer run inside the
API process. Instead :func:`app.queue.enqueue_scan` drops a job onto arq's Redis
queue and this worker picks it up: it drives the scanner generator, publishes
every event onto the job's Redis **stream** (so the WebSocket/REST layer can
forward the live log via :func:`app.streaming.tail`), persists the finished scan
through a **fresh** :class:`~app.database.SessionLocal`, and finally emits a
``saved`` event and the stream's terminal marker.

Run it (Redis + arq required) with::

    arq app.worker.WorkerSettings

Everything Redis/arq-specific is imported lazily so ``import app.worker`` (and
therefore ``import app.main``) succeeds on a machine with neither installed —
the module stays import-safe exactly like the rest of the Phase 2 core.
"""

from __future__ import annotations

import asyncio
import logging
import threading
import time
from datetime import datetime, timezone
from typing import Any

from . import observability
from .config import settings
from .database import SessionLocal
from .scanners import get_scanner
from .streaming import SyncPublisher

logger = logging.getLogger("reconx.worker")

# ``RedisSettings`` only parses a DSN string (no connection), but importing arq
# must not be a hard requirement of merely importing this module. Resolve it
# lazily-at-class-body via a guarded import so ``WorkerSettings`` is well-formed
# when arq is present and simply carries ``redis_settings = None`` when it is
# not (in which case the worker is never actually run anyway).
try:  # pragma: no cover - exercised only where arq is installed
    from arq.connections import RedisSettings as _RedisSettings

    _REDIS_SETTINGS: Any = _RedisSettings.from_dsn(settings.REDIS_URL)
except Exception:  # noqa: BLE001 - arq absent / bad DSN -> import-safe fallback
    _REDIS_SETTINGS = None


def _now() -> str:
    """UTC ISO-8601 timestamp (seconds precision), matching the routers/core."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _finding_to_dict(f: Any) -> dict[str, Any]:
    """Reduce an ORM ``Finding`` to the fields diffing/notification need."""
    return {
        "id": getattr(f, "id", None),
        "severity": getattr(f, "severity", "info"),
        "name": getattr(f, "name", ""),
        "location": getattr(f, "location", ""),
        "description": getattr(f, "description", ""),
    }


def _notify_new_findings(db: Any, scan: Any) -> None:
    """Best-effort: alert org channels about findings new since the prior scan.

    Compares ``scan`` (the just-persisted current scan) against the previous scan
    of the same tool/target via :func:`app.diffing.diff_findings`, then dispatches
    a ``new_finding`` event to every enabled, subscribed org
    :class:`~app.models.NotificationChannel` through :func:`app.notify.dispatch`.

    This is a non-critical enhancement: any error (no workspace, diffing hiccup,
    a broken channel) is swallowed so it can never crash the scan task. Dispatch
    itself is already failure-safe and never raises.
    """
    try:
        from . import crud, diffing, notify  # local imports keep module import-safe

        ws = crud.get_workspace(db, scan.workspace_id) if scan.workspace_id else None
        if ws is None:
            return

        previous, _current = crud.latest_two_scans(db, ws.id, scan.tool, scan.target)
        prev_findings = [_finding_to_dict(f) for f in (previous.findings if previous else [])]
        cur_findings = [_finding_to_dict(f) for f in scan.findings]

        new = diffing.diff_findings(prev_findings, cur_findings)["new"]
        if not new:
            return

        channels = crud.list_channels(db, ws.org_id)
        for ch in channels:
            if not getattr(ch, "enabled", True):
                continue
            channel = {"ctype": ch.ctype, "config": ch.config or {}, "events": ch.events or []}
            if not notify.should_notify(channel, "new_finding"):
                continue
            for finding in new:
                event = {
                    "type": "new_finding",
                    "workspace_id": ws.id,
                    "tool": scan.tool,
                    "target": scan.target,
                    "finding": finding,
                }
                notify.dispatch(channel, event)
    except Exception as exc:  # noqa: BLE001 - notifications must never break a scan
        logger.debug("new-finding notification failed: %s", exc)
        return


def _authorize_scan_target(db: Any, workspace_id: Any, target: str):
    """Shared scan security gate: workspace authorization + engagement scope +
    verified-asset + netguard.

    Mirrors the manual-scan gate in :func:`app.routers.scans.run_scan` so a
    scheduled or queued scan gets the SAME guarantees. Returns
    ``(allowed, reason, workspace)``. Reuses the existing ``scope.check`` /
    ``crud.is_target_authorized`` / ``netguard.validate_target`` — there is no
    second SSRF or authorization system.
    """
    from . import crud, netguard, scope  # deferred: keep app.worker import-safe

    ws = crud.get_workspace(db, workspace_id) if workspace_id else None
    if ws is None:
        return False, "workspace not found or unauthorized", None
    tgt = target or ""
    allowed, reason = scope.check(tgt, ws.scope)
    if not allowed:
        return False, f"out of engagement scope ({reason})", ws
    if not crud.is_target_authorized(db, ws.id, tgt):
        return False, "target is not a verified asset for this workspace", ws
    safe, nreason = netguard.validate_target(tgt)
    if not safe:
        return False, f"blocked by netguard ({nreason})", ws
    return True, "ok", ws


def _blocked_reason(workspace_id: Any, target: str) -> "str | None":
    """Re-run the scan security gate in a fresh session at the worker execution
    boundary. Returns ``None`` if the scan may proceed, else a clear reason.

    This is the TOCTOU-safe check: a target's DNS, the workspace scope, the
    verified-asset set, or the workspace itself may have changed between enqueue
    and execution, so the boundary is re-established here — as close as possible
    to the network operation — before any scanner runs.
    """
    db = SessionLocal()
    try:
        allowed, reason, _ws = _authorize_scan_target(db, workspace_id, target)
        return None if allowed else reason
    finally:
        db.close()


def _execute_and_persist(job: dict[str, Any]) -> dict[str, Any]:
    """Run one scan synchronously, streaming + persisting its result.

    Executed inside a worker thread (via ``run_in_executor``) because the
    scanner generators and :class:`SyncPublisher` are synchronous. The event
    handshake published here mirrors the inline path exactly — the scanner's own
    ``log``/``result``/``error``/``returncode`` events, then a ``saved`` event —
    so a consumer tailing the stream sees the same sequence the inline
    WebSocket worker produces. ``start`` and ``done`` are emitted by
    :func:`app.execution.stream`, not here, to avoid duplication.
    """
    job_id = job["job_id"]
    tool = job["tool"]
    target = job["target"]
    options = job.get("options") or {}

    publisher = SyncPublisher(job_id)
    started = _now()
    t0 = time.monotonic()
    logger.info("queue scan start job_id=%s tool=%s target=%s", job_id, tool, target)
    logs: list = []
    result_data: Any = None
    error_data: Any = None
    blocked_reason: "str | None" = None
    try:
        # --- P1-B4: execution-boundary security gate (TOCTOU-safe) ---------- #
        # Revalidate IMMEDIATELY before any scanner runs. A queued/scheduled job
        # may have been created when the target was safe, but its DNS, the
        # workspace scope, the verified-asset set, or the workspace itself may
        # have changed since. If the target no longer passes workspace
        # authorization + engagement scope + verified-asset + netguard, the
        # scanner is NOT run: a 'blocked' scan (no findings) is persisted and the
        # rejection is audited. Same gate as the manual /scans path.
        blocked_reason = _blocked_reason(job.get("workspace_id"), target)
        if blocked_reason is not None:
            error_data = f"scan blocked: {blocked_reason}"
            publisher.publish({"type": "error", "data": error_data})
        else:
            scanner = get_scanner(tool)
            if scanner is None:
                error_data = f"Unknown tool: {tool}"
                publisher.publish({"type": "error", "data": error_data})
            else:
                # A cancel handle exists for parity with the scanner signature;
                # the queue transport has no cross-process stop channel, so it is
                # simply never set here.
                cancel = threading.Event()
                try:
                    for event in scanner(target, cancel=cancel, **options):
                        kind = event.get("type")
                        if kind == "log":
                            logs.append(event.get("data"))
                        elif kind == "result":
                            result_data = event.get("data")
                        elif kind == "error":
                            error_data = event.get("data")
                        publisher.publish(event)
                except Exception as exc:  # noqa: BLE001 - surface any scanner crash
                    error_data = str(exc)
                    logger.warning(
                        "queue scan crashed job_id=%s tool=%s: %s", job_id, tool, exc
                    )
                    publisher.publish({"type": "error", "data": error_data})

        status = "blocked" if blocked_reason is not None else ("error" if error_data else "done")
        observability.record_scan(tool, status)
        record = {
            "workspace_id": job.get("workspace_id"),
            "created_by": job.get("created_by"),
            "tool": tool,
            "target": target,
            "status": status,
            "options": options,
            "logs": logs,
            "result": result_data,
            "error": error_data,
            "started_at": started,
            "finished_at": _now(),
        }

        db = SessionLocal()
        try:
            from . import crud  # local import keeps module import-order simple

            scan = crud.save_scan(db, record)
            scan_id = scan.id
            ws = crud.get_workspace(db, job["workspace_id"]) if job.get("workspace_id") else None
            if ws is not None:
                if blocked_reason is not None:
                    # Do not silently ignore a rejected scan — audit it clearly.
                    crud.audit(
                        db, ws.org_id, job.get("created_by"),
                        "scan-blocked", f"{tool} {target}: {blocked_reason}",
                    )
                else:
                    crud.audit(
                        db, ws.org_id, job.get("created_by"),
                        "scan", f"{tool} {target} ({status})",
                    )
            db.commit()
            # Phase 4: best-effort new-finding alerts — only a real (non-blocked)
            # scan can produce findings to alert on.
            if blocked_reason is None:
                _notify_new_findings(db, scan)
        finally:
            db.close()

        logger.info(
            "queue scan done job_id=%s scan_id=%s tool=%s status=%s dur=%.2fs",
            job_id, scan_id, tool, status, time.monotonic() - t0,
        )
        publisher.publish(
            {
                "type": "saved",
                "scan_id": scan_id,
                "workspace_id": job.get("workspace_id"),
            }
        )
        return {"scan_id": scan_id, "status": status}
    finally:
        # Terminal marker + TTL so a tailing consumer always unblocks.
        publisher.close()


async def run_scan_task(ctx: dict, job: dict[str, Any]) -> dict[str, Any]:
    """arq task: run a queued scan, stream it, and persist the result.

    ``job`` is the plain dict produced by ``app.execution._job_to_dict`` (keys:
    ``job_id``, ``tool``, ``target``, ``options``, ``workspace_id``,
    ``created_by``). The blocking work runs in a thread so the arq event loop
    stays responsive. Returns a small summary dict (``scan_id``/``status``) for
    arq's result store.
    """
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, _execute_and_persist, job)


def _run_purple_schedule(db: Any, sched: Any) -> bool:
    """Run a due ``tool == "purple"`` schedule inline (emulate + validate).

    Resolves the schedule's workspace and the connector it should validate
    against (its ``config["connector_id"]`` if set and same-org, else the org's
    default connector), re-checks scope + SSRF/netguard defensively, then runs
    :func:`app.purple.run_purple`. Returns ``True`` when a purple run actually
    executed. Never raises — any failure is swallowed so one bad schedule can't
    wedge the poller (the caller still advances ``next_run_at``).

    Unlike a scanner schedule, this does the work *inline* in the worker rather
    than enqueuing a job: a purple run is a self-contained emulate+validate unit
    with no separate scanner backend to dispatch to.
    """
    try:
        from . import crud, netguard, purple, scope  # deferred: keep import-safe

        ws = crud.get_workspace(db, sched.workspace_id)
        if ws is None:
            return False

        # Defensive scope + egress re-check (schedule creation isn't target-gated).
        allowed, _ = scope.check(sched.target, ws.scope)
        if not allowed:
            return False
        safe, _ = netguard.validate_target(sched.target)
        if not safe:
            return False

        cfg = getattr(sched, "config", None) or {}
        connector = None
        connector_id = cfg.get("connector_id")
        if connector_id:
            connector = crud.get_detection_connector(db, connector_id)
            if connector and connector.org_id != ws.org_id:
                connector = None
        if connector is None:
            connector = crud.default_detection_connector(db, ws.org_id)

        purple.run_purple(
            db,
            workspace=ws,
            target=sched.target,
            connector=connector,
            created_by=sched.created_by,
            technique_ids=cfg.get("techniques"),
        )
        return True
    except Exception as exc:  # noqa: BLE001 - a purple schedule must never wedge the poller
        logger.warning(
            "scheduled purple run failed (schedule_id=%s): %s",
            getattr(sched, "id", "?"), exc,
        )
        return False


async def check_schedules(ctx: dict) -> dict[str, Any]:
    """arq cron poller: fire every due :class:`~app.models.Schedule`.

    Runs inside the arq worker (so Redis/arq are present at call time). For each
    schedule returned by :func:`crud.due_schedules`:

    * a ``tool == "purple"`` schedule runs a full purple loop **inline** via
      :func:`_run_purple_schedule` (emulate + validate; no scanner job), and
    * every other schedule is enqueued as a scan job through the same
      :func:`app.queue.enqueue_scan` path the API uses.

    Either way the schedule's ``last_run_at``/``next_run_at`` are advanced
    (``next_run_at`` recomputed from its cron) so it is not re-fired until due
    again — even on failure, so a persistently unreachable broker or a broken
    purple run can't wedge the poller on the same rows.

    A no-op when ``settings.SCHEDULER_ENABLED`` is off. Redis/arq/execution
    imports are deferred so ``import app.worker`` stays safe without them.
    """
    if not settings.SCHEDULER_ENABLED:
        return {"enqueued": 0, "due": 0, "purple": 0, "reason": "scheduler disabled"}

    from . import crud, execution, secretbox  # local imports keep module import-safe
    from . import queue as queue_mod

    db = SessionLocal()
    enqueued = 0
    purple_runs = 0
    rejected = 0
    due: list = []
    try:
        due = crud.due_schedules(db)
        for sched in due:
            if (sched.tool or "").strip().lower() == "purple":
                if _run_purple_schedule(db, sched):
                    purple_runs += 1
            else:
                # P1-B4: refuse to enqueue a scheduled scan whose target no longer
                # passes workspace authorization + engagement scope + verified-
                # asset + netguard. Fail-fast layer (the worker re-checks again at
                # execution time); a rejection is audited, never silently dropped.
                allowed, reason, ws = _authorize_scan_target(
                    db, sched.workspace_id, sched.target
                )
                if not allowed:
                    if ws is not None:
                        crud.audit(
                            db, ws.org_id, sched.created_by,
                            "schedule-rejected",
                            f"{sched.tool} {sched.target}: {reason}",
                        )
                    rejected += 1
                else:
                    # Decrypt credential-bearing option values in memory ONLY here,
                    # immediately before building the scan job — the DB row keeps
                    # them encrypted at rest. A wrong/rotated key (InvalidToken)
                    # fails closed: reject + audit the leg and never run it with
                    # garbage credentials. The schedule is still advanced below so a
                    # bad key can't wedge the poller or re-fire every tick.
                    try:
                        _opts = secretbox.decrypt_options(sched.options or {})
                    except secretbox.InvalidToken:
                        if ws is not None:
                            crud.audit(
                                db, ws.org_id, sched.created_by, "schedule-rejected",
                                f"{sched.tool} {sched.target}: credential decryption "
                                "failed (encryption key changed?) — re-enter credentials",
                            )
                        rejected += 1
                        _opts = None
                    if _opts is not None:
                        job = execution.Job(
                            tool=sched.tool,
                            target=sched.target,
                            options=_opts,
                            workspace_id=sched.workspace_id,
                            created_by=sched.created_by,
                        )
                        job_id = await queue_mod.enqueue_scan(execution._job_to_dict(job))
                        if job_id:
                            enqueued += 1
            # Advance the schedule even if the leg failed, so a persistently
            # unreachable broker (or a bad purple run) can't wedge the poller.
            sched.last_run_at = datetime.now(timezone.utc)
            sched.next_run_at = crud.cron_next(sched.cron)
            db.add(sched)
        db.commit()
    finally:
        db.close()
    return {
        "enqueued": enqueued,
        "due": len(due),
        "purple": purple_runs,
        "rejected": rejected,
    }


# arq's ``cron`` helper builds a CronJob; guard the import so this module stays
# import-safe without arq (the worker is never actually run in that case anyway).
try:  # pragma: no cover - exercised only where arq is installed
    from arq import cron as _cron

    _CRON_JOBS: Any = [_cron(check_schedules, minute=set(range(0, 60, 5)))]
except Exception:  # noqa: BLE001 - arq absent -> no cron jobs
    _CRON_JOBS = []


class WorkerSettings:
    """arq worker configuration — the target of ``arq app.worker.WorkerSettings``.

    arq reads these class attributes to build its worker: ``functions`` is the
    set of registered tasks, ``cron_jobs`` the scheduled pollers (Phase 4's
    :func:`check_schedules`), and ``redis_settings`` points it at the broker.
    Both :mod:`app.queue` (which re-exports this class) and the CLI use it, and
    there is no import cycle because this module never imports :mod:`app.queue`.
    """

    functions = [run_scan_task]
    cron_jobs = _CRON_JOBS
    redis_settings = _REDIS_SETTINGS

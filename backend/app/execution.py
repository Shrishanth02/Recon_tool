"""The single scan-execution abstraction shared by both scan entrypoints.

Phase 0/1 ran every scan inline: the WebSocket router spun a worker thread over
a scanner generator and pumped events through an :class:`asyncio.Queue`, while
the REST router drained the same generator synchronously. This module factors
that logic into one place so:

* **inline mode stays byte-for-byte the behavior it is today** (the default,
  needing no Redis and no Docker), and
* a **queue mode** can be switched on purely by config, delegating execution to
  an out-of-process arq worker and streaming its output back via Redis Streams.

Two public entrypoints:

* :func:`stream` — an async generator of event dicts for the WebSocket router.
* :func:`run_to_completion` — a synchronous drain-and-persist for the REST
  router.

Both run :func:`app.netguard.validate_targets` *first*: a target that resolves
to a private/loopback/metadata address is refused before any packet is sent.

Concurrency for inline runs is capped by the module-level :data:`scan_slots`
semaphore (sized from :data:`settings.MAX_CONCURRENT_SCANS`) — the single guard
both entrypoints share, exactly as the routers shared one before.

Cancellation: every :class:`Job` carries a :class:`threading.Event` at
``job.cancel``. The WebSocket router sets it (``job.cancel.set()``) when the
browser sends ``{"action": "stop"}``; the running scanner generator observes it
and terminates promptly, and the persisted scan is recorded as ``"stopped"``.
"""

from __future__ import annotations

import asyncio
import logging
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, AsyncIterator, Callable
from uuid import uuid4

from . import netguard, observability
from .config import settings
from .scanners import get_scanner

logger = logging.getLogger("reconx.execution")

# --------------------------------------------------------------------------- #
# Shared inline concurrency guard (as today). Sizing matches the routers'
# historical ``threading.Semaphore(settings.MAX_CONCURRENT_SCANS)``.
# --------------------------------------------------------------------------- #
scan_slots = threading.Semaphore(settings.MAX_CONCURRENT_SCANS)

# A persister returns the saved scan (or its id). Callers supply a DB-backed
# closure so this module stays free of any session/ORM coupling.
OnPersist = Callable[[dict[str, Any]], Any]


class TargetBlockedError(Exception):
    """Raised by :func:`run_to_completion` when netguard refuses the target."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class ScanCapacityError(Exception):
    """Raised by :func:`run_to_completion` when the concurrency cap is hit."""


class ScanBackendError(Exception):
    """Raised when the queue backend is selected but unavailable."""


@dataclass
class Job:
    """One unit of scan work, independent of transport or persistence.

    ``cancel`` is the caller-visible stop handle: hold a reference to the job
    and call ``job.cancel.set()`` to abort an inline run. ``job_id`` identifies
    the job on the Redis stream in queue mode.
    """

    tool: str
    target: str
    options: dict[str, Any] = field(default_factory=dict)
    workspace_id: int | None = None
    created_by: int | None = None
    job_id: str = field(default_factory=lambda: uuid4().hex)
    cancel: threading.Event = field(default_factory=threading.Event)


def _now() -> str:
    """UTC ISO-8601 timestamp (seconds precision), matching the routers."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _coerce_scan_id(persisted: Any) -> Any:
    """Normalize an ``on_persist`` return (Scan object or bare id) to an id."""
    return getattr(persisted, "id", persisted)


def _job_to_dict(job: Job) -> dict[str, Any]:
    """Serialize a job for the arq queue (drops the non-serializable cancel)."""
    return {
        "job_id": job.job_id,
        "tool": job.tool,
        "target": job.target,
        "options": job.options,
        "workspace_id": job.workspace_id,
        "created_by": job.created_by,
    }


def _build_record(
    job: Job,
    *,
    status: str,
    logs: list,
    result: Any,
    error: Any,
    started_at: str,
) -> dict[str, Any]:
    """Assemble a ``crud.save_scan``-shaped record dict."""
    return {
        "workspace_id": job.workspace_id,
        "created_by": job.created_by,
        "tool": job.tool,
        "target": job.target,
        "status": status,
        "options": job.options,
        "logs": logs,
        "result": result,
        "error": error,
        "started_at": started_at,
        "finished_at": _now(),
    }


# --------------------------------------------------------------------------- #
# Async streaming entrypoint (WebSocket router)
# --------------------------------------------------------------------------- #
async def stream(job: Job, *, on_persist: OnPersist) -> AsyncIterator[dict[str, Any]]:
    """Run ``job`` and yield its live events (start/log/result/error/saved/done).

    ``on_persist(record) -> scan_id`` is invoked once when the scan finishes; it
    is the caller's DB-backed persister (``crud.save_scan`` + audit + commit).
    The resulting id is surfaced in the ``saved`` event.

    Inline mode reproduces the original WebSocket worker exactly: netguard, then
    the concurrency slot, then a ``start`` event, then a threaded scanner
    generator bridged onto an :class:`asyncio.Queue`, then persistence, then the
    ``saved``/``done`` handshake. Queue mode enqueues the job and forwards the
    worker's events off the Redis stream.
    """
    allowed, reason = netguard.validate_targets(job.target)
    if not allowed:
        yield {"type": "error", "data": f"⛔ {reason}"}
        yield {"type": "done"}
        return

    if settings.use_queue:
        yield {"type": "start", "tool": job.tool, "target": job.target}
        async for event in _stream_queue(job):
            yield event
        return

    # --- Inline: honor the shared concurrency cap before announcing start ---- #
    if not scan_slots.acquire(blocking=False):
        yield {
            "type": "error",
            "data": "Server is at maximum concurrent scans. Try again shortly.",
        }
        yield {"type": "done"}
        return
    try:
        yield {"type": "start", "tool": job.tool, "target": job.target}
        async for event in _stream_inline(job, on_persist):
            yield event
    finally:
        scan_slots.release()


async def _stream_inline(
    job: Job, on_persist: OnPersist
) -> AsyncIterator[dict[str, Any]]:
    """Bridge a threaded scanner generator to an async event stream (as today)."""
    scanner = get_scanner(job.tool)
    loop = asyncio.get_running_loop()
    queue: asyncio.Queue = asyncio.Queue()
    sentinel = object()
    started = _now()
    t0 = time.monotonic()
    logger.info(
        "scan start job_id=%s tool=%s target=%s ws=%s",
        job.job_id, job.tool, job.target, job.workspace_id,
    )

    # Scanner isolation (environment sanitization, process restriction, or a
    # container) is applied per-subprocess in app.scanners.base.stream_command,
    # which also logs the ACTUAL isolation_mode. Nothing is asserted about
    # isolation here — that avoids ever claiming a level that wasn't applied.

    def worker() -> None:
        try:
            for event in scanner(job.target, cancel=job.cancel, **job.options):
                loop.call_soon_threadsafe(queue.put_nowait, event)
        except Exception as exc:  # noqa: BLE001 - surface any scanner crash
            loop.call_soon_threadsafe(
                queue.put_nowait, {"type": "error", "data": str(exc)}
            )
        finally:
            loop.call_soon_threadsafe(queue.put_nowait, sentinel)

    worker_future = loop.run_in_executor(None, worker)

    logs: list = []
    result_data: Any = None
    error_data: Any = None
    try:
        while True:
            event = await queue.get()
            if event is sentinel:
                break
            kind = event.get("type")
            if kind == "log":
                logs.append(event.get("data"))
            elif kind == "result":
                result_data = event.get("data")
            elif kind == "error":
                error_data = event.get("data")
            yield event  # forward every event (incl. returncode), as today

        status = (
            "stopped"
            if job.cancel.is_set()
            else ("error" if error_data else "done")
        )
        record = _build_record(
            job,
            status=status,
            logs=logs,
            result=result_data,
            error=error_data,
            started_at=started,
        )
        scan_id = _coerce_scan_id(on_persist(record))
        observability.record_scan(job.tool, status)
        logger.info(
            "scan done job_id=%s scan_id=%s tool=%s status=%s dur=%.2fs",
            job.job_id, scan_id, job.tool, status, time.monotonic() - t0,
        )
        yield {
            "type": "saved",
            "scan_id": scan_id,
            "workspace_id": job.workspace_id,
        }
        yield {"type": "done"}
    finally:
        # Ensure the worker thread unwinds even if the consumer disconnected.
        job.cancel.set()
        await worker_future


async def _stream_queue(job: Job) -> AsyncIterator[dict[str, Any]]:
    """Enqueue ``job`` and forward the worker's events off the Redis stream."""
    from . import queue as queue_mod  # lazy: import-safe without redis/arq
    from . import streaming

    job_id = await queue_mod.enqueue_scan(_job_to_dict(job))
    if not job_id:
        yield {
            "type": "error",
            "data": "Queue backend is unavailable (Redis/arq not reachable).",
        }
        yield {"type": "done"}
        return

    # The worker persists the scan and emits its own ``saved`` event, which the
    # tail forwards verbatim; we only need to cap the stream with ``done``.
    async for event in streaming.tail(job_id):
        yield event
    yield {"type": "done"}


# --------------------------------------------------------------------------- #
# Synchronous entrypoint (REST router)
# --------------------------------------------------------------------------- #
def run_to_completion(job: Job, *, persist: OnPersist) -> Any:
    """Run ``job`` to completion and persist it; return the persisted record.

    In **inline** mode this drains the scanner generator (like the original
    ``scans._run_scanner``), builds the record, and returns ``persist(record)``
    — i.e. the saved ORM ``Scan``, so the caller can serialize it as today.

    Raises :class:`TargetBlockedError` if netguard refuses the target and
    :class:`ScanCapacityError` if the inline concurrency cap is saturated; the
    REST router maps these to 403 and 503 respectively.

    In **queue** mode the job is enqueued and the Redis stream is block-consumed
    to completion; the out-of-process worker performs persistence, so an
    assembled record dict (including the worker's ``scan_id``) is returned.
    """
    allowed, reason = netguard.validate_targets(job.target)
    if not allowed:
        raise TargetBlockedError(reason)

    if settings.use_queue:
        return _run_queue_to_completion(job)

    return _run_inline_to_completion(job, persist)


def _run_inline_to_completion(job: Job, persist: OnPersist) -> Any:
    """Drain the scanner generator synchronously, persist, and return the Scan."""
    scanner = get_scanner(job.tool)
    if not scan_slots.acquire(blocking=False):
        raise ScanCapacityError(
            "Server is at maximum concurrent scans. Try again shortly."
        )
    started = _now()
    t0 = time.monotonic()
    logger.info(
        "scan start job_id=%s tool=%s target=%s ws=%s",
        job.job_id, job.tool, job.target, job.workspace_id,
    )
    logs: list = []
    result_data: Any = None
    error_data: Any = None
    try:
        for event in scanner(job.target, cancel=job.cancel, **job.options):
            kind = event.get("type")
            if kind == "log":
                logs.append(event.get("data"))
            elif kind == "result":
                result_data = event.get("data")
            elif kind == "error":
                error_data = event.get("data")
    finally:
        scan_slots.release()

    status = (
        "stopped" if job.cancel.is_set() else ("error" if error_data else "done")
    )
    record = _build_record(
        job,
        status=status,
        logs=logs,
        result=result_data,
        error=error_data,
        started_at=started,
    )
    persisted = persist(record)
    observability.record_scan(job.tool, status)
    logger.info(
        "scan done job_id=%s scan_id=%s tool=%s status=%s dur=%.2fs",
        job.job_id, getattr(persisted, "id", None), job.tool, status,
        time.monotonic() - t0,
    )
    return persisted


def _run_queue_to_completion(job: Job) -> dict[str, Any]:
    """Enqueue and block-consume the Redis stream, assembling the record."""

    async def _consume() -> dict[str, Any]:
        from . import queue as queue_mod  # lazy imports
        from . import streaming

        job_id = await queue_mod.enqueue_scan(_job_to_dict(job))
        if not job_id:
            raise ScanBackendError(
                "Queue backend is unavailable (Redis/arq not reachable)."
            )
        started = _now()
        logs: list = []
        result_data: Any = None
        error_data: Any = None
        scan_id: Any = None
        async for event in streaming.tail(job_id):
            kind = event.get("type")
            if kind == "log":
                logs.append(event.get("data"))
            elif kind == "result":
                result_data = event.get("data")
            elif kind == "error":
                error_data = event.get("data")
            elif kind == "saved":
                scan_id = event.get("scan_id")
        status = "error" if error_data else "done"
        record = _build_record(
            job,
            status=status,
            logs=logs,
            result=result_data,
            error=error_data,
            started_at=started,
        )
        record["scan_id"] = scan_id
        return record

    return asyncio.run(_consume())

"""Redis/arq task-queue seam for out-of-process scan execution.

Phase 0/1 runs every scan in-process. Phase 2 adds an optional *queue* backend:
when ``settings.EXECUTION_BACKEND == "queue"`` the API enqueues a job here and an
:mod:`app.worker` process consumes it. This module owns the *producer* side —
:func:`enqueue_scan` — plus a re-export of the worker's :class:`WorkerSettings`
so ``arq app.queue.WorkerSettings`` and ``arq app.worker.WorkerSettings`` both
work.

Import-safety is a hard requirement: ``redis`` and ``arq`` are imported lazily
inside the functions (and behind ``try/except``) so ``import app.queue`` — and
therefore ``import app.main`` — succeeds on a machine with neither package
installed and no Redis running. Every failure path degrades to ``None`` so a
caller can surface a clean "queue unavailable" error rather than crashing.

The dependency direction is one-way (``queue`` imports ``worker``; ``worker``
never imports ``queue``), so there is no import cycle.
"""

from __future__ import annotations

from typing import Any

from .config import settings

# The worker defines the actual task + WorkerSettings; re-export the class so the
# historical ``arq app.queue.WorkerSettings`` entrypoint keeps working. Importing
# app.worker is import-safe (it lazily guards arq), so this is cheap and safe.
from .worker import WorkerSettings, run_scan_task  # noqa: F401  (re-exported)

__all__ = ["redis_available", "enqueue_scan", "run_scan_task", "WorkerSettings"]


def redis_available() -> bool:
    """Best-effort check that a Redis server answers on ``settings.REDIS_URL``.

    Returns ``False`` (rather than raising) if ``redis`` is not installed or the
    server is unreachable, so callers can degrade gracefully instead of running
    a scan that can never be enqueued.
    """
    try:
        import redis  # type: ignore
    except Exception:  # noqa: BLE001 - package absent -> unavailable
        return False
    try:
        client = redis.Redis.from_url(settings.REDIS_URL, socket_connect_timeout=0.5)
        return bool(client.ping())
    except Exception:  # noqa: BLE001 - server unreachable -> unavailable
        return False


async def enqueue_scan(job: dict[str, Any]) -> str | None:
    """Enqueue a scan job onto arq's Redis queue and return its job id.

    ``job`` is the serialized job dict from ``app.execution._job_to_dict``.
    Returns the arq job id on success, or ``None`` when Redis/arq are
    unavailable — the execution core turns that ``None`` into an ``error`` event
    (WebSocket) or a :class:`~app.execution.ScanBackendError` (REST), never a
    crash.
    """
    if not redis_available():
        return None
    try:
        from arq import create_pool  # type: ignore
        from arq.connections import RedisSettings  # type: ignore
    except Exception:  # noqa: BLE001 - arq absent
        return None

    pool = None
    try:
        pool = await create_pool(RedisSettings.from_dsn(settings.REDIS_URL))
        arq_job = await pool.enqueue_job("run_scan_task", job)
        return arq_job.job_id if arq_job else None
    except Exception:  # noqa: BLE001 - broker hiccup -> caller degrades
        return None
    finally:
        if pool is not None:
            # redis-py renamed ``close`` -> ``aclose``; support both.
            closer = getattr(pool, "aclose", None) or getattr(pool, "close", None)
            if closer is not None:
                try:
                    await closer()
                except Exception:  # noqa: BLE001 - best-effort cleanup
                    pass

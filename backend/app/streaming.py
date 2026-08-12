"""Redis Streams transport for live scan output.

When RECON-X runs in *queue* mode the scanner executes inside an out-of-process
arq worker, so its live log can no longer be handed straight to the WebSocket.
This module bridges that gap with a Redis **stream** (``XADD``/``XREAD``) — not
pub/sub — deliberately: a stream persists its entries, so a WebSocket that
attaches a few hundred milliseconds *after* the worker starts still replays the
full log from the beginning rather than missing the opening lines.

Two halves:

* :class:`SyncPublisher` — used from the (synchronous) worker thread that is
  draining a scanner generator. It ``XADD``s one entry per event and, on
  :meth:`~SyncPublisher.close`, appends a terminal marker and expires the key.
* :func:`tail` — an async generator used by the API/WebSocket layer to forward
  events to the browser until the terminal marker is seen.

``redis`` is imported lazily inside every function/method so that merely
importing this module never requires the package to be installed or a server to
be reachable.
"""

from __future__ import annotations

import json
import time
from typing import Any, AsyncIterator

from .config import settings

#: Sentinel event appended by the publisher to mark end-of-stream. ``tail``
#: consumes it to stop, but never yields it to callers.
_TERMINAL = {"type": "__end__"}


def stream_key(job_id: str) -> str:
    """Return the Redis stream key backing a job's live output."""
    return f"reconx:scan:{job_id}"


class SyncPublisher:
    """Publish scan events onto a Redis stream from synchronous worker code.

    Instantiate once per job inside the worker thread, call :meth:`publish` for
    each event the scanner yields, and :meth:`close` exactly once when the scan
    finishes (success, error, or cancel). ``close`` writes a terminal marker so
    a tailing consumer knows the stream is complete, then applies the TTL so the
    key is reaped after :data:`settings.STREAM_TTL_SECONDS`.
    """

    def __init__(self, job_id: str) -> None:
        import redis  # lazy: keep module import-safe without redis installed

        self.job_id = job_id
        self._key = stream_key(job_id)
        self._client = redis.Redis.from_url(settings.REDIS_URL)

    def publish(self, event: dict[str, Any]) -> None:
        """``XADD`` one event (JSON-encoded under the ``data`` field)."""
        self._client.xadd(self._key, {"data": json.dumps(event, default=str)})

    def close(self) -> None:
        """Append the terminal marker, set the TTL, and drop the connection."""
        try:
            self._client.xadd(self._key, {"data": json.dumps(_TERMINAL)})
            self._client.expire(self._key, settings.STREAM_TTL_SECONDS)
        finally:
            try:
                self._client.close()
            except Exception:  # noqa: BLE001 - close must never raise
                pass


async def tail(job_id: str) -> AsyncIterator[dict[str, Any]]:
    """Yield a job's events from its Redis stream until the terminal marker.

    Uses ``XREAD BLOCK`` with a moving ``last-id`` cursor starting at ``"0-0"``
    (so the full backlog is replayed even for a late subscriber). An overall
    wall-clock guard of :data:`settings.SCAN_TIMEOUT` seconds prevents an
    orphaned stream (worker died without a terminal marker) from blocking a
    consumer forever. The terminal ``{"type": "__end__"}`` marker stops the
    generator and is **not** yielded.
    """
    import redis.asyncio as aioredis  # lazy import

    client = aioredis.Redis.from_url(settings.REDIS_URL, decode_responses=True)
    key = stream_key(job_id)
    last_id = "0-0"
    deadline = time.monotonic() + settings.SCAN_TIMEOUT
    block_ms = 1000
    try:
        while True:
            if time.monotonic() > deadline:
                return
            response = await client.xread({key: last_id}, count=100, block=block_ms)
            if not response:
                continue  # block timeout elapsed with no new entries; re-check
            for _stream, entries in response:
                for entry_id, fields in entries:
                    last_id = entry_id
                    raw = fields.get("data")
                    if raw is None:
                        continue
                    try:
                        event = json.loads(raw)
                    except (TypeError, ValueError):
                        continue
                    if event.get("type") == "__end__":
                        return
                    yield event
    finally:
        try:
            await client.aclose()
        except Exception:  # noqa: BLE001 - best-effort cleanup
            pass

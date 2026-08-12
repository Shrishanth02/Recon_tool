"""Redis-Streams transport tests for :mod:`app.streaming`, backed by fakeredis.

The real transport uses a Redis stream: :class:`SyncPublisher` ``XADD``s events
from the (sync) worker and :func:`tail` ``XREAD``s them from the async API layer
until a terminal marker. These tests replace the Redis client factories with a
shared in-memory ``fakeredis`` server so the publish -> tail round-trip is
exercised with no real Redis and no network.

The suite skips gracefully if ``fakeredis`` is not importable.
"""

import asyncio

import pytest

fakeredis = pytest.importorskip("fakeredis")
import fakeredis.aioredis  # noqa: E402

from app import streaming  # noqa: E402


@pytest.fixture()
def fake_redis(monkeypatch):
    """Point both the sync and async redis factories at one fakeredis server."""
    import redis
    import redis.asyncio

    server = fakeredis.FakeServer()

    def _sync_from_url(url, **kwargs):
        return fakeredis.FakeRedis(
            server=server, decode_responses=kwargs.get("decode_responses", False)
        )

    def _async_from_url(url, **kwargs):
        return fakeredis.aioredis.FakeRedis(
            server=server, decode_responses=kwargs.get("decode_responses", False)
        )

    monkeypatch.setattr(redis.Redis, "from_url", staticmethod(_sync_from_url))
    monkeypatch.setattr(
        redis.asyncio.Redis, "from_url", staticmethod(_async_from_url)
    )
    return server


def _tail_all(job_id):
    async def _go():
        out = []
        async for event in streaming.tail(job_id):
            out.append(event)
        return out

    return asyncio.run(_go())


def test_publish_then_tail_yields_same_events(fake_redis):
    job_id = "job-round-trip"
    events = [
        {"type": "start", "tool": "nuclei", "target": "example.com"},
        {"type": "log", "data": "starting scan"},
        {"type": "result", "data": {"total": 1, "counts": {"high": 1}}},
        {"type": "returncode", "data": 0},
    ]

    pub = streaming.SyncPublisher(job_id)
    for event in events:
        pub.publish(event)
    pub.close()

    got = _tail_all(job_id)
    assert got == events
    # The terminal marker is consumed to stop, never yielded to callers.
    assert all(e.get("type") != "__end__" for e in got)


def test_tail_replays_full_backlog_for_late_subscriber(fake_redis):
    # Everything (including the terminal) is published before tail attaches;
    # tail starts from "0-0" so a late consumer still sees the whole log.
    job_id = "job-late"
    pub = streaming.SyncPublisher(job_id)
    pub.publish({"type": "log", "data": "line 1"})
    pub.publish({"type": "log", "data": "line 2"})
    pub.close()

    got = _tail_all(job_id)
    assert got == [
        {"type": "log", "data": "line 1"},
        {"type": "log", "data": "line 2"},
    ]


def test_tail_stops_at_terminal_and_ignores_post_terminal_entries(fake_redis):
    job_id = "job-terminal"
    pub = streaming.SyncPublisher(job_id)
    pub.publish({"type": "log", "data": "before terminal"})
    pub.close()  # appends the terminal marker

    # Anything written after the terminal must never be surfaced.
    pub2 = streaming.SyncPublisher(job_id)
    pub2.publish({"type": "log", "data": "after terminal"})

    got = _tail_all(job_id)
    assert got == [{"type": "log", "data": "before terminal"}]


def test_stream_key_is_namespaced_by_job_id():
    assert streaming.stream_key("abc123") == "reconx:scan:abc123"

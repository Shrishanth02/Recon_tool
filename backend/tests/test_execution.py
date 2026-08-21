"""End-to-end tests for the inline execution core (:mod:`app.execution`).

The default (and only Phase-2-verified) backend is ``inline`` — no Redis, no
Docker. These tests drive both entrypoints through the fake nuclei scanner:

* :func:`execution.stream` — the async WebSocket path: it must announce
  ``start``, forward the scanner's events, persist exactly once through the
  supplied ``on_persist`` callback, then emit ``saved`` + ``done``.
* :func:`execution.run_to_completion` — the sync REST path: it must drain the
  scanner, call ``persist`` once, and return whatever that persister returns.

An SSRF target (a private literal IP, so no DNS is needed) must be refused
*before* the scanner runs: ``stream`` yields an ``error`` then ``done`` and
never touches the scanner; ``run_to_completion`` raises ``TargetBlockedError``.
"""

import asyncio
import threading

import pytest

from app import execution, scanners
from app.config import settings


def _drain(job, on_persist):
    """Collect every event from the async ``execution.stream`` generator."""

    async def _go():
        out = []
        async for event in execution.stream(job, on_persist=on_persist):
            out.append(event)
        return out

    return asyncio.run(_go())


class _FakeScan:
    """Stand-in for the ORM ``Scan`` returned by a real persister."""

    def __init__(self, scan_id):
        self.id = scan_id


def test_default_execution_backend_is_inline():
    assert settings.EXECUTION_BACKEND == "inline"
    assert settings.use_queue is False


def test_stream_inline_persists_and_emits_saved_done(fake_scanner):
    captured = {}

    def on_persist(record):
        captured["record"] = record
        return _FakeScan(4242)

    job = execution.Job(
        tool="nuclei",
        target="example.com",
        workspace_id=7,
        created_by=11,
    )
    events = _drain(job, on_persist)
    types = [e["type"] for e in events]

    # start first, then the scanner's own events, then saved -> done last.
    assert types[0] == "start"
    assert types[-2:] == ["saved", "done"]
    assert "log" in types and "result" in types

    saved = next(e for e in events if e["type"] == "saved")
    assert saved["scan_id"] == 4242
    assert saved["workspace_id"] == 7

    # on_persist invoked exactly once, with the full assembled record.
    record = captured["record"]
    assert record["status"] == "done"
    assert record["tool"] == "nuclei"
    assert record["target"] == "example.com"
    assert record["created_by"] == 11
    assert record["error"] is None
    assert record["logs"]  # the fake scanner emitted a log line
    assert record["result"]["total"] == 1


def test_stream_inline_records_scan_metric(fake_scanner, monkeypatch):
    # STEP 4 observability: the terminal scan status feeds reconx_scans_total.
    from app import observability

    calls = []
    monkeypatch.setattr(
        observability, "record_scan", lambda tool, status: calls.append((tool, status))
    )
    job = execution.Job(tool="nuclei", target="example.com", workspace_id=7)
    _drain(job, lambda record: _FakeScan(4242))
    assert ("nuclei", "done") in calls


def test_run_to_completion_records_scan_metric(fake_scanner, monkeypatch):
    from app import observability

    calls = []
    monkeypatch.setattr(
        observability, "record_scan", lambda tool, status: calls.append((tool, status))
    )
    job = execution.Job(tool="nuclei", target="example.com", workspace_id=3)
    execution.run_to_completion(job, persist=lambda record: _FakeScan(99))
    assert ("nuclei", "done") in calls


def test_stream_ssrf_target_errors_and_skips_scanner(monkeypatch):
    calls = []

    def spy_scanner(target, cancel=None, **options):
        calls.append(target)
        yield {"type": "log", "data": "should never run"}

    monkeypatch.setitem(scanners.REGISTRY, "nuclei", spy_scanner)

    persisted = []
    job = execution.Job(tool="nuclei", target="127.0.0.1", workspace_id=1)
    events = _drain(job, lambda record: persisted.append(record))

    types = [e["type"] for e in events]
    assert types == ["error", "done"]
    assert "⛔" in events[0]["data"]
    # Scanner never invoked and nothing persisted for a blocked target.
    assert calls == []
    assert persisted == []


def test_run_to_completion_persists_and_returns(fake_scanner):
    captured = {}

    def persist(record):
        captured["record"] = record
        return _FakeScan(99)

    job = execution.Job(
        tool="nuclei",
        target="example.com",
        workspace_id=3,
        created_by=5,
    )
    result = execution.run_to_completion(job, persist=persist)

    assert isinstance(result, _FakeScan)
    assert result.id == 99
    record = captured["record"]
    assert record["status"] == "done"
    assert record["created_by"] == 5
    assert record["result"]["total"] == 1


def test_run_to_completion_ssrf_raises_target_blocked(monkeypatch):
    calls = []

    def spy_scanner(target, cancel=None, **options):
        calls.append(target)
        yield {"type": "log", "data": "should never run"}

    monkeypatch.setitem(scanners.REGISTRY, "nuclei", spy_scanner)

    job = execution.Job(tool="nuclei", target="10.0.0.5", workspace_id=1)
    with pytest.raises(execution.TargetBlockedError):
        execution.run_to_completion(job, persist=lambda record: None)
    assert calls == []


def test_job_defaults_carry_cancel_event_and_job_id():
    job = execution.Job(tool="nuclei", target="example.com")
    assert isinstance(job.cancel, threading.Event)
    assert not job.cancel.is_set()
    assert job.job_id  # a uuid hex is auto-assigned

"""nuclei scanner — honest reporting of cancelled / timed-out runs.

nuclei can match a template late in a long run, and its findings are flushed in
bursts. Previously, when the scan was cancelled or hit the wall-clock timeout the
scanner returned early and emitted NO result at all — indistinguishable from a
clean, complete run that found nothing (a false-clean). It must instead always
emit a result carrying whatever was captured, flagged incomplete.
"""
import threading

from app.scanners import nuclei_scan

_FINDING_LINE = (
    '{"template-id":"exposed-env","info":{"name":"Env File Disclosure",'
    '"severity":"high"},"matched-at":"http://t/.env"}'
)


def _run_with_fake(monkeypatch, *, cancel_midway):
    cancel = threading.Event()

    def fake_stream_command(cmd, **k):
        # nuclei emits one finding, then the run is cut short (timeout kill).
        yield {"type": "log", "data": _FINDING_LINE}
        if cancel_midway:
            cancel.set()
            yield {"type": "returncode", "data": -9}   # killed by the watcher
        else:
            yield {"type": "returncode", "data": 0}

    monkeypatch.setattr(nuclei_scan, "stream_command", fake_stream_command)
    monkeypatch.setattr(nuclei_scan, "reachable", lambda t: True)
    events = list(nuclei_scan.stream("http://t", cancel=cancel))
    results = [e["data"] for e in events if e.get("type") == "result"]
    logs = [str(e["data"]) for e in events if e.get("type") == "log"]
    return results, logs


def test_nuclei_cancelled_run_emits_partial_result_not_silent_clean(monkeypatch):
    results, logs = _run_with_fake(monkeypatch, cancel_midway=True)
    # A cancelled run must STILL yield a result (never a silent empty return)...
    assert results, "cancelled nuclei must emit a result, not return silently"
    r = results[-1]
    # ...flagged incomplete, carrying the finding parsed before the kill...
    assert r["complete"] is False
    assert r["total"] >= 1
    # ...and an explicit 'partial / not a clean result' warning.
    joined = " ".join(logs).lower()
    assert "partial" in joined and "not a clean result" in joined


def test_nuclei_complete_run_is_flagged_complete(monkeypatch):
    results, logs = _run_with_fake(monkeypatch, cancel_midway=False)
    assert results and results[-1]["complete"] is True
    assert "partial" not in " ".join(logs).lower()

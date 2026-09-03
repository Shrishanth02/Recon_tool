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


def _run_with_exit(monkeypatch, *, rc, with_error=False, finding=True):
    """Simulate a run that is NOT user-cancelled but ends with exit status ``rc`` —
    a wall-clock-timeout SIGKILL, a crash/panic, or a missing binary (rc 127).
    Crucially, ``cancel`` is never set, so this exercises the branch the old code
    got wrong (it derived 'partial' from cancel alone and discarded the rc)."""
    def fake_stream_command(cmd, **k):
        if with_error:
            yield {"type": "error", "data": "'nuclei' was not found."}
        if finding:
            yield {"type": "log", "data": _FINDING_LINE}
        yield {"type": "returncode", "data": rc}

    monkeypatch.setattr(nuclei_scan, "stream_command", fake_stream_command)
    monkeypatch.setattr(nuclei_scan, "reachable", lambda t: True)
    events = list(nuclei_scan.stream("http://t"))  # NO cancel passed in
    results = [e["data"] for e in events if e.get("type") == "result"]
    logs = [str(e["data"]) for e in events if e.get("type") == "log"]
    errors = [e for e in events if e.get("type") == "error"]
    return results, logs, errors


def test_nuclei_walltime_timeout_or_crash_is_partial_not_false_clean(monkeypatch):
    # A wall-clock timeout SIGKILLs nuclei (non-zero exit) WITHOUT setting cancel;
    # a crash/panic likewise exits non-zero. Either must be flagged PARTIAL, never
    # reported as a complete/clean run. Regression: the returncode was discarded and
    # 'partial' came from cancel.is_set() alone, so a timed-out/crashed run reported
    # complete:true / "0 findings" — a false-clean.
    results, logs, _ = _run_with_exit(monkeypatch, rc=-9)  # SIGKILL, no cancel
    assert results, "a timed-out/crashed nuclei run must still emit a result"
    r = results[-1]
    assert r["complete"] is False, "non-zero exit (timeout/crash) must be complete=False"
    assert r["total"] >= 1  # findings captured before the kill are preserved
    joined = " ".join(logs).lower()
    assert "partial" in joined and "not a clean result" in joined


def test_nuclei_missing_binary_is_partial_not_false_clean(monkeypatch):
    # A missing binary yields an error event + rc 127 and zero findings; it must
    # NOT be reported as a complete, clean scan.
    results, logs, errors = _run_with_exit(monkeypatch, rc=127, with_error=True, finding=False)
    assert errors, "missing-binary error event must be forwarded"
    assert results and results[-1]["complete"] is False
    assert results[-1]["total"] == 0

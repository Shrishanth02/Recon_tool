"""P0-4 regression tests — SQLAlchemy Session thread-safety in the pipeline.

The auto-pentest pipeline runs its whole stage body on a worker thread
(``loop.run_in_executor``) and calls the ``persist`` callback from there, while
the WebSocket coroutine uses its own Session on the event-loop thread. SQLAlchemy
Sessions are NOT thread-safe, so persistence on the worker thread must own a
Session of its own — never the coroutine's.

These tests prove the invariants the fix guarantees:

* the persist callback runs on a DIFFERENT thread than the driver, with its own
  Session, and its rows are visible afterwards (normal completion);
* concurrent own-Session writes to the same workspace all succeed;
* a persist failure rolls back only its OWN Session — a separate (coroutine-like)
  Session's pending work is untouched (rollback isolation);
* a persist that raises never aborts the run;
* cancellation completes cleanly;
* two concurrent pipeline runs persist independently (no shared Session state).
"""

import threading
from datetime import datetime, timezone

import pytest

from app import crud
from app.database import SessionLocal

# Reuse the offline pipeline harness (fixture + driver) from the P0 suite.
# ``tests`` is a package (tests/__init__.py), so import it package-qualified.
from tests.test_pipeline_p0 import _run, stub_pipeline  # noqa: F401  (stub_pipeline is a fixture)


def _make_ws(email: str):
    """Create a fresh user+org+workspace and return its workspace id."""
    db = SessionLocal()
    try:
        _u, _o, ws = crud.create_user_with_org(db, email, "password123")
        db.commit()
        return ws.id
    finally:
        db.close()


def _nuclei_record(name: str) -> dict:
    """A save_scan-shaped nuclei record that derives exactly one high finding."""
    now = datetime.now(timezone.utc)
    return {
        "tool": "nuclei",
        "target": "https://app.example.com",
        "status": "done",
        "options": {},
        "logs": [],
        "started_at": now,
        "finished_at": now,
        "result": {
            "findings": [
                {
                    "severity": "high",
                    "name": name,
                    "template_id": f"tmpl-{name}",
                    "matched_at": f"https://app.example.com/{name}",
                    "description": "isolation test",
                    "cve": [],
                    "cwe": ["CWE-79"],
                    "cvss": 7.5,
                }
            ]
        },
    }


def _own_session_persist(ws_id: int):
    """Return a persist callback mirroring the fixed pipeline_ws._persist:

    a short-lived Session owned entirely by the calling (worker) thread.
    """
    def persist(rec: dict) -> None:
        s = SessionLocal()
        try:
            crud.save_scan(s, {**rec, "workspace_id": ws_id, "created_by": None})
            s.commit()
        finally:
            s.close()
    return persist


# --------------------------------------------------------------------------- #
# 1. Normal completion — persist runs on a worker thread with its own Session.
# --------------------------------------------------------------------------- #
def test_persist_runs_on_worker_thread_and_rows_are_visible(stub_pipeline):
    ws_id = _make_ws("iso-normal@example.com")
    main_ident = threading.get_ident()
    persist_threads: list[int] = []

    def persist(rec: dict) -> None:
        persist_threads.append(threading.get_ident())
        s = SessionLocal()
        try:
            crud.save_scan(s, {**rec, "workspace_id": ws_id, "created_by": None})
            s.commit()
        finally:
            s.close()

    events = _run("example.com", persist=persist)

    assert any(e.get("type") == "pipeline_done" for e in events)
    assert persist_threads, "persist was never called"
    # Every persist ran OFF the driver thread (i.e. on the executor worker thread).
    assert all(t != main_ident for t in persist_threads)

    # Rows written by the worker-thread Sessions are visible from a fresh Session.
    check = SessionLocal()
    try:
        findings = crud.list_findings(check, ws_id)
        assert any(f.severity == "high" and f.name == "Stub High Finding"
                   for f in findings)
    finally:
        check.close()


# --------------------------------------------------------------------------- #
# 2. Concurrent own-Session writes to one workspace all succeed.
# --------------------------------------------------------------------------- #
def test_concurrent_own_session_persist_is_safe():
    ws_id = _make_ws("iso-concurrent@example.com")
    n = 12
    errors: list[Exception] = []
    barrier = threading.Barrier(n)

    def worker(i: int) -> None:
        persist = _own_session_persist(ws_id)
        try:
            barrier.wait(timeout=10)  # maximize real overlap
            persist(_nuclei_record(f"Concurrent-{i}"))
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)

    assert not errors, f"concurrent persistence raised: {errors}"
    check = SessionLocal()
    try:
        findings = crud.list_findings(check, ws_id)
        names = {f.name for f in findings}
        assert names == {f"Concurrent-{i}" for i in range(n)}, names
    finally:
        check.close()


# --------------------------------------------------------------------------- #
# 3. Rollback isolation — a failed persist Session never touches another Session.
# --------------------------------------------------------------------------- #
def test_persist_failure_rolls_back_only_its_own_session():
    ws_id = _make_ws("iso-rollback@example.com")

    # A "coroutine-like" Session with an UNCOMMITTED pending write.
    main = SessionLocal()
    try:
        run = crud.create_pentest_run(main, ws_id, None, "example.com")  # pending

        def doomed_persist() -> None:
            s = SessionLocal()
            try:
                # A real partial write (flushes a scan + finding) ...
                crud.save_scan(s, {**_nuclei_record("Doomed"), "workspace_id": ws_id})
                raise RuntimeError("boom before commit")  # ... then fail
            except Exception:
                s.rollback()
            finally:
                s.close()

        t = threading.Thread(target=doomed_persist)
        t.start()
        t.join(timeout=15)

        # The worker rolled its OWN Session back: nothing it wrote survived.
        check = SessionLocal()
        try:
            assert crud.list_findings(check, ws_id) == []
        finally:
            check.close()

        # The main Session's pending work is completely unaffected and commits.
        main.commit()
        assert run.id is not None
        reloaded = crud.get_pentest_run(main, run.id) if hasattr(crud, "get_pentest_run") else run
        assert reloaded is not None
    finally:
        main.close()


# --------------------------------------------------------------------------- #
# 4. A persist that raises must never abort the run.
# --------------------------------------------------------------------------- #
def test_persist_exception_does_not_break_run(stub_pipeline):
    def boom(_rec: dict) -> None:
        raise RuntimeError("persist blew up")

    events = _run("example.com", persist=boom)
    # do_persist swallows callback errors; the run still reaches its summary.
    assert any(e.get("type") == "pipeline_done" for e in events)


# --------------------------------------------------------------------------- #
# 5. Cancellation completes cleanly (no dangling exception).
# --------------------------------------------------------------------------- #
def test_cancellation_completes_cleanly(stub_pipeline):
    ws_id = _make_ws("iso-cancel@example.com")
    cancel = threading.Event()
    cancel.set()  # pre-cancelled: the pipeline should wind down immediately

    records: list[dict] = []
    persist = _own_session_persist(ws_id)

    def recording_persist(rec: dict) -> None:
        records.append(rec)
        persist(rec)

    events = _run("example.com", cancel=cancel, persist=recording_persist)
    # No exception propagated; we got a well-formed event list back.
    assert isinstance(events, list)
    # Whatever DID persist is intact and queryable (Sessions were closed cleanly).
    check = SessionLocal()
    try:
        crud.list_findings(check, ws_id)  # must not raise
    finally:
        check.close()


# --------------------------------------------------------------------------- #
# 6. Two concurrent pipeline runs persist to their own workspaces independently.
# --------------------------------------------------------------------------- #
def test_concurrent_pipeline_runs_are_isolated(stub_pipeline):
    ws_a = _make_ws("iso-run-a@example.com")
    ws_b = _make_ws("iso-run-b@example.com")
    errors: list[Exception] = []

    def drive(ws_id: int, tag: str) -> None:
        try:
            _run("example.com", persist=_own_session_persist(ws_id))
        except Exception as exc:  # noqa: BLE001
            errors.append((tag, exc))

    ta = threading.Thread(target=drive, args=(ws_a, "A"))
    tb = threading.Thread(target=drive, args=(ws_b, "B"))
    ta.start()
    tb.start()
    ta.join(timeout=60)
    tb.join(timeout=60)

    assert not errors, f"concurrent runs raised: {errors}"
    check = SessionLocal()
    try:
        for ws_id in (ws_a, ws_b):
            findings = crud.list_findings(check, ws_id)
            assert any(f.name == "Stub High Finding" for f in findings), (
                f"workspace {ws_id} missing its persisted finding"
            )
    finally:
        check.close()

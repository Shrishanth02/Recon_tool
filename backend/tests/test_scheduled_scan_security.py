"""P1-B4 regression tests — scheduled-scan scope + netguard security boundary.

The invariant: NO scan executes against a target that fails workspace
authorization, engagement scope, the verified-asset gate, or netguard — and the
final, authoritative check happens IMMEDIATELY before the worker runs the scanner
(TOCTOU-safe), not only at schedule creation or enqueue time.

Tested layers:
  * ``_authorize_scan_target`` — the shared gate (unit).
  * ``check_schedules`` — refuses to enqueue an unsafe schedule (before enqueue).
  * ``_execute_and_persist`` — refuses to run the scanner (before execution).
  * ``POST /schedules`` — fail-fast rejection at creation.
"""

import threading
from datetime import datetime, timedelta, timezone

import pytest

from app import crud, models, worker
from app.database import SessionLocal


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _make_ws(email: str, scope=None):
    db = SessionLocal()
    try:
        u, o, ws = crud.create_user_with_org(db, email, "password123")
        if scope is not None:
            ws.scope = scope
            db.add(ws)
        db.commit()
        return ws.id, o.id, u.id
    finally:
        db.close()


def _set_scope(ws_id: int, scope: list):
    db = SessionLocal()
    try:
        ws = crud.get_workspace(db, ws_id)
        ws.scope = scope
        db.add(ws)
        db.commit()
    finally:
        db.close()


class FakePublisher:
    """Stand-in for SyncPublisher so tests need no Redis."""

    def __init__(self, job_id):
        self.events = []

    def publish(self, ev):
        self.events.append(ev)

    def close(self):
        pass


def _scanner_factory(ran_flag: dict, with_finding=True):
    def scanner(target, cancel=None, **opts):
        ran_flag["called"] = True
        if with_finding:
            yield {"type": "result", "data": {"findings": [{
                "severity": "high", "name": "StubFinding", "template_id": "t",
                "matched_at": str(target), "cve": [], "cwe": ["CWE-1"], "cvss": 1.0,
            }]}}
    return scanner


PUBLIC = "1.1.1.1"      # public literal IP (passes netguard, no DNS)
OTHER_PUBLIC = "8.8.8.8"


# --------------------------------------------------------------------------- #
# The shared gate — _authorize_scan_target
# --------------------------------------------------------------------------- #
def test_gate_allows_in_scope_public_target():
    ws_id, _o, _u = _make_ws("gate-ok@e.com", scope=[PUBLIC])
    db = SessionLocal()
    try:
        allowed, reason, ws = worker._authorize_scan_target(db, ws_id, PUBLIC)
        assert allowed, reason
        assert ws is not None
    finally:
        db.close()


def test_gate_blocks_out_of_scope_target():
    ws_id, _o, _u = _make_ws("gate-oos@e.com", scope=[PUBLIC])
    db = SessionLocal()
    try:
        allowed, reason, _ws = worker._authorize_scan_target(db, ws_id, OTHER_PUBLIC)
        assert not allowed and "scope" in reason.lower()
    finally:
        db.close()


@pytest.mark.parametrize("bad", ["127.0.0.1", "10.0.0.5", "192.168.1.1",
                                 "169.254.1.1", "169.254.169.254", "::1", "fe80::1"])
def test_gate_blocks_private_loopback_linklocal_metadata(bad):
    # Unrestricted scope so the decision falls to netguard.
    ws_id, _o, _u = _make_ws(f"gate-ng-{bad}@e.com", scope=[])
    db = SessionLocal()
    try:
        allowed, reason, _ws = worker._authorize_scan_target(db, ws_id, bad)
        assert not allowed and "netguard" in reason.lower()
    finally:
        db.close()


def test_gate_blocks_dns_that_resolves_to_private(monkeypatch):
    ws_id, _o, _u = _make_ws("gate-rebind@e.com", scope=[])
    monkeypatch.setattr(
        worker_netguard().socket, "getaddrinfo",
        lambda *a, **k: [(2, 1, 6, "", ("10.0.0.9", 0))],  # resolves to private
    )
    db = SessionLocal()
    try:
        allowed, reason, _ws = worker._authorize_scan_target(db, ws_id, "rebind.example")
        assert not allowed and "netguard" in reason.lower()
    finally:
        db.close()


def test_gate_blocks_unknown_workspace():
    db = SessionLocal()
    try:
        allowed, reason, ws = worker._authorize_scan_target(db, 999999, PUBLIC)
        assert not allowed and ws is None
    finally:
        db.close()


@pytest.mark.parametrize("bad", ["", "   ", None])
def test_gate_blocks_malformed_target(bad):
    ws_id, _o, _u = _make_ws(f"gate-mal-{bad!r}@e.com", scope=[])
    db = SessionLocal()
    try:
        allowed, reason, _ws = worker._authorize_scan_target(db, ws_id, bad)
        assert not allowed
    finally:
        db.close()


def test_gate_blocks_cross_tenant_target():
    # Workspace A only scopes PUBLIC; a target that belongs to B's scope is not
    # in A's scope, so scheduling it under A is refused.
    ws_a, _oa, _ua = _make_ws("tenant-a@e.com", scope=[PUBLIC])
    _ws_b, _ob, _ub = _make_ws("tenant-b@e.com", scope=[OTHER_PUBLIC])
    db = SessionLocal()
    try:
        allowed, reason, _ws = worker._authorize_scan_target(db, ws_a, OTHER_PUBLIC)
        assert not allowed and "scope" in reason.lower()
    finally:
        db.close()


def test_gate_enforces_verified_asset_when_required(monkeypatch):
    from app.config import settings
    monkeypatch.setattr(settings, "REQUIRE_VERIFIED_ASSET", True)
    ws_id, _o, _u = _make_ws("gate-verify@e.com", scope=[PUBLIC])
    db = SessionLocal()
    try:
        allowed, reason, _ws = worker._authorize_scan_target(db, ws_id, PUBLIC)
        assert not allowed and "verified asset" in reason.lower()
    finally:
        db.close()


def worker_netguard():
    from app import netguard
    return netguard


# --------------------------------------------------------------------------- #
# Worker execution boundary — _execute_and_persist
# --------------------------------------------------------------------------- #
def _job(ws_id, uid, target, tool="nuclei"):
    return {"job_id": f"j-{target}", "tool": tool, "target": target,
            "options": {}, "workspace_id": ws_id, "created_by": uid}


def test_worker_runs_allowed_target_and_persists_findings(monkeypatch):
    ws_id, _o, uid = _make_ws("wrk-ok@e.com", scope=[PUBLIC])
    monkeypatch.setattr(worker, "SyncPublisher", FakePublisher)
    ran = {"called": False}
    monkeypatch.setattr(worker, "get_scanner", lambda tool: _scanner_factory(ran))
    result = worker._execute_and_persist(_job(ws_id, uid, PUBLIC))
    assert result["status"] == "done"
    assert ran["called"] is True
    db = SessionLocal()
    try:
        assert len(crud.list_findings(db, ws_id)) == 1
    finally:
        db.close()


def test_worker_blocks_out_of_scope_target_without_running_scanner(monkeypatch):
    ws_id, org_id, uid = _make_ws("wrk-blk@e.com", scope=[PUBLIC])
    monkeypatch.setattr(worker, "SyncPublisher", FakePublisher)
    ran = {"called": False}
    monkeypatch.setattr(worker, "get_scanner", lambda tool: _scanner_factory(ran))

    result = worker._execute_and_persist(_job(ws_id, uid, OTHER_PUBLIC))

    assert result["status"] == "blocked"
    assert ran["called"] is False                      # scanner NEVER ran
    db = SessionLocal()
    try:
        assert crud.list_findings(db, ws_id) == []     # no findings from a block
        scans = crud.list_scans(db, ws_id)
        assert any(s.status == "blocked" for s in scans)  # rejection recorded
        audits = db.query(models.AuditLog).filter_by(org_id=org_id).all()
        assert any(a.action == "scan-blocked" for a in audits)  # audited, not silent
    finally:
        db.close()


@pytest.mark.parametrize("bad", ["127.0.0.1", "169.254.169.254", ""])
def test_worker_blocks_unsafe_targets(monkeypatch, bad):
    ws_id, _o, uid = _make_ws(f"wrk-ng-{bad!r}@e.com", scope=[])
    monkeypatch.setattr(worker, "SyncPublisher", FakePublisher)
    ran = {"called": False}
    monkeypatch.setattr(worker, "get_scanner", lambda tool: _scanner_factory(ran))
    result = worker._execute_and_persist(_job(ws_id, uid, bad))
    assert result["status"] == "blocked"
    assert ran["called"] is False


def test_concurrent_scheduled_executions_are_isolated(monkeypatch):
    ws_ok, _o1, u_ok = _make_ws("conc-ok@e.com", scope=[PUBLIC])
    ws_blk, _o2, u_blk = _make_ws("conc-blk@e.com", scope=[PUBLIC])
    monkeypatch.setattr(worker, "SyncPublisher", FakePublisher)
    ran = {"called": False}
    monkeypatch.setattr(worker, "get_scanner", lambda tool: _scanner_factory(ran))

    results = {}

    def run(key, ws_id, uid, target):
        results[key] = worker._execute_and_persist(_job(ws_id, uid, target))

    t1 = threading.Thread(target=run, args=("ok", ws_ok, u_ok, PUBLIC))
    t2 = threading.Thread(target=run, args=("blk", ws_blk, u_blk, OTHER_PUBLIC))
    t1.start(); t2.start(); t1.join(15); t2.join(15)

    assert results["ok"]["status"] == "done"
    assert results["blk"]["status"] == "blocked"
    db = SessionLocal()
    try:
        assert len(crud.list_findings(db, ws_ok)) == 1
        assert crud.list_findings(db, ws_blk) == []
    finally:
        db.close()


# --------------------------------------------------------------------------- #
# Scheduler — check_schedules (before enqueue)
# --------------------------------------------------------------------------- #
def _due_schedule(ws_id, uid, target, tool="nuclei"):
    db = SessionLocal()
    try:
        sched = crud.create_schedule(
            db, workspace_id=ws_id, tool=tool, target=target,
            cron="*/5 * * * *", options={}, enabled=True, created_by=uid,
        )
        sched.next_run_at = datetime.now(timezone.utc) - timedelta(minutes=1)  # due
        db.add(sched)
        db.commit()
        return sched.id
    finally:
        db.close()


def _patch_queue(monkeypatch):
    calls = []
    import app.queue as q

    async def fake_enqueue(jobdict):
        calls.append(jobdict)
        return "queued-id"

    monkeypatch.setattr(q, "enqueue_scan", fake_enqueue)
    return calls


def test_check_schedules_rejects_out_of_scope_before_enqueue(monkeypatch):
    import asyncio
    from app.config import settings
    monkeypatch.setattr(settings, "SCHEDULER_ENABLED", True)
    ws_id, org_id, uid = _make_ws("sch-oos@e.com", scope=[PUBLIC])
    _due_schedule(ws_id, uid, OTHER_PUBLIC)
    calls = _patch_queue(monkeypatch)

    result = asyncio.run(worker.check_schedules({}))

    assert result["rejected"] >= 1
    assert calls == []          # NOT enqueued
    db = SessionLocal()
    try:
        audits = db.query(models.AuditLog).filter_by(org_id=org_id).all()
        assert any(a.action == "schedule-rejected" for a in audits)
    finally:
        db.close()


def test_check_schedules_enqueues_in_scope(monkeypatch):
    import asyncio
    from app.config import settings
    monkeypatch.setattr(settings, "SCHEDULER_ENABLED", True)
    ws_id, _o, uid = _make_ws("sch-ok@e.com", scope=[PUBLIC])
    _due_schedule(ws_id, uid, PUBLIC)
    calls = _patch_queue(monkeypatch)

    result = asyncio.run(worker.check_schedules({}))

    assert result["enqueued"] >= 1
    assert len(calls) >= 1       # enqueued exactly the in-scope job
    assert any(c.get("target") == PUBLIC for c in calls)


# --------------------------------------------------------------------------- #
# Creation fail-fast — POST /schedules
# --------------------------------------------------------------------------- #
def test_create_schedule_rejects_out_of_scope(client, auth):
    _set_scope(auth["ws_id"], [PUBLIC])
    r = client.post(
        f"/workspaces/{auth['ws_id']}/schedules", headers=auth["headers"],
        json={"tool": "nuclei", "target": OTHER_PUBLIC, "cron": "0 0 * * *",
              "options": {}, "enabled": True},
    )
    assert r.status_code == 403, r.text


def test_create_schedule_allows_in_scope(client, auth):
    _set_scope(auth["ws_id"], [PUBLIC])
    r = client.post(
        f"/workspaces/{auth['ws_id']}/schedules", headers=auth["headers"],
        json={"tool": "nuclei", "target": PUBLIC, "cron": "0 0 * * *",
              "options": {}, "enabled": True},
    )
    assert r.status_code == 201, r.text

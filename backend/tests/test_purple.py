"""Purple-Team P4 tests — continuous purple loop + coverage dashboard + drift.

Fully hermetic. The SAFE emulation engine's HTTP/TCP transports are monkeypatched
with the same fakes P2/P3 use (no packet ever leaves the box), the detection side
runs against the deterministic :class:`~app.connectors.mock.MockConnector`, and the
notification dispatch is stubbed for the drift assertions. Nothing here touches a
real network, SIEM, Redis, or arq.

Coverage:

* Integration: ``POST /workspaces/{id}/purple-run`` against an in-scope target
  with a mock connector persists an ``EmulationRun`` + ``TechniqueResult`` rows +
  ``DetectionResult`` rows and returns a coverage summary; an out-of-scope target
  is refused 403. ``GET /workspaces/{id}/coverage`` returns
  summary/techniques/tactics/trend/gaps consistent with the run (emulated
  techniques present, missed ones surface as gaps).
* Unit: ``crud.coverage_dashboard`` math over a hand-built run + detections.
* Drift: a second purple run where a previously-detected technique is now missed
  emits a ``detection_drift`` event (``notify.dispatch`` is stubbed and asserted to
  have been called with the regressions).
* Scheduler: ``worker.check_schedules`` with a due ``tool="purple"`` schedule runs
  the purple loop inline (``run_purple`` is stubbed) and advances ``next_run_at``.
"""

import pytest

from app import crud, netguard, notify, purple, worker
from app.connectors.mock import MockConnector
from app.database import SessionLocal

# Reuse the P2 emulation fakes verbatim so the whole path stays hermetic.
from tests.test_emulation import (
    FakeSocketModule,
    RecordingRequests,
    _patch_transport,
    _set_scope,
    safe_transport,  # noqa: F401  (pytest fixture, imported for use)
)

# The five techniques the SAFE emulation registry fires, in execution order.
ALL_TECHNIQUE_IDS = {"T1595.002", "T1190", "T1071.001", "T1046", "T1048"}


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _create_connector(client, auth, headers=None, **overrides):
    """Create an org-scoped detection connector (defaults to a full-coverage mock)."""
    body = {
        "name": overrides.get("name", "Primary SIEM"),
        "ctype": overrides.get("ctype", "mock"),
        "config": overrides.get("config", {"coverage": 1.0}),
        "enabled": overrides.get("enabled", True),
    }
    return client.post(
        f"/orgs/{auth['org_id']}/detection-connectors",
        headers=headers or auth["headers"],
        json=body,
    )


def _seed_run(db, ws_id, techniques, detections=None, created_by=None, target="example.com"):
    """Hand-build a persisted emulation run (+ optional detection results).

    ``techniques`` is a list of ``(technique_id, name, tactic, status)`` tuples;
    ``detections`` is a list of ``(technique_id, name, tactic, detected)`` tuples.
    """
    run = crud.create_emulation_run(db, ws_id, created_by, target)
    executed = blocked = failed = 0
    for tid, name, tactic, status in techniques:
        crud.save_technique_result(
            db,
            run.id,
            {
                "technique_id": tid,
                "name": name,
                "tactic": tactic,
                "status": status,
                "evidence": "",
                "detail": "",
            },
        )
        if status == "executed":
            executed += 1
        elif status == "blocked":
            blocked += 1
        elif status == "failed":
            failed += 1
    crud.finish_emulation_run(
        db, run, executed=executed, blocked=blocked, failed=failed, summary={}
    )
    if detections:
        crud.save_detection_results(
            db,
            run.id,
            None,
            [
                {
                    "technique_id": tid,
                    "technique_name": name,
                    "tactic": tactic,
                    "detected": det,
                    "count": 1 if det else 0,
                    "source": "mock",
                    "evidence": "",
                }
                for tid, name, tactic, det in detections
            ],
        )
    db.flush()
    return run


# =========================================================================== #
# Integration — POST /workspaces/{id}/purple-run
# =========================================================================== #
def test_purple_run_in_scope_persists_and_returns_summary(client, auth, safe_transport):
    """An in-scope purple run persists the run + technique + detection results."""
    _set_scope(client, auth, ["example.com"])
    conn = _create_connector(client, auth, config={"coverage": 1.0}).json()

    resp = client.post(
        f"/workspaces/{auth['ws_id']}/purple-run",
        headers=auth["headers"],
        json={"target": "example.com", "connector_id": conn["id"]},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()

    # The emulation run persisted with all five technique results.
    run = body["emulation_run"]
    run_id = run["id"]
    assert run["target"] == "example.com"
    assert run["status"] == "done"
    assert run["executed"] == 5
    assert {r["technique_id"] for r in run["technique_results"]} == ALL_TECHNIQUE_IDS

    # Full-coverage mock => every technique detected, and the rows persisted.
    detections = body["detections"]
    assert len(detections) == 5
    assert all(d["detected"] is True for d in detections)
    assert all(d["emulation_run_id"] == run_id for d in detections)

    # The coverage summary reflects the full detection.
    summary = body["summary"]
    assert summary["validated"] is True
    assert summary["total"] == 5
    assert summary["detected"] == 5
    assert summary["missed"] == 0
    assert summary["coverage_pct"] == 100
    # First run for the workspace => no prior baseline => no drift.
    assert body["drift"] is None

    # Only benign GET/POST marker traffic left the box.
    assert safe_transport.calls
    for call in safe_transport.calls:
        assert call["method"] in {"GET", "POST"}
        assert call["url"].startswith("http://example.com")


def test_purple_run_out_of_scope_is_refused(client, auth, safe_transport):
    """An out-of-scope target is refused 403 and nothing is persisted."""
    _set_scope(client, auth, ["example.com"])
    conn = _create_connector(client, auth).json()

    resp = client.post(
        f"/workspaces/{auth['ws_id']}/purple-run",
        headers=auth["headers"],
        json={"target": "attacker.net", "connector_id": conn["id"]},
    )
    assert resp.status_code == 403, resp.text

    # No run was created, and no emulation traffic was issued.
    listing = client.get(
        f"/workspaces/{auth['ws_id']}/emulations", headers=auth["headers"]
    )
    assert listing.status_code == 200
    assert listing.json() == []
    assert safe_transport.calls == []


def test_purple_run_without_connector_only_emulates(client, auth, safe_transport):
    """Omitting the connector runs the RED half only (unvalidated, no detections)."""
    _set_scope(client, auth, ["example.com"])

    resp = client.post(
        f"/workspaces/{auth['ws_id']}/purple-run",
        headers=auth["headers"],
        json={"target": "example.com"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["detections"] == []
    assert body["summary"]["validated"] is False
    assert body["summary"]["coverage_pct"] is None
    assert body["drift"] is None


# =========================================================================== #
# Integration — GET /workspaces/{id}/coverage consistent with the run
# =========================================================================== #
def test_coverage_dashboard_reflects_partial_run(client, auth, safe_transport):
    """A partial-coverage purple run drives a consistent coverage dashboard."""
    _set_scope(client, auth, ["example.com"])
    # Detect exactly two of the five emulated techniques.
    conn = _create_connector(
        client, auth, config={"detect_technique_ids": ["T1046", "T1190"]}
    ).json()

    run_resp = client.post(
        f"/workspaces/{auth['ws_id']}/purple-run",
        headers=auth["headers"],
        json={"target": "example.com", "connector_id": conn["id"]},
    )
    assert run_resp.status_code == 200, run_resp.text
    run_id = run_resp.json()["emulation_run"]["id"]

    cov = client.get(
        f"/workspaces/{auth['ws_id']}/coverage", headers=auth["headers"]
    )
    assert cov.status_code == 200, cov.text
    data = cov.json()

    # Summary math: 5 emulated, 2 detected, 3 missed, 40% coverage.
    summary = data["summary"]
    assert summary["techniques_emulated"] == 5
    assert summary["detected"] == 2
    assert summary["missed"] == 3
    assert summary["not_validated"] == 0
    assert summary["coverage_pct"] == 40

    # Every emulated technique is present and flagged emulated.
    assert {t["technique_id"] for t in data["techniques"]} == ALL_TECHNIQUE_IDS
    assert all(t["emulated"] is True for t in data["techniques"])

    # The three undetected techniques surface as gaps; detected ones do not.
    gap_ids = {g["technique_id"] for g in data["gaps"]}
    assert gap_ids == {"T1595.002", "T1071.001", "T1048"}

    # Tactics rollup is populated; the trend carries the single validated run.
    assert data["tactics"]
    assert len(data["trend"]) == 1
    assert data["trend"][0]["run_id"] == run_id
    assert data["trend"][0]["coverage_pct"] == 40


def test_coverage_dashboard_empty_before_any_run(client, auth):
    """A workspace with no runs yields an all-empty dashboard (coverage None)."""
    cov = client.get(
        f"/workspaces/{auth['ws_id']}/coverage", headers=auth["headers"]
    )
    assert cov.status_code == 200, cov.text
    data = cov.json()
    assert data["summary"]["techniques_emulated"] == 0
    assert data["summary"]["coverage_pct"] is None
    assert data["techniques"] == []
    assert data["tactics"] == []
    assert data["trend"] == []
    assert data["gaps"] == []


# =========================================================================== #
# Unit — crud.coverage_dashboard math on a hand-built run + detections
# =========================================================================== #
def test_coverage_dashboard_math_hand_built(client, auth):
    """coverage_dashboard computes coverage over only executed/blocked techniques."""
    db = SessionLocal()
    try:
        _seed_run(
            db,
            auth["ws_id"],
            techniques=[
                ("T1046", "Network Service Discovery", "discovery", "executed"),
                ("T1190", "Exploit Public-Facing App", "initial-access", "blocked"),
                ("T1071.001", "Web Protocols", "command-and-control", "skipped"),
                ("T1595.002", "Vulnerability Scanning", "reconnaissance", "failed"),
                ("T1048", "Exfil Over Alt Protocol", "exfiltration", "executed"),
            ],
            detections=[
                ("T1046", "Network Service Discovery", "discovery", True),
                ("T1190", "Exploit Public-Facing App", "initial-access", False),
                ("T1048", "Exfil Over Alt Protocol", "exfiltration", True),
            ],
        )
        db.commit()

        dash = crud.coverage_dashboard(db, auth["ws_id"])
    finally:
        db.close()

    # Only the 3 executed/blocked techniques count; skipped/failed are dropped.
    summary = dash["summary"]
    assert summary["techniques_emulated"] == 3
    assert summary["detected"] == 2
    assert summary["missed"] == 1
    assert summary["not_validated"] == 0
    assert summary["coverage_pct"] == round(100 * 2 / 3)  # 67

    assert {t["technique_id"] for t in dash["techniques"]} == {"T1046", "T1190", "T1048"}
    # The one missed technique is the sole gap.
    assert [g["technique_id"] for g in dash["gaps"]] == ["T1190"]
    # Trend carries the single validated run at the same coverage.
    assert len(dash["trend"]) == 1
    assert dash["trend"][0]["coverage_pct"] == round(100 * 2 / 3)


def test_coverage_dashboard_latest_run_wins(client, auth):
    """When a technique is re-emulated, its latest run + verdict supersede the old."""
    db = SessionLocal()
    try:
        # Run 1: T1046 emulated and missed.
        _seed_run(
            db,
            auth["ws_id"],
            techniques=[("T1046", "Network Service Discovery", "discovery", "executed")],
            detections=[("T1046", "Network Service Discovery", "discovery", False)],
        )
        db.commit()
        # Run 2 (later id): same technique now detected.
        run2 = _seed_run(
            db,
            auth["ws_id"],
            techniques=[("T1046", "Network Service Discovery", "discovery", "executed")],
            detections=[("T1046", "Network Service Discovery", "discovery", True)],
        )
        db.commit()

        dash = crud.coverage_dashboard(db, auth["ws_id"])
        techs = {t["technique_id"]: t for t in dash["techniques"]}
    finally:
        db.close()

    # One technique row, reflecting the latest (detected) verdict and run.
    assert set(techs) == {"T1046"}
    assert techs["T1046"]["detected"] is True
    assert techs["T1046"]["last_run_id"] == run2.id
    # No gaps now that the latest verdict is a detection.
    assert dash["gaps"] == []
    assert dash["summary"]["coverage_pct"] == 100


# =========================================================================== #
# Drift — a regressed second run emits a detection_drift event
# =========================================================================== #
def test_drift_event_on_regression(client, auth, monkeypatch):
    """A previously-detected technique now missed dispatches a detection_drift alert."""
    reqs = RecordingRequests(status_code=200, reason="OK")
    sock = FakeSocketModule(connect_result=1)
    _patch_transport(monkeypatch, reqs, sock)

    dispatched = []
    monkeypatch.setattr(
        notify, "dispatch", lambda ch, ev: dispatched.append(ev) or {"ok": True}
    )

    db = SessionLocal()
    try:
        ws = crud.get_workspace(db, auth["ws_id"])
        # Subscribe an enabled channel to the drift event so dispatch is exercised.
        crud.create_channel(
            db,
            auth["org_id"],
            "webhook",
            {"url": "https://hooks.example/drift"},
            ["detection_drift"],
            True,
        )
        db.commit()

        # Run 1: full coverage -> every technique detected. No baseline -> no drift.
        _, _, s1 = purple.run_purple(
            db,
            workspace=ws,
            target="example.com",
            connector=MockConnector({"coverage": 1.0}),
            created_by=None,
        )
        db.commit()
        assert s1["drift"] is None
        assert dispatched == []

        # Run 2: zero coverage -> techniques detected-before are now missed.
        _, _, s2 = purple.run_purple(
            db,
            workspace=ws,
            target="example.com",
            connector=MockConnector({"coverage": 0.0}),
            created_by=None,
        )
        db.commit()
    finally:
        db.close()

    # A drift event was produced and carries the regressed techniques.
    drift = s2["drift"]
    assert drift is not None
    assert drift["type"] == purple.DRIFT_EVENT_TYPE == "detection_drift"
    assert drift["regressions"], "expected at least one detection regression"
    regressed_ids = {r["technique_id"] for r in drift["regressions"]}
    assert "T1046" in regressed_ids  # detected in run 1, missed in run 2
    assert drift["coverage_before"] == 100
    assert drift["coverage_after"] == 0

    # And it was dispatched to the subscribed channel.
    assert dispatched, "notify.dispatch should have been called for the drift event"
    assert dispatched[0]["type"] == "detection_drift"
    assert dispatched[0]["regressions"]


# =========================================================================== #
# Scheduler — a due purple schedule runs the loop inline and advances
# =========================================================================== #
@pytest.mark.asyncio
async def test_check_schedules_runs_purple_and_advances(client, auth, monkeypatch):
    """A due tool='purple' schedule invokes run_purple and advances next_run_at."""
    calls = []

    def fake_run_purple(db, workspace, target, connector, created_by, technique_ids=None):
        calls.append(
            {"target": target, "ws_id": workspace.id, "techniques": technique_ids}
        )
        return (None, [], {})

    monkeypatch.setattr(purple, "run_purple", fake_run_purple)
    monkeypatch.setattr(netguard, "validate_target", lambda target: (True, "ok"))
    monkeypatch.setattr(worker.settings, "SCHEDULER_ENABLED", True)

    # Seed an in-scope, immediately-due purple schedule.
    db = SessionLocal()
    try:
        ws = crud.get_workspace(db, auth["ws_id"])
        ws.scope = ["example.com"]
        db.add(ws)
        sched = crud.create_schedule(
            db,
            auth["ws_id"],
            "purple",
            "example.com",
            "0 3 * * *",
            config={"techniques": ["E1"]},
            created_by=auth["user_id"],
        )
        sched.next_run_at = None  # NULL == immediately due
        db.add(sched)
        db.commit()
        sched_id = sched.id
    finally:
        db.close()

    result = await worker.check_schedules({})

    # The purple leg ran exactly once, inline, with the schedule's params.
    assert result["purple"] == 1
    assert result["due"] >= 1
    assert len(calls) == 1
    assert calls[0]["target"] == "example.com"
    assert calls[0]["ws_id"] == auth["ws_id"]
    assert calls[0]["techniques"] == ["E1"]

    # The schedule was advanced so it will not immediately re-fire.
    db = SessionLocal()
    try:
        after = crud.get_schedule(db, sched_id)
        assert after.next_run_at is not None
        assert after.last_run_at is not None
    finally:
        db.close()

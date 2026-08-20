"""Purple-Team P5 tests — the AI triage auto-chain degrades gracefully OFF.

``purple.run_purple`` now chains the deterministic scanners into the optional
Claude triage layer and stamps ``summary["triage"]`` with a compact
``{"enabled": bool, ...}`` dict. With no ``ANTHROPIC_API_KEY`` (the test env)
triage MUST report ``enabled == False`` and never raise — the run stays green
whether or not the AI is configured.

These tests pin the key OFF explicitly (so the assertion holds even if a key
leaks into the environment) and exercise the chain three ways: the
``chain_triage`` helper directly, ``run_purple`` in-process, and the full
``POST /workspaces/{id}/purple-run`` route. All paths are hermetic — the SAFE
emulation transports are faked, so no packet leaves the box.
"""

import pytest

from app import ai, crud, purple
from app.database import SessionLocal

from tests.test_emulation import (
    FakeSocketModule,
    RecordingRequests,
    _patch_transport,
    _set_scope,
    safe_transport,  # noqa: F401  (pytest fixture, imported for use)
)


def _seed_findings(ws_id, specs):
    """Persist a scan + Finding rows so triage has something to prioritize."""
    from app import models

    db = SessionLocal()
    try:
        scan = models.Scan(
            workspace_id=ws_id, tool="nuclei", target="example.com", status="done"
        )
        db.add(scan)
        db.flush()
        for s in specs:
            db.add(
                models.Finding(
                    scan_id=scan.id,
                    workspace_id=ws_id,
                    source="nuclei",
                    severity=s.get("severity", "high"),
                    name=s.get("name", "finding"),
                    location=s.get("location", ""),
                    description=s.get("description", ""),
                    status="open",
                    technique_id=s.get("technique_id"),
                    tactic=s.get("tactic"),
                )
            )
        db.commit()
    finally:
        db.close()


@pytest.fixture()
def ai_off(monkeypatch):
    """Deterministically force AI triage OFF by clearing the API key.

    The test env has no ``ANTHROPIC_API_KEY``, but pinning it empty here makes the
    graceful-off assertions robust even if one leaks into the process. ``settings``
    is the same singleton ``app.ai`` reads at call time.
    """
    monkeypatch.setattr(ai.settings, "ANTHROPIC_API_KEY", "")
    assert ai.settings.ai_enabled is False  # guard: we really are OFF
    return None


# =========================================================================== #
# chain_triage — direct, graceful-off
# =========================================================================== #
def test_chain_triage_disabled_without_api_key(client, auth, ai_off):
    """chain_triage returns a compact disabled dict and never raises (no key)."""
    _seed_findings(
        auth["ws_id"], [{"severity": "high", "name": "RCE", "technique_id": "T1046"}]
    )

    db = SessionLocal()
    try:
        ws = crud.get_workspace(db, auth["ws_id"])
        out = purple.chain_triage(db, ws)  # must not raise
    finally:
        db.close()

    assert isinstance(out, dict)
    assert out["enabled"] is False
    assert "reason" in out and out["reason"]
    assert out["count"] == 1
    assert out["top"] == []


def test_chain_triage_disabled_with_no_findings(client, auth, ai_off):
    """Even with zero findings the disabled path is graceful (count 0)."""
    db = SessionLocal()
    try:
        ws = crud.get_workspace(db, auth["ws_id"])
        out = purple.chain_triage(db, ws)
    finally:
        db.close()
    assert out["enabled"] is False
    assert out["count"] == 0
    assert out["top"] == []


# =========================================================================== #
# run_purple — the summary carries a disabled triage block
# =========================================================================== #
def test_run_purple_summary_carries_disabled_triage(client, auth, ai_off, monkeypatch):
    """run_purple's summary includes triage with enabled False (no key)."""
    reqs = RecordingRequests(status_code=200, reason="OK")
    sock = FakeSocketModule(connect_result=1)
    _patch_transport(monkeypatch, reqs, sock)
    _seed_findings(
        auth["ws_id"], [{"severity": "high", "name": "RCE", "technique_id": "T1046"}]
    )

    db = SessionLocal()
    try:
        ws = crud.get_workspace(db, auth["ws_id"])
        run, detections, summary = purple.run_purple(
            db, workspace=ws, target="example.com", connector=None, created_by=None
        )
        db.commit()
    finally:
        db.close()

    assert "triage" in summary
    assert summary["triage"]["enabled"] is False
    # The RED half still ran (no connector => unvalidated), proving triage-off did
    # not abort the loop.
    assert summary["executed"] >= 0
    assert summary["validated"] is False


# =========================================================================== #
# Route — POST /workspaces/{id}/purple-run reports triage disabled
# =========================================================================== #
def test_purple_run_route_reports_triage_disabled(client, auth, ai_off, safe_transport):
    """The purple-run endpoint's summary reports triage.enabled == False."""
    _set_scope(client, auth, ["example.com"])
    resp = client.post(
        f"/workspaces/{auth['ws_id']}/purple-run",
        headers=auth["headers"],
        json={"target": "example.com"},
    )
    assert resp.status_code == 200, resp.text
    summary = resp.json()["summary"]
    assert "triage" in summary
    assert summary["triage"]["enabled"] is False

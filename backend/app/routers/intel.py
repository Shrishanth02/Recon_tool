"""Phase 4 intelligence routes: risk scoring, scan diffing, AI triage,
recurring schedules, and org notification channels.

Every route is tenant-scoped. Workspace-scoped routes resolve the workspace and
the caller's membership via :func:`deps.get_workspace_for_user` (404 hides
existence from non-members); org-scoped routes gate on :func:`deps.require_role`.
Reads require ``viewer``/membership; mutations require ``analyst`` or higher,
matching the rest of the platform.

Nothing here depends on an external service at import time: the AI layer
(:mod:`app.ai`) lazy-imports the ``anthropic`` SDK and degrades to a structured
``{"enabled": False}`` response when no key/SDK is present, and notification
dispatch is owned by the worker, not these synchronous routes.
"""

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Path, Query, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from .. import ai, crud, diffing, models, risk, schemas, scope, security
from ..deps import get_current_user, get_db, get_workspace_for_user, require_role

router = APIRouter(tags=["intel"])


class ScheduleToggleIn(BaseModel):
    """Body for enabling/disabling a schedule via PATCH."""

    enabled: bool


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _require_ws_role(membership: models.Membership, min_role: str) -> None:
    """Raise 403 unless ``membership`` holds at least ``min_role``."""
    if security.ROLE_RANK.get(membership.role, -1) < security.ROLE_RANK[min_role]:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, f"Requires role '{min_role}' or higher"
        )


def _finding_dicts(findings: list[models.Finding]) -> list[dict[str, Any]]:
    """Serialize ORM findings to plain dicts for the pure risk/diff/AI helpers."""
    return [schemas.FindingOut.model_validate(f).model_dump() for f in findings]


def _scan_finding_dicts(scan: models.Scan | None) -> list[dict[str, Any]]:
    """Return a scan's findings as dicts (empty list when the scan is None)."""
    if scan is None:
        return []
    return [schemas.FindingOut.model_validate(f).model_dump() for f in scan.findings]


# --------------------------------------------------------------------------- #
# Risk score
# --------------------------------------------------------------------------- #
@router.get("/workspaces/{ws_id}/risk", response_model=schemas.RiskOut)
def workspace_risk(
    ctx: tuple[models.Workspace, models.Membership] = Depends(get_workspace_for_user),
    db: Session = Depends(get_db),
):
    """Compute the workspace's aggregate 0-100 risk score over its findings."""
    ws, _membership = ctx
    return risk.workspace_risk(_finding_dicts(crud.list_findings(db, ws.id)))


# --------------------------------------------------------------------------- #
# Scan diff
# --------------------------------------------------------------------------- #
@router.get("/workspaces/{ws_id}/diff", response_model=schemas.DiffOut)
def workspace_diff(
    tool: str = Query(...),
    target: str = Query(...),
    ctx: tuple[models.Workspace, models.Membership] = Depends(get_workspace_for_user),
    db: Session = Depends(get_db),
):
    """Diff the two most recent scans of ``tool``/``target`` in the workspace."""
    ws, _membership = ctx
    previous, current = crud.latest_two_scans(db, ws.id, tool, target)
    return diffing.diff_findings(
        _scan_finding_dicts(previous), _scan_finding_dicts(current)
    )


# --------------------------------------------------------------------------- #
# AI triage
# --------------------------------------------------------------------------- #
@router.post("/workspaces/{ws_id}/triage")
def run_triage(
    ctx: tuple[models.Workspace, models.Membership] = Depends(get_workspace_for_user),
    db: Session = Depends(get_db),
):
    """Run AI triage over the workspace's findings (analyst+); persist on success.

    Returns the structured :func:`app.ai.triage_findings` envelope verbatim. When
    AI is unavailable (no key/SDK) it is ``{"enabled": False, "reason": ...}`` and
    nothing is persisted; on a successful run the result is saved via
    :func:`crud.save_triage` before being returned.
    """
    ws, membership = ctx
    _require_ws_role(membership, "analyst")

    findings = _finding_dicts(crud.list_findings(db, ws.id))
    # Release the read transaction/connection BEFORE the (potentially slow)
    # external AI call: the findings are already materialized to plain dicts and
    # this path has no pending writes, so holding a pooled DB connection across a
    # network call is unnecessary. save_triage/audit below re-acquire a fresh
    # transaction. (The purple path shares a write transaction by design and is
    # bounded by AI_TIMEOUT instead — see app.purple.chain_triage.)
    db.rollback()
    outcome = ai.triage_findings(findings)

    if outcome.get("enabled") and isinstance(outcome.get("result"), dict):
        crud.save_triage(
            db,
            workspace_id=ws.id,
            created_by=membership.user_id,
            model=outcome.get("model", ""),
            triage_dict=outcome["result"],
        )
        crud.audit(db, ws.org_id, membership.user_id, "ai-triage", f"ws#{ws.id}")
        db.commit()

    return outcome


@router.get("/workspaces/{ws_id}/triage")
def get_triage(
    ctx: tuple[models.Workspace, models.Membership] = Depends(get_workspace_for_user),
    db: Session = Depends(get_db),
):
    """Return the most recent persisted triage for the workspace, if any."""
    ws, _membership = ctx
    row = crud.latest_triage(db, ws.id)
    if row is None:
        return {"enabled": False, "reason": "no triage has been run for this workspace"}
    return {
        "enabled": True,
        "model": row.model,
        "summary": row.summary,
        "risk_narrative": row.risk_narrative,
        "result": row.data,
        "created_at": row.created_at,
        "created_by": row.created_by,
    }


# --------------------------------------------------------------------------- #
# Schedules (workspace-scoped)
# --------------------------------------------------------------------------- #
@router.get("/workspaces/{ws_id}/schedules", response_model=list[schemas.ScheduleOut])
def list_schedules(
    ctx: tuple[models.Workspace, models.Membership] = Depends(get_workspace_for_user),
    db: Session = Depends(get_db),
):
    """List a workspace's recurring scan schedules."""
    ws, _membership = ctx
    return [schemas.ScheduleOut.model_validate(s) for s in crud.list_schedules(db, ws.id)]


@router.post(
    "/workspaces/{ws_id}/schedules",
    response_model=schemas.ScheduleOut,
    status_code=201,
)
def create_schedule(
    payload: schemas.ScheduleIn,
    ctx: tuple[models.Workspace, models.Membership] = Depends(get_workspace_for_user),
    db: Session = Depends(get_db),
):
    """Create a recurring scan schedule (analyst+)."""
    ws, membership = ctx
    _require_ws_role(membership, "analyst")
    # P1-B4: validate the scheduled target against the SAME boundary as a manual
    # scan (engagement scope + verified-asset gate) so an out-of-scope/unverified
    # schedule can't be created. Fail-fast only — the scheduler and the worker
    # re-validate (incl. netguard) at enqueue and execution time, because a
    # target's scope/DNS can change after the schedule is created.
    allowed, reason = scope.check(payload.target or "", ws.scope)
    if not allowed:
        crud.audit(db, ws.org_id, membership.user_id, "scope-denied",
                   f"schedule {payload.tool} {payload.target}: {reason}")
        db.commit()
        raise HTTPException(status.HTTP_403_FORBIDDEN, reason)
    if not crud.is_target_authorized(db, ws.id, payload.target or ""):
        crud.audit(db, ws.org_id, membership.user_id, "asset-denied",
                   f"schedule {payload.tool} {payload.target}")
        db.commit()
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "Target is not a verified asset for this workspace.",
        )
    sched = crud.create_schedule(
        db,
        workspace_id=ws.id,
        tool=payload.tool,
        target=payload.target,
        cron=payload.cron,
        options=payload.options,
        enabled=payload.enabled,
        created_by=membership.user_id,
    )
    crud.audit(
        db, ws.org_id, membership.user_id, "schedule-create", f"{payload.tool} {payload.target}"
    )
    db.commit()
    return schemas.ScheduleOut.model_validate(sched)


@router.delete("/schedules/{schedule_id}", status_code=204)
def delete_schedule(
    schedule_id: int = Path(...),
    user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Delete a schedule (analyst+ within its workspace's org)."""
    sched = crud.get_schedule(db, schedule_id)
    if not sched:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Schedule not found")
    ws = crud.get_workspace(db, sched.workspace_id)
    membership = crud.get_membership(db, user.id, ws.org_id) if ws else None
    if not membership:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Schedule not found")
    _require_ws_role(membership, "analyst")
    crud.delete_schedule(db, sched)
    crud.audit(db, ws.org_id, user.id, "schedule-delete", f"#{schedule_id}")
    db.commit()
    return None


@router.patch("/schedules/{schedule_id}", response_model=schemas.ScheduleOut)
def patch_schedule(
    payload: ScheduleToggleIn,
    schedule_id: int = Path(...),
    user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Enable or disable a schedule (analyst+ within its workspace's org)."""
    sched = crud.get_schedule(db, schedule_id)
    if not sched:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Schedule not found")
    ws = crud.get_workspace(db, sched.workspace_id)
    membership = crud.get_membership(db, user.id, ws.org_id) if ws else None
    if not membership:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Schedule not found")
    _require_ws_role(membership, "analyst")
    crud.set_schedule_enabled(db, sched, payload.enabled)
    crud.audit(db, ws.org_id, user.id, "schedule-toggle", f"#{schedule_id} -> {payload.enabled}")
    db.commit()
    return schemas.ScheduleOut.model_validate(sched)


# --------------------------------------------------------------------------- #
# Notification channels (org-scoped)
# --------------------------------------------------------------------------- #
@router.get("/orgs/{org_id}/notifications", response_model=list[schemas.ChannelOut])
def list_notifications(
    org_id: int = Path(...),
    membership: models.Membership = Depends(require_role("viewer")),
    db: Session = Depends(get_db),
):
    """List an org's notification channels (viewer+)."""
    return [schemas.ChannelOut.model_validate(c) for c in crud.list_channels(db, org_id)]


@router.post(
    "/orgs/{org_id}/notifications",
    response_model=schemas.ChannelOut,
    status_code=201,
)
def create_notification(
    payload: schemas.ChannelIn,
    org_id: int = Path(...),
    membership: models.Membership = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    """Create a notification channel for an org (ADMIN+).

    Admin-gated because a channel's config is an external sink (Slack/webhook/
    email) that receives every new finding — a low-trust analyst must not be able
    to point org findings at an attacker-controlled webhook. Matches the admin
    gate on the other secret-bearing org integrations (connectors, API keys, SSO).
    """
    channel = crud.create_channel(
        db,
        org_id=org_id,
        ctype=payload.ctype,
        config=payload.config,
        events=payload.events,
        enabled=payload.enabled,
    )
    crud.audit(db, org_id, membership.user_id, "channel-create", payload.ctype)
    db.commit()
    return schemas.ChannelOut.model_validate(channel)


@router.delete("/notifications/{channel_id}", status_code=204)
def delete_notification(
    channel_id: int = Path(...),
    user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Delete a notification channel (ADMIN+ within its org)."""
    channel = db.get(models.NotificationChannel, channel_id)
    if not channel:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Channel not found")
    membership = crud.get_membership(db, user.id, channel.org_id)
    if not membership:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Channel not found")
    _require_ws_role(membership, "admin")
    crud.delete_channel(db, channel)
    crud.audit(db, channel.org_id, user.id, "channel-delete", f"#{channel_id}")
    db.commit()
    return None

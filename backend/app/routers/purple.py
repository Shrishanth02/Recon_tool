"""Purple-Team P4: continuous purple-loop + coverage-dashboard routes.

Exposes the one-call purple loop (:func:`app.purple.run_purple`) and the
workspace coverage dashboard (:func:`app.crud.coverage_dashboard`) over REST, so
an analyst can answer "are we exposed and would we catch it?" in a single request
and read the rolled-up posture back.

The launch route is triple-gated *before* a single packet leaves the box,
mirroring :mod:`app.routers.emulation`:

1. :func:`app.scope.check`              — target must be in the workspace scope (403).
2. :func:`app.netguard.validate_target` — SSRF/egress safety (403 if unsafe).
3. :func:`app.billing.check_quota`      — the org's monthly scan quota (402).

Workspace access + the analyst role gate reuse :func:`deps.get_workspace_for_user`
(404 hides existence from non-members). The dashboard read is member-gated.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from .. import (
    billing,
    crud,
    models,
    netguard,
    preflight,
    purple,
    report,
    schemas,
    scope,
    security,
)
from ..deps import get_db, get_workspace_for_user

router = APIRouter(tags=["purple"])


@router.post(
    "/workspaces/{ws_id}/purple-run",
    response_model=schemas.PurpleRunOut,
)
def run_workspace_purple(
    payload: schemas.PurpleRunIn,
    ctx: tuple[models.Workspace, models.Membership] = Depends(get_workspace_for_user),
    db: Session = Depends(get_db),
):
    """Run a continuous purple loop against an authorized target (analyst+).

    Enforces the analyst role, then scope + SSRF/netguard + billing quota before
    running :func:`app.purple.run_purple` (emulate, then validate against the
    optional connector). Persists the emulation run, its technique results, and —
    when a connector is given — the detection results, audits the action, and
    returns ``{emulation_run, detections, summary, drift}``.
    """
    ws, membership = ctx
    if security.ROLE_RANK.get(membership.role, -1) < security.ROLE_RANK["analyst"]:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, "Requires role 'analyst' or higher"
        )
    acting_user = membership.user_id

    target = (payload.target or "").strip()
    if not target:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "A target is required")

    # --- Scope gate --------------------------------------------------------- #
    allowed, reason = scope.check(target, ws.scope)
    if not allowed:
        crud.audit(db, ws.org_id, acting_user, "purple-scope-denied", f"{target}: {reason}")
        db.commit()
        raise HTTPException(status.HTTP_403_FORBIDDEN, reason)

    # --- SSRF / egress safety gate (netguard) ------------------------------- #
    safe, nreason = netguard.validate_target(target)
    if not safe:
        crud.audit(db, ws.org_id, acting_user, "purple-target-blocked", f"{target}: {nreason}")
        db.commit()
        raise HTTPException(status.HTTP_403_FORBIDDEN, nreason)

    # --- Billing quota gate ------------------------------------------------- #
    org = crud.get_org(db, ws.org_id)
    ok, qreason = billing.check_quota(db, org, "scan")
    if not ok:
        crud.audit(db, ws.org_id, acting_user, "purple-quota-denied", f"purple: {qreason}")
        db.commit()
        raise HTTPException(status.HTTP_402_PAYMENT_REQUIRED, qreason)

    # --- Resolve the optional detection connector (same org, enabled). ------ #
    connector_row = None
    if payload.connector_id is not None:
        connector_row = crud.get_detection_connector(db, payload.connector_id)
        # Cross-tenant / missing connector is a 404 (don't leak existence).
        if not connector_row or connector_row.org_id != ws.org_id:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Connector not found")
        if not connector_row.enabled:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Connector is disabled")

    # --- Run the purple loop and persist ------------------------------------ #
    run, detections, summary = purple.run_purple(
        db,
        workspace=ws,
        target=target,
        connector=connector_row,
        created_by=acting_user,
        technique_ids=payload.techniques,
    )
    cov = summary.get("coverage_pct")
    crud.audit(
        db,
        ws.org_id,
        acting_user,
        "purple-run",
        f"{target} (run {run.id}, "
        f"{summary['executed']} executed, {summary['blocked']} blocked; "
        f"coverage {cov if cov is not None else 'n/a'})",
    )
    db.commit()
    db.refresh(run)
    return schemas.PurpleRunOut(
        emulation_run=schemas.EmulationRunOut.model_validate(run),
        detections=[schemas.DetectionResultOut.model_validate(d) for d in detections],
        summary=summary,
        drift=summary.get("drift"),
    )


@router.get(
    "/workspaces/{ws_id}/coverage",
    response_model=schemas.CoverageDashboardOut,
)
def workspace_coverage(
    ctx: tuple[models.Workspace, models.Membership] = Depends(get_workspace_for_user),
    db: Session = Depends(get_db),
):
    """Return the workspace's continuous-purple coverage dashboard (member)."""
    ws, _membership = ctx
    return schemas.CoverageDashboardOut(**crud.coverage_dashboard(db, ws.id))


@router.get(
    "/workspaces/{ws_id}/pentest-runs",
    response_model=list[schemas.PentestRunOut],
)
def list_pentest_runs(
    ctx: tuple[models.Workspace, models.Membership] = Depends(get_workspace_for_user),
    db: Session = Depends(get_db),
):
    """List a workspace's auto-pentest runs, newest first (member)."""
    ws, _membership = ctx
    return [
        schemas.PentestRunOut.model_validate(r)
        for r in crud.list_pentest_runs(db, ws.id)
    ]


@router.get(
    "/workspaces/{ws_id}/pentest-runs/{run_id}",
    response_model=schemas.PentestRunDetailOut,
)
def get_pentest_run(
    run_id: int,
    ctx: tuple[models.Workspace, models.Membership] = Depends(get_workspace_for_user),
    db: Session = Depends(get_db),
):
    """Return a single auto-pentest run WITH its full stage-by-stage process (member)."""
    ws, _membership = ctx
    run = crud.get_pentest_run(db, run_id)
    if not run or run.workspace_id != ws.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Pentest run not found")
    return schemas.PentestRunDetailOut.model_validate(run)


@router.delete("/workspaces/{ws_id}/pentest-runs/{run_id}", status_code=204)
def delete_pentest_run(
    run_id: int,
    ctx: tuple[models.Workspace, models.Membership] = Depends(get_workspace_for_user),
    db: Session = Depends(get_db),
):
    """Delete an auto-pentest run summary (analyst+; 404 if not in this workspace)."""
    ws, membership = ctx
    if security.ROLE_RANK.get(membership.role, -1) < security.ROLE_RANK["analyst"]:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Requires role 'analyst' or higher")
    run = crud.get_pentest_run(db, run_id)
    if not run or run.workspace_id != ws.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Pentest run not found")
    crud.delete_pentest_run(db, run)
    crud.audit(db, ws.org_id, membership.user_id, "pentest-run-delete", f"run #{run_id}")
    db.commit()
    return None


@router.get("/workspaces/{ws_id}/purple-report", response_class=HTMLResponse)
def workspace_purple_report(
    ctx: tuple[models.Workspace, models.Membership] = Depends(get_workspace_for_user),
    db: Session = Depends(get_db),
):
    """Render the printable purple-team report for a workspace (member).

    Extends the recon engagement report with the ATT&CK coverage matrix,
    detection gaps, coverage trend and the AI-triage prioritized actions —
    assembled from the same sources the coverage dashboard and engagement
    report already use, so it stays consistent with both.
    """
    ws, _membership = ctx
    findings = [
        schemas.FindingOut.model_validate(f).model_dump()
        for f in crud.list_findings(db, ws.id)
    ]
    scans = [
        schemas.ScanOut.model_validate(s).model_dump()
        for s in crud.list_scans(db, ws.id)
    ]
    project = {
        "name": ws.name,
        "description": ws.description,
        "scope": ws.scope or [],
    }
    coverage = crud.coverage_dashboard(db, ws.id)
    triage_row = crud.latest_triage(db, ws.id)
    # The persisted payload is the raw TriageOut shape (summary / risk_narrative /
    # items / dedup_groups) — the `enabled` flag lived only on the triage_findings
    # ENVELOPE, which both save paths strip before persisting. The renderer gates
    # the section on `enabled`, so without re-adding it the flagship AI-triage
    # section always rendered "unavailable" even when triage ran. A persisted row
    # only ever exists for a successful, enabled triage (both save paths gate on
    # it), so marking it enabled here is correct; no row -> None -> "unavailable".
    triage = {**triage_row.data, "enabled": True} if triage_row else None
    org = crud.get_org(db, ws.org_id)
    branding = crud.org_branding(org)
    _pf = preflight.check_tools()
    tools = {**_pf.get("required", {}), **_pf.get("optional", {})}
    return HTMLResponse(
        report.generate_purple(
            project, findings, scans, coverage, triage=triage, branding=branding, tools=tools
        )
    )

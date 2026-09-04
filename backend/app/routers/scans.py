"""Scanning routes: tool catalogue, synchronous REST runs, history, findings,
finding triage, and the HTML engagement report.

The synchronous ``GET /scan/{tool}`` endpoint accepts either a Bearer JWT or an
``X-API-Key`` (via :func:`deps.get_principal`), resolves the target workspace,
enforces the workspace's scope and the Phase 2 verified-asset gate, then runs the
scan to completion via :func:`app.execution.run_to_completion`, persists it, and
derives its findings.

Execution concerns — the SSRF netguard, the shared inline concurrency cap
(``execution.scan_slots``, sized from ``MAX_CONCURRENT_SCANS`` and shared with
the WebSocket router), and draining the scanner — live in :mod:`app.execution`,
so this router no longer owns its own semaphore.
"""

from fastapi import APIRouter, Depends, HTTPException, Path, Query, status
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from .. import billing, crud, execution, models, preflight, report, schemas, scope, security
from ..deps import Principal, get_current_user, get_db, get_principal, get_workspace_for_user
from ..scanners import TOOLS, get_scanner

router = APIRouter(tags=["scans"])


# --------------------------------------------------------------------------- #
# Authorization helper for principal-based (JWT or API-key) scan access
# --------------------------------------------------------------------------- #
def resolve_scan_workspace(
    db: Session, principal: Principal, ws_id: int, min_role: str = "analyst"
) -> models.Workspace:
    """Resolve and authorize a workspace for a scan by a JWT/API-key principal.

    * ``ws_id`` of 0/None falls back to the principal's org default workspace.
    * API-key principals are authorized when the workspace is in their org.
    * User principals must hold at least ``min_role`` in the workspace's org.

    404 hides existence from callers who can't see the workspace; 403 is used
    for an authenticated member lacking the required role.
    """
    if not ws_id:
        org_id = principal.org_id
        if org_id is None and principal.user is not None:
            orgs = crud.list_user_orgs(db, principal.user)
            org_id = orgs[0].id if orgs else None
        if org_id is None:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "workspace_id is required")
        ws_id = crud.default_workspace_id_for_org(db, org_id)
        if not ws_id:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "No workspace for this org")

    ws = crud.get_workspace(db, ws_id)
    if not ws:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Workspace not found")

    if principal.is_api_key:
        if principal.org_id != ws.org_id:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Workspace not found")
        return ws

    membership = crud.get_membership(db, principal.user_id, ws.org_id)
    if not membership:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Workspace not found")
    if security.ROLE_RANK.get(membership.role, -1) < security.ROLE_RANK[min_role]:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, f"Requires role '{min_role}' or higher"
        )
    return ws


def _authorize_workspace_read(
    db: Session, user: models.User, ws_id: int
) -> models.Workspace:
    """Load a workspace the ``user`` may read, or 404 (existence-hiding)."""
    ws = crud.get_workspace(db, ws_id)
    if not ws or not crud.get_membership(db, user.id, ws.org_id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Workspace not found")
    return ws


# --------------------------------------------------------------------------- #
# Tool catalogue
# --------------------------------------------------------------------------- #
@router.get("/tools")
def tools(principal: Principal = Depends(get_principal)):
    """Return the scanner catalogue that drives the UI."""
    return {"tools": TOOLS}


# --------------------------------------------------------------------------- #
# Synchronous REST scan
# --------------------------------------------------------------------------- #
@router.get("/scan/{tool}", response_model=schemas.ScanOut)
def run_scan(
    tool: str = Path(...),
    target: str = Query(...),
    workspace_id: int = Query(0),
    scan_type: str = Query("quick"),
    severity: str = Query("low,medium,high,critical"),
    principal: Principal = Depends(get_principal),
    db: Session = Depends(get_db),
):
    """Run a scan synchronously, persist it, and return the stored record."""
    if get_scanner(tool) is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Unknown tool: {tool}")
    target = (target or "").strip()
    if not target:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "A target is required")

    ws = resolve_scan_workspace(db, principal, workspace_id)

    options: dict = {}
    if tool == "nmap":
        options["scan_type"] = scan_type
    elif tool == "nuclei":
        options["severity"] = severity

    allowed, reason = scope.check(target, ws.scope)
    if not allowed:
        crud.audit(db, ws.org_id, principal.user_id, "scope-denied", f"{tool} {target}: {reason}")
        db.commit()
        raise HTTPException(status.HTTP_403_FORBIDDEN, reason)

    # --- Verified-asset gate (Phase 2) -------------------------------------- #
    # No-op unless settings.REQUIRE_VERIFIED_ASSET is on (Phase 0/1 unchanged).
    if not crud.is_target_authorized(db, ws.id, target):
        crud.audit(db, ws.org_id, principal.user_id, "asset-denied", f"{tool} {target}")
        db.commit()
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "Target is not a verified asset for this workspace.",
        )

    # --- Billing quota gate (Phase 3) --------------------------------------- #
    # No-op unless settings.billing_enabled (BILLING_MODE != "none"); billing.
    # check_quota returns (True, "billing disabled") in that case. When active,
    # a scan over the plan's monthly limit is refused with 402 Payment Required.
    org = crud.get_org(db, ws.org_id)
    allowed, reason = billing.check_quota(db, org, "scan")
    if not allowed:
        crud.audit(db, ws.org_id, principal.user_id, "quota-denied", f"scan: {reason}")
        db.commit()
        raise HTTPException(status.HTTP_402_PAYMENT_REQUIRED, reason)

    # --- Delegate execution to the shared core ------------------------------ #
    # execution.run_to_completion owns netguard, the shared concurrency cap, and
    # draining the scanner; it calls our persister once and returns the saved
    # Scan (inline mode) so ScanOut.model_validate works exactly as before.
    job = execution.Job(
        tool=tool,
        target=target,
        options=options,
        workspace_id=ws.id,
        created_by=principal.user_id,
    )

    def persist(record: dict):
        scan = crud.save_scan(db, record)
        crud.audit(db, ws.org_id, principal.user_id, "scan", f"{tool} {target}")
        db.commit()
        return scan

    try:
        result = execution.run_to_completion(job, persist=persist)
    except execution.TargetBlockedError as exc:
        crud.audit(db, ws.org_id, principal.user_id, "target-blocked", f"{tool} {target}: {exc.reason}")
        db.commit()
        raise HTTPException(status.HTTP_403_FORBIDDEN, exc.reason)
    except execution.ScanCapacityError as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(exc))
    except execution.ScanBackendError as exc:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, str(exc))

    return schemas.ScanOut.model_validate(result)


# --------------------------------------------------------------------------- #
# History / findings
# --------------------------------------------------------------------------- #
@router.get("/workspaces/{ws_id}/scans", response_model=list[schemas.ScanSummaryOut])
def list_scans(
    ctx: tuple[models.Workspace, models.Membership] = Depends(get_workspace_for_user),
    db: Session = Depends(get_db),
):
    """List a workspace's scan history (most recent first)."""
    ws, _membership = ctx
    return [schemas.ScanSummaryOut.model_validate(s) for s in crud.list_scans(db, ws.id)]


@router.get("/scans/{scan_id}", response_model=schemas.ScanOut)
def get_scan(
    scan_id: int = Path(...),
    user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Fetch a single stored scan the caller can see."""
    scan = crud.get_scan(db, scan_id)
    if not scan:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Scan not found")
    _authorize_workspace_read(db, user, scan.workspace_id)
    return schemas.ScanOut.model_validate(scan)


def _authorize_workspace_write(
    db: Session, user: models.User, ws_id: int, role: str = "analyst"
) -> tuple[models.Workspace, models.Membership]:
    """Load a workspace the ``user`` may modify at ``role``+, or 404/403."""
    ws = crud.get_workspace(db, ws_id)
    membership = crud.get_membership(db, user.id, ws.org_id) if ws else None
    if not ws or not membership:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Workspace not found")
    if security.ROLE_RANK.get(membership.role, -1) < security.ROLE_RANK[role]:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, f"Requires role '{role}' or higher"
        )
    return ws, membership


@router.delete("/scans/{scan_id}", status_code=204)
def delete_scan(
    scan_id: int = Path(...),
    user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Delete a single stored scan (and its findings). Analyst+ within its workspace."""
    scan = crud.get_scan(db, scan_id)
    if not scan:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Scan not found")
    ws, membership = _authorize_workspace_write(db, user, scan.workspace_id, "analyst")
    crud.delete_scan(db, scan)
    crud.audit(db, ws.org_id, user.id, "scan-delete", f"scan #{scan_id} ({scan.tool} {scan.target})")
    db.commit()
    return None


@router.delete("/workspaces/{ws_id}/scans")
def clear_scans(
    ws_id: int = Path(...),
    user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Clear ALL scan history + findings for a workspace. Admin+ (destructive)."""
    ws, membership = _authorize_workspace_write(db, user, ws_id, "admin")
    removed = crud.clear_workspace_scans(db, ws.id)
    crud.audit(db, ws.org_id, user.id, "scans-clear", f"cleared {removed} scan(s) from ws {ws.id}")
    db.commit()
    return {"deleted": removed}


@router.get("/workspaces/{ws_id}/findings", response_model=list[schemas.FindingOut])
def list_findings(
    ctx: tuple[models.Workspace, models.Membership] = Depends(get_workspace_for_user),
    db: Session = Depends(get_db),
):
    """List a workspace's findings, ordered critical-first."""
    ws, _membership = ctx
    return [schemas.FindingOut.model_validate(f) for f in crud.list_findings(db, ws.id)]


@router.patch("/findings/{finding_id}", response_model=schemas.FindingOut)
def patch_finding(
    payload: schemas.FindingPatchIn,
    finding_id: int = Path(...),
    user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Update a finding's triage status (analyst+)."""
    finding = crud.get_finding(db, finding_id)
    if not finding:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Finding not found")
    ws = crud.get_workspace(db, finding.workspace_id)
    membership = crud.get_membership(db, user.id, ws.org_id) if ws else None
    if not membership:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Finding not found")
    if security.ROLE_RANK.get(membership.role, -1) < security.ROLE_RANK["analyst"]:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Requires role 'analyst' or higher")

    crud.update_finding_status(db, finding, payload.status)
    crud.audit(db, ws.org_id, user.id, "finding-status", f"#{finding.id} -> {payload.status}")
    db.commit()
    return schemas.FindingOut.model_validate(finding)


# --------------------------------------------------------------------------- #
# Report
# --------------------------------------------------------------------------- #
@router.get("/workspaces/{ws_id}/report", response_class=HTMLResponse)
def workspace_report(
    ctx: tuple[models.Workspace, models.Membership] = Depends(get_workspace_for_user),
    db: Session = Depends(get_db),
):
    """Render the printable HTML engagement report for a workspace."""
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
    # White-label branding (Phase 5): pull the owning org's branding and pass it
    # through. crud.org_branding returns {} when nothing is configured, so the
    # rendered report is byte-identical to before for unbranded orgs.
    org = crud.get_org(db, ws.org_id)
    branding = crud.org_branding(org)
    # Tool availability drives the honest coverage matrix (e.g. SQLi -> NOT TESTED
    # when sqlmap is absent). Merge required+optional into a flat {tool: present}.
    _pf = preflight.check_tools()
    tools = {**_pf.get("required", {}), **_pf.get("optional", {})}
    return HTMLResponse(report.generate(project, findings, scans, branding=branding, tools=tools))

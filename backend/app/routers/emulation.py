"""Purple-Team P2: SAFE ATT&CK emulation routes.

Exposes the SAFE emulation engine (:mod:`app.emulation`) over REST so an analyst
can fire non-destructive, ATT&CK-mapped technique tests at an authorized target
and persist the resulting telemetry for later detection validation (P3).

Every emulation launch is triple-gated *before* a single packet leaves the box,
mirroring the synchronous scan route in :mod:`app.routers.scans`:

1. :func:`app.scope.check`         — the target must be in the workspace scope (403).
2. :func:`app.netguard.validate_target` — SSRF/egress safety (403 if unsafe).
3. :func:`app.billing.check_quota` — the org's monthly scan quota (402).

Workspace access + the analyst role gate reuse :func:`deps.get_workspace_for_user`
(404 hides existence from non-members). The read routes are member-gated.
"""

from fastapi import APIRouter, Depends, HTTPException, Path, status
from sqlalchemy.orm import Session

from .. import billing, crud, emulation, models, netguard, schemas, scope, security
from ..deps import get_current_user, get_db, get_workspace_for_user

router = APIRouter(tags=["emulation"])


@router.post(
    "/workspaces/{ws_id}/emulate",
    response_model=schemas.EmulationRunOut,
)
def run_workspace_emulation(
    payload: schemas.EmulationRunIn,
    ctx: tuple[models.Workspace, models.Membership] = Depends(get_workspace_for_user),
    db: Session = Depends(get_db),
):
    """Launch a SAFE ATT&CK emulation against an authorized target (analyst+).

    Enforces the analyst role, then scope + SSRF/netguard + billing quota before
    running the engine. Persists the run and each technique result, audits the
    action, and returns the finished run with its per-technique outcomes.
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
        crud.audit(db, ws.org_id, acting_user, "emulation-scope-denied", f"{target}: {reason}")
        db.commit()
        raise HTTPException(status.HTTP_403_FORBIDDEN, reason)

    # --- SSRF / egress safety gate (netguard) ------------------------------- #
    safe, nreason = netguard.validate_target(target)
    if not safe:
        crud.audit(db, ws.org_id, acting_user, "emulation-target-blocked", f"{target}: {nreason}")
        db.commit()
        raise HTTPException(status.HTTP_403_FORBIDDEN, nreason)

    # --- Billing quota gate ------------------------------------------------- #
    org = crud.get_org(db, ws.org_id)
    ok, qreason = billing.check_quota(db, org, "scan")
    if not ok:
        crud.audit(db, ws.org_id, acting_user, "emulation-quota-denied", f"emulate: {qreason}")
        db.commit()
        raise HTTPException(status.HTTP_402_PAYMENT_REQUIRED, qreason)

    # --- Run the SAFE emulation engine and persist -------------------------- #
    run = crud.create_emulation_run(db, ws.id, acting_user, target)
    outcome = emulation.run_emulation(target, payload.techniques)
    for result in outcome["results"]:
        crud.save_technique_result(db, run.id, result)
    crud.finish_emulation_run(
        db,
        run,
        executed=outcome["executed"],
        blocked=outcome["blocked"],
        failed=outcome["failed"],
        summary=outcome,
    )
    crud.audit(
        db,
        ws.org_id,
        acting_user,
        "emulation",
        f"{target} ({outcome['executed']} executed, {outcome['blocked']} blocked, "
        f"{outcome['failed']} failed)",
    )
    db.commit()
    db.refresh(run)
    return schemas.EmulationRunOut.model_validate(run)


@router.get(
    "/workspaces/{ws_id}/emulations",
    response_model=list[schemas.EmulationRunOut],
)
def list_workspace_emulations(
    ctx: tuple[models.Workspace, models.Membership] = Depends(get_workspace_for_user),
    db: Session = Depends(get_db),
):
    """List a workspace's SAFE emulation runs (most recent first, member)."""
    ws, _membership = ctx
    return [
        schemas.EmulationRunOut.model_validate(r)
        for r in crud.list_emulation_runs(db, ws.id)
    ]


@router.get("/emulations/{run_id}", response_model=schemas.EmulationRunOut)
def get_emulation(
    run_id: int = Path(...),
    user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Fetch a single emulation run with its results (member of its workspace)."""
    run = crud.get_emulation_run(db, run_id)
    if not run:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Emulation run not found")
    ws = crud.get_workspace(db, run.workspace_id)
    if not ws or not crud.get_membership(db, user.id, ws.org_id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Emulation run not found")
    return schemas.EmulationRunOut.model_validate(run)

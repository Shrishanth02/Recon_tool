"""Purple-Team P1: MITRE ATT&CK coverage route.

Exposes the workspace ATT&CK coverage matrix so the app can speak purple-team
language — every finding is tagged with an ATT&CK technique/tactic at derivation
time (see :func:`app.crud.save_scan`), and this route rolls those tags up into a
tactic -> technique matrix with per-severity counts.

The single endpoint is workspace-scoped and member-gated via
:func:`deps.get_workspace_for_user` (404 hides existence from non-members),
mirroring the read routes in :mod:`app.routers.scans` / :mod:`app.routers.intel`.
"""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from .. import crud, models, schemas
from ..deps import get_db, get_workspace_for_user

router = APIRouter(tags=["attack"])


@router.get(
    "/workspaces/{ws_id}/attack-coverage",
    response_model=schemas.AttackCoverageOut,
)
def workspace_attack_coverage(
    ctx: tuple[models.Workspace, models.Membership] = Depends(get_workspace_for_user),
    db: Session = Depends(get_db),
):
    """Return the workspace's MITRE ATT&CK coverage matrix over its findings."""
    ws, _membership = ctx
    return crud.attack_coverage(db, ws.id)

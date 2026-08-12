"""Workspace (engagement) routes.

A workspace is the tenant's client/engagement container and carries the
authorized ``scope``. Role gating:

* list/get — ``viewer+`` (any member of the owning org)
* create/update-scope/delete — ``admin+`` (workspace management)

Workspace-scoped routes use :func:`deps.get_workspace_for_user`, which resolves
``(workspace, membership)`` and returns 404 for anything the caller can't see.
"""

from fastapi import APIRouter, Depends, HTTPException, Path, status
from sqlalchemy.orm import Session

from .. import crud, models, schemas, security
from ..deps import get_db, get_workspace_for_user, require_role

router = APIRouter(tags=["workspaces"])


def _require_ws_role(membership: models.Membership, min_role: str) -> None:
    """Enforce a minimum role for an operation on an already-resolved workspace."""
    if security.ROLE_RANK.get(membership.role, -1) < security.ROLE_RANK[min_role]:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, f"Requires role '{min_role}' or higher"
        )


@router.get("/orgs/{org_id}/workspaces", response_model=list[schemas.WorkspaceOut])
def list_workspaces(
    org_id: int = Path(...),
    membership: models.Membership = Depends(require_role("viewer")),
    db: Session = Depends(get_db),
):
    """List the workspaces of an organization, each with summary counts."""
    out = []
    for ws in crud.list_workspaces(db, org_id):
        out.append(schemas.WorkspaceOut.model_validate(crud.workspace_summary(db, ws)))
    return out


@router.post("/orgs/{org_id}/workspaces", response_model=schemas.WorkspaceOut, status_code=201)
def create_workspace(
    payload: schemas.WorkspaceIn,
    org_id: int = Path(...),
    membership: models.Membership = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    """Create a new workspace within the organization."""
    ws = crud.create_workspace(
        db, org_id, payload.name, payload.description, payload.scope
    )
    crud.audit(db, org_id, membership.user_id, "workspace-create", ws.slug)
    db.commit()
    return schemas.WorkspaceOut.model_validate(crud.workspace_summary(db, ws))


@router.get("/workspaces/{ws_id}", response_model=schemas.WorkspaceOut)
def get_workspace(
    ctx: tuple[models.Workspace, models.Membership] = Depends(get_workspace_for_user),
    db: Session = Depends(get_db),
):
    """Fetch a single workspace (any member of its org) with summary counts."""
    ws, _membership = ctx
    return schemas.WorkspaceOut.model_validate(crud.workspace_summary(db, ws))


@router.put("/workspaces/{ws_id}/scope", response_model=schemas.WorkspaceOut)
def update_scope(
    payload: schemas.ScopeIn,
    ctx: tuple[models.Workspace, models.Membership] = Depends(get_workspace_for_user),
    db: Session = Depends(get_db),
):
    """Replace a workspace's authorized scope list (admin+)."""
    ws, membership = ctx
    _require_ws_role(membership, "admin")
    crud.update_scope(db, ws, payload.scope)
    crud.audit(db, ws.org_id, membership.user_id, "scope-update", f"ws {ws.id}")
    db.commit()
    return schemas.WorkspaceOut.model_validate(crud.workspace_summary(db, ws))


@router.delete("/workspaces/{ws_id}")
def delete_workspace(
    ctx: tuple[models.Workspace, models.Membership] = Depends(get_workspace_for_user),
    db: Session = Depends(get_db),
):
    """Delete a workspace and everything under it (admin+)."""
    ws, membership = ctx
    _require_ws_role(membership, "admin")
    ws_id = ws.id
    org_id = ws.org_id
    crud.delete_workspace(db, ws)
    crud.audit(db, org_id, membership.user_id, "workspace-delete", f"ws {ws_id}")
    db.commit()
    return {"deleted": ws_id}

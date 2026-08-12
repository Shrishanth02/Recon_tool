"""Organization, membership, and API-key routes.

Role gating (via :func:`deps.require_role`):

* read (list/get) — ``viewer+``
* member & API-key management — ``admin+``

All ``/orgs/{org_id}/...`` routes are tenant-scoped: the path ``org_id`` is
validated against the caller's memberships before anything runs.
"""

from fastapi import APIRouter, Depends, HTTPException, Path, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import billing, crud, models, schemas, security
from ..deps import get_current_user, get_db, require_role

router = APIRouter(tags=["orgs"])


# --------------------------------------------------------------------------- #
# Organizations
# --------------------------------------------------------------------------- #
@router.get("/orgs", response_model=list[schemas.OrgOut])
def list_orgs(
    user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List every organization the current user belongs to."""
    return [schemas.OrgOut.model_validate(o) for o in crud.list_user_orgs(db, user)]


@router.post("/orgs", response_model=schemas.OrgOut, status_code=201)
def create_org(
    payload: schemas.OrgIn,
    user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Create a new organization (the caller becomes its owner)."""
    org = crud.create_org(db, user, payload.name)
    crud.audit(db, org.id, user.id, "org-create", org.slug)
    db.commit()
    return schemas.OrgOut.model_validate(org)


@router.get("/orgs/{org_id}", response_model=schemas.OrgOut)
def get_org(
    org_id: int = Path(...),
    membership: models.Membership = Depends(require_role("viewer")),
    db: Session = Depends(get_db),
):
    """Fetch a single organization the caller can see."""
    org = crud.get_org(db, org_id)
    if not org:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Organization not found")
    return schemas.OrgOut.model_validate(org)


# --------------------------------------------------------------------------- #
# Members
# --------------------------------------------------------------------------- #
def _member_out(db: Session, m: models.Membership) -> schemas.MemberOut:
    user = crud.get_user(db, m.user_id)
    return schemas.MemberOut(
        id=m.id,
        user_id=m.user_id,
        org_id=m.org_id,
        role=m.role,
        email=user.email if user else "",
        full_name=user.full_name if user else "",
        created_at=m.created_at,
    )


def _list_memberships(db: Session, org_id: int) -> list[models.Membership]:
    rows = db.scalars(
        select(models.Membership)
        .where(models.Membership.org_id == org_id)
        .order_by(models.Membership.id)
    ).all()
    return list(rows)


def _count_owners(db: Session, org_id: int) -> int:
    return sum(1 for m in _list_memberships(db, org_id) if m.role == "owner")


@router.get("/orgs/{org_id}/members", response_model=list[schemas.MemberOut])
def list_members(
    org_id: int = Path(...),
    membership: models.Membership = Depends(require_role("viewer")),
    db: Session = Depends(get_db),
):
    """List the members of an organization."""
    return [_member_out(db, m) for m in _list_memberships(db, org_id)]


@router.post("/orgs/{org_id}/members", response_model=schemas.MemberOut, status_code=201)
def add_member(
    payload: schemas.MemberIn,
    org_id: int = Path(...),
    membership: models.Membership = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    """Add an *existing* user to the organization by email, with a role."""
    target = crud.get_user_by_email(db, payload.email)
    if not target:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            "No user with that email; they must register first",
        )
    if crud.get_membership(db, target.id, org_id):
        raise HTTPException(status.HTTP_409_CONFLICT, "Already a member")

    # --- Billing quota gate (Phase 3) --------------------------------------- #
    # No-op unless settings.billing_enabled; over the plan's seat limit -> 402.
    org = crud.get_org(db, org_id)
    allowed, reason = billing.check_quota(db, org, "seat")
    if not allowed:
        crud.audit(db, org_id, membership.user_id, "quota-denied", f"seat: {reason}")
        db.commit()
        raise HTTPException(status.HTTP_402_PAYMENT_REQUIRED, reason)

    new_member = models.Membership(user_id=target.id, org_id=org_id, role=payload.role)
    db.add(new_member)
    db.flush()
    crud.audit(
        db, org_id, membership.user_id,
        "member-add", f"{target.email} as {payload.role}",
    )
    db.commit()
    return _member_out(db, new_member)


@router.patch("/orgs/{org_id}/members/{user_id}", response_model=schemas.MemberOut)
def update_member_role(
    payload: schemas.MemberRoleIn,
    org_id: int = Path(...),
    user_id: int = Path(...),
    membership: models.Membership = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    """Change a member's role. The final owner cannot be demoted."""
    target = crud.get_membership(db, user_id, org_id)
    if not target:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Membership not found")
    if target.role == "owner" and payload.role != "owner" and _count_owners(db, org_id) <= 1:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Cannot demote the last owner")

    target.role = payload.role
    db.add(target)
    crud.audit(
        db, org_id, membership.user_id,
        "member-role", f"user {user_id} -> {payload.role}",
    )
    db.commit()
    return _member_out(db, target)


@router.delete("/orgs/{org_id}/members/{user_id}")
def remove_member(
    org_id: int = Path(...),
    user_id: int = Path(...),
    membership: models.Membership = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    """Remove a member. The final owner cannot be removed."""
    target = crud.get_membership(db, user_id, org_id)
    if not target:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Membership not found")
    if target.role == "owner" and _count_owners(db, org_id) <= 1:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Cannot remove the last owner")

    db.delete(target)
    crud.audit(db, org_id, membership.user_id, "member-remove", f"user {user_id}")
    db.commit()
    return {"removed": user_id}


# --------------------------------------------------------------------------- #
# API keys
# --------------------------------------------------------------------------- #
@router.get("/orgs/{org_id}/apikeys", response_model=list[schemas.ApiKeyOut])
def list_apikeys(
    org_id: int = Path(...),
    membership: models.Membership = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    """List an organization's API keys (never exposes the secret)."""
    return [schemas.ApiKeyOut.model_validate(k) for k in crud.list_api_keys(db, org_id)]


@router.post("/orgs/{org_id}/apikeys", response_model=schemas.ApiKeyOut, status_code=201)
def create_apikey(
    payload: schemas.ApiKeyIn,
    org_id: int = Path(...),
    membership: models.Membership = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    """Mint a new API key. The full ``rcx_...`` value is returned **once**."""
    row, full_key = crud.create_api_key(db, org_id, payload.name, membership.user_id)
    crud.audit(db, org_id, membership.user_id, "apikey-create", f"{payload.name} ({row.prefix})")
    db.commit()
    out = schemas.ApiKeyOut.model_validate(row)
    out.key = full_key  # shown exactly once, never persisted
    return out


@router.delete("/orgs/{org_id}/apikeys/{key_id}")
def revoke_apikey(
    org_id: int = Path(...),
    key_id: int = Path(...),
    membership: models.Membership = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    """Revoke an API key (soft-delete: the row is kept for audit)."""
    key = db.get(models.ApiKey, key_id)
    if not key or key.org_id != org_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "API key not found")
    key.revoked = True
    db.add(key)
    crud.audit(db, org_id, membership.user_id, "apikey-revoke", f"{key.name} ({key.prefix})")
    db.commit()
    return {"revoked": key_id}

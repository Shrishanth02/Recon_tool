"""Enterprise / compliance routes: audit log, GDPR export, white-label branding,
and global session revocation.

Role gating (via :func:`app.deps.require_role`):

* audit log, data export, branding **write** — ``admin+``
* branding **read** — ``viewer+`` (any member may see how their reports look)

``POST /auth/logout-all`` is self-service (any authenticated user): it bumps the
caller's ``token_version`` so every previously-issued *versioned* token is
revoked, then returns a fresh access/refresh pair carrying the **new** version so
the caller stays logged in on this device. Tokens minted before Phase 5 (which
carry no ``"ver"`` claim) are intentionally unaffected — see
:func:`app.deps.get_current_user`.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Path, status
from sqlalchemy.orm import Session

from .. import crud, models, schemas, security
from ..deps import get_current_user, get_db, require_role

router = APIRouter(tags=["enterprise"])


# --------------------------------------------------------------------------- #
# Audit log (admin+)
# --------------------------------------------------------------------------- #
@router.get("/orgs/{org_id}/audit", response_model=list[schemas.AuditEntryOut])
def list_audit(
    org_id: int = Path(...),
    limit: int = 200,
    membership: models.Membership = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    """Return the org's most recent audit-log entries (newest first)."""
    limit = max(1, min(int(limit), 1000))
    return [
        schemas.AuditEntryOut.model_validate(row)
        for row in crud.list_audit(db, org_id, limit=limit)
    ]


# --------------------------------------------------------------------------- #
# GDPR-style data export (admin+)
# --------------------------------------------------------------------------- #
@router.get("/orgs/{org_id}/export", response_model=schemas.OrgExportOut)
def export_org(
    org_id: int = Path(...),
    membership: models.Membership = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    """Produce a full, JSON-serializable export of the org's data."""
    data = crud.export_org_data(db, org_id)
    if not data:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Organization not found")
    crud.audit(db, org_id, membership.user_id, "data-export", f"org {org_id}")
    db.commit()
    return schemas.OrgExportOut(**data)


# --------------------------------------------------------------------------- #
# White-label branding
# --------------------------------------------------------------------------- #
@router.get("/orgs/{org_id}/branding", response_model=schemas.BrandingOut)
def get_branding(
    org_id: int = Path(...),
    membership: models.Membership = Depends(require_role("viewer")),
    db: Session = Depends(get_db),
):
    """Return the org's current white-label branding (any member may read)."""
    org = crud.get_org(db, org_id)
    if not org:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Organization not found")
    return schemas.BrandingOut.model_validate(org)


@router.put("/orgs/{org_id}/branding", response_model=schemas.BrandingOut)
def set_branding(
    payload: schemas.BrandingIn,
    org_id: int = Path(...),
    membership: models.Membership = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    """Update the org's white-label branding (admin+).

    ``None`` fields are left unchanged; an empty string clears a field (falling
    back to the RECON-X default in generated reports).
    """
    org = crud.set_org_branding(db, org_id, **payload.model_dump())
    if not org:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Organization not found")
    crud.audit(db, org_id, membership.user_id, "branding", "updated")
    db.commit()
    return schemas.BrandingOut.model_validate(org)


# --------------------------------------------------------------------------- #
# Global session revocation (self-service)
# --------------------------------------------------------------------------- #
def _primary_org(db: Session, user: models.User) -> models.Organization | None:
    orgs = crud.list_user_orgs(db, user)
    return orgs[0] if orgs else None


@router.post("/auth/logout-all", response_model=schemas.TokenOut)
def logout_all(
    user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Revoke every versioned session for the caller and re-issue fresh tokens.

    Bumps ``token_version`` (invalidating any outstanding token that carries a
    ``"ver"`` claim) and returns a new access/refresh pair stamped with the new
    version so this device stays authenticated.
    """
    new_version = crud.bump_token_version(db, user)
    org = _primary_org(db, user)
    org_id = org.id if org else None
    crud.audit(db, org_id, user.id, "logout-all", f"token_version -> {new_version}")
    db.commit()
    return schemas.TokenOut(
        access_token=security.create_access_token(
            user.id, org_id=org_id, token_version=new_version
        ),
        refresh_token=security.create_refresh_token(
            user.id, org_id=org_id, token_version=new_version
        ),
    )

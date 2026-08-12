"""Authentication & account routes.

Covers registration (which bootstraps an org + default workspace), login with
optional TOTP MFA, refresh-token rotation, the ``/auth/me`` self endpoint, and
TOTP enrollment/verification.

Both ``/auth/register`` and ``/auth/login`` return the full :class:`RegisterOut`
payload — ``{access_token, refresh_token, token_type, user, org, workspace}`` —
so the front-end has everything it needs to render the dashboard immediately.
``/auth/refresh`` returns a bare :class:`TokenOut`.
"""

import jwt
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from .. import crud, models, schemas, security
from ..deps import get_current_user, get_db

router = APIRouter(tags=["auth"])


def _primary_org(db: Session, user: models.User) -> models.Organization | None:
    """Return the user's oldest organization (their "home" tenant), if any."""
    orgs = crud.list_user_orgs(db, user)
    return orgs[0] if orgs else None


def _build_register_out(
    db: Session,
    user: models.User,
    org: models.Organization,
    workspace: models.Workspace,
) -> schemas.RegisterOut:
    """Assemble the token + user/org/workspace convenience payload."""
    # Stamp the user's current token_version so "sign out everywhere"
    # (logout-all bumps token_version) can actually revoke these sessions.
    ver = user.token_version
    access = security.create_access_token(user.id, org_id=org.id, token_version=ver)
    refresh = security.create_refresh_token(user.id, org_id=org.id, token_version=ver)
    ws_summary = crud.workspace_summary(db, workspace)
    return schemas.RegisterOut(
        access_token=access,
        refresh_token=refresh,
        user=schemas.UserOut.model_validate(user),
        org=schemas.OrgOut.model_validate(org),
        workspace=schemas.WorkspaceOut.model_validate(ws_summary),
    )


@router.post("/auth/register", response_model=schemas.RegisterOut, status_code=201)
def register(payload: schemas.RegisterIn, db: Session = Depends(get_db)):
    """Create a user, their first organization, and a default workspace."""
    if crud.get_user_by_email(db, payload.email):
        raise HTTPException(status.HTTP_409_CONFLICT, "Email already registered")

    user, org, workspace = crud.create_user_with_org(
        db,
        email=payload.email,
        password=payload.password,
        full_name=payload.full_name,
        org_name=payload.org_name,
    )
    crud.audit(db, org.id, user.id, "register", f"{user.email} -> org {org.slug}")
    db.commit()
    return _build_register_out(db, user, org, workspace)


@router.post("/auth/login", response_model=schemas.RegisterOut)
def login(payload: schemas.LoginIn, db: Session = Depends(get_db)):
    """Authenticate an email/password pair (plus TOTP when MFA is enabled)."""
    user = crud.authenticate(db, payload.email, payload.password)
    if not user:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid credentials")

    if user.mfa_enabled:
        if not payload.mfa_code or not security.totp_verify(
            user.mfa_secret or "", payload.mfa_code
        ):
            raise HTTPException(
                status.HTTP_401_UNAUTHORIZED, "Valid MFA code required"
            )

    org = _primary_org(db, user)
    if not org:
        raise HTTPException(
            status.HTTP_409_CONFLICT, "Account has no organization; contact support"
        )
    ws_id = crud.default_workspace_id_for_org(db, org.id)
    workspace = crud.get_workspace(db, ws_id) if ws_id else None
    if not workspace:
        workspace = crud.create_workspace(db, org.id, "Default Engagement")

    crud.audit(db, org.id, user.id, "login", user.email)
    db.commit()
    return _build_register_out(db, user, org, workspace)


@router.post("/auth/refresh", response_model=schemas.TokenOut)
def refresh(payload: schemas.RefreshIn, db: Session = Depends(get_db)):
    """Rotate a refresh token into a fresh access/refresh pair."""
    try:
        claims = security.decode_token(payload.refresh_token)
    except jwt.PyJWTError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired token")
    if claims.get("type") != "refresh":
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Not a refresh token")

    user = crud.get_user(db, int(claims.get("sub", 0)))
    if not user or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "User not found or inactive")

    # Reject refresh tokens that predate a "sign out everywhere" (revocation).
    if "ver" in claims and claims["ver"] != user.token_version:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Session revoked")

    org_id = claims.get("org_id")
    ver = user.token_version
    return schemas.TokenOut(
        access_token=security.create_access_token(user.id, org_id=org_id, token_version=ver),
        refresh_token=security.create_refresh_token(user.id, org_id=org_id, token_version=ver),
    )


@router.get("/auth/me", response_model=schemas.MeOut)
def me(
    user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Return the current user with all of their memberships and orgs."""
    memberships = crud.list_user_memberships(db, user)
    orgs = crud.list_user_orgs(db, user)
    return schemas.MeOut(
        user=schemas.UserOut.model_validate(user),
        memberships=[schemas.MembershipOut.model_validate(m) for m in memberships],
        orgs=[schemas.OrgOut.model_validate(o) for o in orgs],
    )


@router.post("/auth/mfa/enroll", response_model=schemas.MfaEnrollOut)
def mfa_enroll(
    user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Generate (and store, unconfirmed) a TOTP secret for the current user.

    MFA is only *enabled* once the user proves possession via
    ``/auth/mfa/verify``. Re-enrolling before verifying simply rolls the secret.
    """
    secret = security.totp_new_secret()
    user.mfa_secret = secret
    user.mfa_enabled = False
    db.add(user)
    crud.audit(db, None, user.id, "mfa-enroll", user.email)
    db.commit()
    return schemas.MfaEnrollOut(
        secret=secret,
        otpauth_uri=security.totp_uri(secret, user.email),
    )


@router.post("/auth/mfa/verify", response_model=schemas.UserOut)
def mfa_verify(
    payload: schemas.MfaVerifyIn,
    user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Confirm the enrolled TOTP secret and switch MFA on for the account."""
    if not user.mfa_secret:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "No MFA enrollment pending")
    if not security.totp_verify(user.mfa_secret, payload.code):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid MFA code")
    user.mfa_enabled = True
    db.add(user)
    crud.audit(db, None, user.id, "mfa-enable", user.email)
    db.commit()
    return schemas.UserOut.model_validate(user)

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
from fastapi import APIRouter, Body, Depends, HTTPException, Request, Response, status
from sqlalchemy.orm import Session

from .. import authcookies, crud, models, schemas, security
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
    """Assemble the token + user/org/workspace convenience payload.

    Issues a fresh refresh-token record (a new rotation family) and embeds its
    jti/family in the refresh JWT so it can be rotated + replay-detected. Flushes
    only — the caller commits.
    """
    # Stamp the user's current token_version so "sign out everywhere"
    # (logout-all bumps token_version) can actually revoke these sessions.
    ver = int(getattr(user, "token_version", 0) or 0)
    rt = crud.issue_refresh_token(db, user.id)
    access = security.create_access_token(user.id, org_id=org.id, token_version=ver)
    refresh = security.create_refresh_token(
        user.id, org_id=org.id, token_version=ver, jti=rt.jti, family=rt.family_id,
    )
    ws_summary = crud.workspace_summary(db, workspace)
    return schemas.RegisterOut(
        access_token=access,
        refresh_token=refresh,
        user=schemas.UserOut.model_validate(user),
        org=schemas.OrgOut.model_validate(org),
        workspace=schemas.WorkspaceOut.model_validate(ws_summary),
    )


@router.post("/auth/register", response_model=schemas.RegisterOut, status_code=201)
def register(payload: schemas.RegisterIn, response: Response, db: Session = Depends(get_db)):
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
    out = _build_register_out(db, user, org, workspace)
    db.commit()
    # STEP 4: also deliver the refresh token as an httpOnly cookie so the SPA
    # never has to persist it in JS-readable storage (the body copy is kept for
    # the test harness + legacy programmatic clients).
    authcookies.set_refresh_cookie(response, out.refresh_token)
    return out


@router.post("/auth/login", response_model=schemas.RegisterOut)
def login(payload: schemas.LoginIn, response: Response, db: Session = Depends(get_db)):
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
    out = _build_register_out(db, user, org, workspace)
    db.commit()
    authcookies.set_refresh_cookie(response, out.refresh_token)  # STEP 4 (see register)
    return out


@router.post("/auth/refresh", response_model=schemas.TokenOut)
def refresh(
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    payload: schemas.RefreshIn | None = Body(default=None),
):
    """Rotate a refresh token into a fresh access/refresh pair.

    The token is taken from the httpOnly ``reconx_refresh`` cookie when present
    (the SPA path — CSRF-guarded by SameSite + an Origin check, and the rotated
    token is returned ONLY in the re-set cookie, never in the body), else from the
    request body (legacy programmatic clients). Rotation + reuse-detection are
    unchanged.
    """
    # Precedence: an explicit body token (legacy/programmatic client) wins; else
    # the httpOnly cookie (the SPA). An XSS cannot read the httpOnly cookie, so it
    # cannot supply a body token — it is forced onto the cookie path, whose
    # response never contains the refresh token.
    cookie_token = authcookies.read_refresh_cookie(request)
    if payload and payload.refresh_token:
        token = payload.refresh_token
        used_cookie = False
    elif cookie_token:
        authcookies.enforce_refresh_origin(request)  # CSRF guard for the cookie path
        token = cookie_token
        used_cookie = True
    else:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing refresh token")

    try:
        claims = security.decode_token(token)
    except jwt.PyJWTError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired token")
    if claims.get("type") != "refresh":
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Not a refresh token")

    user = crud.get_user(db, int(claims.get("sub", 0)))
    if not user or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "User not found or inactive")

    # Fail-closed account-wide revocation: a missing "ver" is treated as 0, so a
    # token that predates a "sign out everywhere" (token_version bump) is rejected.
    if security.is_token_revoked(claims.get("ver"), user.token_version):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Session revoked")

    # Per-session rotation + replay detection. Every refresh token carries a jti;
    # rotate it (consume + mint successor). Replay of a consumed token revokes the
    # whole family (that session lineage) — never the account (no lockout DoS).
    jti = claims.get("jti")
    if not jti:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "Refresh token is not rotatable; please sign in again",
        )
    outcome, successor = crud.rotate_refresh_token(db, jti)
    if outcome == "reuse":
        crud.audit(db, claims.get("org_id"), user.id, "refresh-reuse",
                   "replay of a consumed refresh token; session family revoked")
        db.commit()
        authcookies.clear_refresh_cookie(response)  # the session family is dead
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, "Refresh token reuse detected; session revoked"
        )
    if outcome != "ok" or successor is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired refresh token")

    org_id = claims.get("org_id")
    ver = int(getattr(user, "token_version", 0) or 0)
    new_access = security.create_access_token(user.id, org_id=org_id, token_version=ver)
    new_refresh = security.create_refresh_token(
        user.id, org_id=org_id, token_version=ver,
        jti=successor.jti, family=successor.family_id,
    )
    db.commit()
    if used_cookie:
        # Rotated refresh goes ONLY into the cookie — never the body — so an XSS
        # that calls /auth/refresh cannot read it.
        authcookies.set_refresh_cookie(response, new_refresh)
        return schemas.TokenOut(access_token=new_access)
    return schemas.TokenOut(access_token=new_access, refresh_token=new_refresh)


@router.post("/auth/logout", status_code=204)
def logout(request: Request, response: Response, db: Session = Depends(get_db)):
    """Single-device sign-out: clear the refresh cookie and kill its session.

    Best-effort revokes the presented refresh token's rotation family (so the
    session cannot be resumed with the lingering cookie), then clears the cookie.
    Always 204 and never raises — logging out must never fail. Unlike
    ``/auth/logout-all`` it does NOT bump ``token_version``, so the user's OTHER
    devices stay signed in.
    """
    token = authcookies.read_refresh_cookie(request)
    if token:
        try:
            claims = security.decode_token(token)
            jti = claims.get("jti")
            if jti:
                rec = (
                    db.query(models.RefreshToken)
                    .filter(models.RefreshToken.jti == jti)
                    .one_or_none()
                )
                if rec is not None:
                    crud.revoke_refresh_family(db, rec.family_id)
                    db.commit()
        except Exception:  # noqa: BLE001 - logout is idempotent + must never error
            db.rollback()
    # Clear on the INJECTED response (returning a new Response would drop the
    # Set-Cookie); the route's status_code=204 gives an empty body.
    authcookies.clear_refresh_cookie(response)


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

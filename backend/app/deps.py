"""FastAPI dependencies for authentication and tenant enforcement.

The dependency graph is intentionally shallow:

* ``get_current_user``     — Bearer JWT -> User (401 on failure)
* ``get_principal``        — Bearer JWT *or* X-API-Key -> Principal
* ``require_org_member``   — path org must be one the caller belongs to (403)
* ``require_role(min)``    — capability gate over the caller's role in the org
* ``get_workspace_for_user`` — workspace must belong to a visible org (404/403)
"""

from dataclasses import dataclass

import jwt
from fastapi import Depends, Header, HTTPException, Path, status
from sqlalchemy.orm import Session

from . import crud, models, security
from .database import get_db  # re-exported for routers

__all__ = [
    "get_db",
    "get_current_user",
    "get_principal",
    "require_org_member",
    "require_role",
    "get_workspace_for_user",
    "Principal",
]


@dataclass
class Principal:
    """A resolved caller: either a human user or an API-key service principal.

    Exactly one of ``user`` / ``api_key`` is set. ``org_id`` is the tenant the
    call operates within (always present for API keys, optional for users until
    they select an org via the path).
    """

    user: models.User | None = None
    api_key: models.ApiKey | None = None
    org_id: int | None = None

    @property
    def is_api_key(self) -> bool:
        return self.api_key is not None

    @property
    def user_id(self) -> int | None:
        return self.user.id if self.user else None


def _bearer_token(authorization: str | None) -> str | None:
    if not authorization:
        return None
    parts = authorization.split(" ", 1)
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1].strip()
    return None


def get_current_user(
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db),
) -> models.User:
    """Resolve a User from an ``Authorization: Bearer <access>`` header."""
    token = _bearer_token(authorization)
    if not token:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, "Missing bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        payload = security.decode_token(token)
    except jwt.PyJWTError:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, "Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if payload.get("type") != "access":
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Wrong token type")
    user = crud.get_user(db, int(payload.get("sub", 0)))
    if not user or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "User not found or inactive")
    # Session revocation (fail-CLOSED): a token's "ver" (missing => 0) must equal
    # the user's current token_version. A "sign out everywhere" bumps
    # token_version, so any earlier token — versioned OR ver-less — is rejected.
    if security.is_token_revoked(payload.get("ver"), user.token_version):
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "session revoked",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


def get_principal(
    authorization: str | None = Header(default=None),
    x_api_key: str | None = Header(default=None),
    db: Session = Depends(get_db),
) -> Principal:
    """Accept either a Bearer JWT or an ``X-API-Key`` header.

    An API key resolves to an org-scoped service principal (no user).
    """
    if x_api_key:
        api_key = crud.resolve_api_key(db, x_api_key.strip())
        if not api_key:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid API key")
        return Principal(api_key=api_key, org_id=api_key.org_id)

    token = _bearer_token(authorization)
    if not token:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, "Missing credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        payload = security.decode_token(token)
    except jwt.PyJWTError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired token")
    if payload.get("type") != "access":
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Wrong token type")
    user = crud.get_user(db, int(payload.get("sub", 0)))
    if not user or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "User not found or inactive")
    # Same fail-closed revocation check as get_current_user (this path was missing it).
    if security.is_token_revoked(payload.get("ver"), user.token_version):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "session revoked")
    return Principal(user=user, org_id=payload.get("org_id"))


def require_org_member(
    org_id: int = Path(...),
    user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> models.Membership:
    """Ensure the current user is a member of ``org_id`` (403 otherwise)."""
    membership = crud.get_membership(db, user.id, org_id)
    if not membership:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Not a member of this organization")
    return membership


def require_role(min_role: str):
    """Dependency factory: require at least ``min_role`` within the path org.

    Usage::

        @router.post("/orgs/{org_id}/members")
        def add_member(membership = Depends(require_role("admin"))): ...
    """
    min_rank = security.ROLE_RANK[min_role]

    def _dep(
        membership: models.Membership = Depends(require_org_member),
    ) -> models.Membership:
        if security.ROLE_RANK.get(membership.role, -1) < min_rank:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                f"Requires role '{min_role}' or higher",
            )
        return membership

    return _dep


def get_workspace_for_user(
    ws_id: int = Path(...),
    user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> tuple[models.Workspace, models.Membership]:
    """Load a workspace and the caller's membership in its owning org.

    404 if the workspace is not visible to the caller (either it doesn't exist
    or the caller isn't a member of its org — the two are deliberately
    indistinguishable to avoid leaking existence). Role checks for the specific
    operation are the caller's responsibility via ``membership.role``.
    """
    ws = crud.get_workspace(db, ws_id)
    if not ws:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Workspace not found")
    membership = crud.get_membership(db, user.id, ws.org_id)
    if not membership:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Workspace not found")
    return ws, membership

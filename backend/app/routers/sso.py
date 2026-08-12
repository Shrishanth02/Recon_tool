"""Single sign-on (SSO) routes: browser login flow + admin configuration.

Two surfaces live here:

* **Login flow** (``/auth/sso/{org_slug}/...``) — the provider-agnostic OIDC /
  SAML entry points. Every route is double-gated: the global
  :attr:`app.config.Settings.SSO_ENABLED` master switch AND a per-org
  :class:`~app.models.SsoConfig` row whose ``enabled`` flag is set. When either
  is off the endpoints 404 (existence-hiding), so turning SSO off makes the whole
  surface disappear.
* **Admin config** (``/orgs/{org_id}/sso``) — admin+ read/write of the org's SSO
  settings. :class:`~app.schemas.SsoConfigOut` masks the stored secrets
  (``client_secret`` / ``x509_cert``), exposing only ``*_set`` booleans.

Token issuance after a successful SSO login reuses the standard RECON-X token
flow, but always mints the pair **with the user's current** ``token_version`` so
that a later ``/auth/logout-all`` (which bumps the version) revokes SSO-issued
sessions too.
"""

from __future__ import annotations

import secrets

from fastapi import APIRouter, Depends, HTTPException, Path, Query, status
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from .. import crud, models, schemas, security, sso
from ..config import settings
from ..deps import get_db, require_role

router = APIRouter(tags=["sso"])


class SamlAcsIn(BaseModel):
    """Input for the SAML Assertion Consumer Service endpoint.

    ``saml_response`` is the base64-encoded SAML ``Response`` posted by the IdP.
    Accepts the standard ``SAMLResponse`` field name as an alias so an IdP form
    POST maps straight onto it.
    """

    saml_response: str = Field(..., alias="SAMLResponse")

    model_config = {"populate_by_name": True}


# --------------------------------------------------------------------------- #
# Gating helpers
# --------------------------------------------------------------------------- #
def _resolve_sso(db: Session, org_slug: str) -> tuple[models.Organization, models.SsoConfig]:
    """Resolve an org + its *enabled* SSO config, or 404.

    Enforces the two-level gate: the global ``SSO_ENABLED`` switch and the org's
    own ``SsoConfig.enabled`` flag. Any miss is reported as 404 so an outsider
    cannot probe which orgs have SSO configured.
    """
    if not settings.sso_enabled:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "SSO is not enabled")
    org = crud.get_org_by_slug(db, org_slug)
    if not org:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "SSO is not available")
    cfg = crud.get_sso_config(db, org.id)
    if not cfg or not cfg.enabled:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "SSO is not available")
    return org, cfg


def _issue_login(db: Session, user: models.User, org: models.Organization) -> schemas.RegisterOut:
    """Mint the standard RegisterOut payload for an SSO-authenticated user.

    Tokens carry the user's current ``token_version`` so revocation via
    ``/auth/logout-all`` invalidates them. A default workspace is created on the
    fly if the org has none (mirrors the password-login path).
    """
    ver = int(getattr(user, "token_version", 0) or 0)
    access = security.create_access_token(user.id, org_id=org.id, token_version=ver)
    refresh = security.create_refresh_token(user.id, org_id=org.id, token_version=ver)

    ws_id = crud.default_workspace_id_for_org(db, org.id)
    workspace = crud.get_workspace(db, ws_id) if ws_id else None
    if not workspace:
        workspace = crud.create_workspace(db, org.id, "Default Engagement")
    ws_summary = crud.workspace_summary(db, workspace)

    return schemas.RegisterOut(
        access_token=access,
        refresh_token=refresh,
        user=schemas.UserOut.model_validate(user),
        org=schemas.OrgOut.model_validate(org),
        workspace=schemas.WorkspaceOut.model_validate(ws_summary),
    )


def _saml_sso_url(cfg: models.SsoConfig) -> str | None:
    """Best-effort extraction of an IdP SingleSignOnService URL from metadata.

    The SAML support is a scaffold; when the stored metadata XML contains a
    ``SingleSignOnService`` binding we can redirect (SP-initiated). Otherwise the
    caller should use IdP-initiated login (POST to the ACS endpoint).
    """
    metadata = getattr(cfg, "saml_metadata", None)
    if not metadata:
        return None
    import xml.etree.ElementTree as ET

    try:
        root = ET.fromstring(metadata)
    except Exception:
        return None
    for elem in root.iter():
        if elem.tag.rsplit("}", 1)[-1] == "SingleSignOnService":
            location = elem.get("Location")
            if location:
                return location
    return None


# --------------------------------------------------------------------------- #
# Login flow
# --------------------------------------------------------------------------- #
@router.get("/auth/sso/{org_slug}/login")
def sso_login(
    org_slug: str = Path(...),
    db: Session = Depends(get_db),
):
    """Begin an SSO login, redirecting the browser to the identity provider.

    * **OIDC** — builds the authorization URL (via :func:`app.sso.build_auth_url`)
      and 302s to it. ``state`` encodes the org slug so the fixed
      ``/auth/sso/callback`` redirect URI can recover the tenant; ``nonce`` is a
      replay guard. (State/nonce should be persisted in a production deployment;
      here they are opaque round-trip values.)
    * **SAML** — 302s to the IdP's SingleSignOnService when the stored metadata
      advertises one, else 400 directing the caller to IdP-initiated login.
    """
    org, cfg = _resolve_sso(db, org_slug)
    provider = (cfg.provider or "oidc").strip().lower()

    if provider == "oidc":
        state = f"{org.slug}:{secrets.token_urlsafe(16)}"
        nonce = secrets.token_urlsafe(16)
        try:
            url = sso.build_auth_url(cfg, state=state, nonce=nonce)
        except sso.SsoError as exc:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc))
        return RedirectResponse(url, status_code=status.HTTP_302_FOUND)

    if provider == "saml":
        url = _saml_sso_url(cfg)
        if not url:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                "SAML SP-initiated login is unavailable; use IdP-initiated login "
                "by POSTing the assertion to the ACS endpoint",
            )
        return RedirectResponse(url, status_code=status.HTTP_302_FOUND)

    raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Unsupported SSO provider: {provider}")


def _oidc_callback(db: Session, org: models.Organization, cfg: models.SsoConfig, code: str) -> schemas.RegisterOut:
    """Shared OIDC callback logic: code -> tokens -> userinfo -> provision."""
    if not code:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Missing authorization code")
    try:
        tokens = sso.exchange_code(cfg, code)
        info = sso.fetch_userinfo(cfg, tokens)
    except sso.SsoError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc))
    try:
        user = sso.provision_sso_user(db, org, info["email"], info.get("name", ""))
    except sso.SsoError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc))
    out = _issue_login(db, user, org)
    db.commit()
    return out


@router.get("/auth/sso/{org_slug}/callback", response_model=schemas.RegisterOut)
def sso_callback(
    org_slug: str = Path(...),
    code: str = Query(""),
    state: str = Query(""),
    db: Session = Depends(get_db),
):
    """OIDC redirect handler (slug in the path): validate, provision, issue tokens."""
    org, cfg = _resolve_sso(db, org_slug)
    if (cfg.provider or "oidc").strip().lower() != "oidc":
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Callback is only valid for OIDC")
    return _oidc_callback(db, org, cfg, code)


@router.get("/auth/sso/callback", response_model=schemas.RegisterOut)
def sso_callback_compat(
    code: str = Query(""),
    state: str = Query(""),
    db: Session = Depends(get_db),
):
    """OIDC redirect handler matching :func:`app.sso.redirect_uri`.

    The provider is configured with the fixed ``/auth/sso/callback`` redirect URI
    (no slug), so the tenant is recovered from the ``org_slug:...`` prefix of the
    ``state`` value produced by :func:`sso_login`.
    """
    org_slug = (state or "").split(":", 1)[0]
    if not org_slug:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Missing or malformed state")
    org, cfg = _resolve_sso(db, org_slug)
    if (cfg.provider or "oidc").strip().lower() != "oidc":
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Callback is only valid for OIDC")
    return _oidc_callback(db, org, cfg, code)


@router.post("/auth/sso/{org_slug}/acs", response_model=schemas.RegisterOut)
def sso_acs(
    payload: SamlAcsIn,
    org_slug: str = Path(...),
    db: Session = Depends(get_db),
):
    """SAML Assertion Consumer Service: validate the assertion and issue tokens.

    Accepts the base64 ``SAMLResponse``, parses out the identity via
    :func:`app.sso.parse_saml_response` (which refuses to trust a signed
    assertion without ``python3-saml`` when a certificate is configured), JIT
    provisions the user, and returns the standard token payload.
    """
    org, cfg = _resolve_sso(db, org_slug)
    if (cfg.provider or "oidc").strip().lower() != "saml":
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "ACS is only valid for SAML")
    try:
        identity = sso.parse_saml_response(cfg, payload.saml_response)
        user = sso.provision_sso_user(db, org, identity["email"], identity.get("name", ""))
    except sso.SsoError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc))
    out = _issue_login(db, user, org)
    db.commit()
    return out


# --------------------------------------------------------------------------- #
# Admin configuration (admin+)
# --------------------------------------------------------------------------- #
@router.get("/orgs/{org_id}/sso", response_model=schemas.SsoConfigOut)
def get_sso_config(
    org_id: int = Path(...),
    membership: models.Membership = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    """Return the org's SSO configuration (secrets masked). 404 when unset."""
    cfg = crud.get_sso_config(db, org_id)
    if not cfg:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "SSO is not configured")
    return schemas.SsoConfigOut.from_config(cfg)


@router.put("/orgs/{org_id}/sso", response_model=schemas.SsoConfigOut)
def put_sso_config(
    payload: schemas.SsoConfigIn,
    org_id: int = Path(...),
    membership: models.Membership = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    """Create or update the org's SSO configuration (admin+)."""
    cfg = crud.upsert_sso_config(db, org_id, **payload.model_dump())
    crud.audit(
        db, org_id, membership.user_id,
        "sso-config", f"provider={cfg.provider} enabled={cfg.enabled}",
    )
    db.commit()
    return schemas.SsoConfigOut.from_config(cfg)

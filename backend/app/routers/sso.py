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

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request, Response, status
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
    rt = crud.issue_refresh_token(db, user.id)  # new rotation family; caller commits
    access = security.create_access_token(user.id, org_id=org.id, token_version=ver)
    refresh = security.create_refresh_token(
        user.id, org_id=org.id, token_version=ver, jti=rt.jti, family=rt.family_id,
    )

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
# OIDC state (CSRF + replay) — browser-binding cookie helpers
# --------------------------------------------------------------------------- #
#: httpOnly cookie carrying the OIDC ``state`` id back to the callback. It binds
#: the round-trip to the browser that began the login: the callback requires the
#: cookie to match the ``state`` query parameter, so a forged callback replayed in
#: a victim's browser (login-CSRF) — which has no matching cookie — is rejected.
_OIDC_STATE_COOKIE = "reconx_oidc_state"
#: The cookie (and every OIDC callback) lives under this path, so it is scoped to
#: the SSO surface and never sent with ordinary API calls.
_OIDC_COOKIE_PATH = "/auth/sso"


def _set_state_cookie(resp: Response, state_id: str) -> None:
    """Set the browser-binding OIDC state cookie on ``resp`` (the login redirect).

    ``SameSite=Lax`` so it rides the provider's top-level GET redirect back to the
    callback; ``Secure`` in production (relaxed only under DEBUG for local http);
    ``httpOnly`` so page scripts cannot read it; ``max_age`` matches the state TTL.
    """
    resp.set_cookie(
        _OIDC_STATE_COOKIE,
        state_id,
        max_age=int(settings.SSO_STATE_TTL_SECONDS),
        httponly=True,
        samesite="lax",
        secure=not settings.DEBUG,
        path=_OIDC_COOKIE_PATH,
    )


def _clear_state_cookie(resp: Response) -> None:
    """Delete the OIDC state cookie once the callback has consumed the state."""
    resp.delete_cookie(_OIDC_STATE_COOKIE, path=_OIDC_COOKIE_PATH)


def _verify_oidc_state(
    db: Session,
    request: Request,
    state: str,
    *,
    expected_org_id: int | None = None,
) -> models.SsoState:
    """Validate a callback's ``state`` and consume it single-use, or 400.

    Every state invariant is enforced BEFORE any token work happens:

    * **Browser binding** — the request must carry the ``reconx_oidc_state``
      cookie set at ``/login`` and it must equal the ``state`` query parameter
      (constant-time compare). A missing/mismatched cookie means the callback did
      not originate in the browser that began the login (login-CSRF) — reject.
      This also rejects a missing/empty ``state``.
    * **Existence / expiry / single use / tenant** — delegated to
      :func:`app.crud.consume_sso_state`, which atomically claims the row only if
      it exists, is unexpired, is unused, and (when ``expected_org_id`` is given)
      belongs to the callback's org. A replay of an already-consumed state, an
      expired state, a tampered/unknown state, or a state minted for another org
      all return ``invalid``.

    On success the row is durably consumed (committed) before returning, so token
    work that fails afterwards can never leave the state reusable. Returns the
    consumed record (carrying the bound org + nonce). Raises 400 on any failure,
    so tokens are NEVER issued for an invalid/replayed/tampered/foreign state.
    """
    cookie_state = request.cookies.get(_OIDC_STATE_COOKIE) or ""
    if not state or not cookie_state or not secrets.compare_digest(cookie_state, state):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid SSO state")
    result, rec = crud.consume_sso_state(db, state, expected_org_id=expected_org_id)
    if result != "ok" or rec is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid SSO state")
    db.commit()  # lock in single-use consumption BEFORE any token work
    return rec


# --------------------------------------------------------------------------- #
# Login flow
# --------------------------------------------------------------------------- #
@router.get("/auth/sso/{org_slug}/login")
def sso_login(
    org_slug: str = Path(...),
    db: Session = Depends(get_db),
):
    """Begin an SSO login, redirecting the browser to the identity provider.

    * **OIDC** — mints a single-use :class:`~app.models.SsoState` row (unguessable
      ``state`` id + ``nonce``, bound to this org, short-lived) and 302s to the
      authorization URL. The ``state`` id is ALSO set as an httpOnly cookie, so the
      callback can prove the round-trip returned to the same browser. The org is
      carried by the server-side record, never by the ``state`` string, so a
      forged ``state`` cannot select a tenant. ``nonce`` is later matched against
      the provider's id_token.
    * **SAML** — 302s to the IdP's SingleSignOnService when the stored metadata
      advertises one, else 400 directing the caller to IdP-initiated login.
    """
    org, cfg = _resolve_sso(db, org_slug)
    provider = (cfg.provider or "oidc").strip().lower()

    if provider == "oidc":
        rec = crud.create_sso_state(db, org.id)  # flushed, not yet committed
        try:
            url = sso.build_auth_url(cfg, state=rec.state_id, nonce=rec.nonce)
        except sso.SsoError as exc:
            db.rollback()  # discard the unused state row on a config error
            raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc))
        db.commit()
        resp = RedirectResponse(url, status_code=status.HTTP_302_FOUND)
        _set_state_cookie(resp, rec.state_id)
        return resp

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


def _oidc_callback(
    db: Session,
    org: models.Organization,
    cfg: models.SsoConfig,
    code: str,
    *,
    nonce: str,
) -> schemas.RegisterOut:
    """Shared OIDC callback logic: code -> tokens -> nonce-check -> userinfo -> provision.

    ``nonce`` is the value bound to the (already-consumed) state record; the
    provider's id_token must echo it, or the exchange is rejected before any user
    is provisioned or any token issued.
    """
    if not code:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Missing authorization code")
    try:
        tokens = sso.exchange_code(cfg, code)
        sso.verify_id_token_nonce(tokens, nonce)  # id_token replay guard
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
    request: Request,
    response: Response,
    org_slug: str = Path(...),
    code: str = Query(""),
    state: str = Query(""),
    db: Session = Depends(get_db),
):
    """OIDC redirect handler (slug in the path): validate state, provision, issue tokens.

    The ``state`` must match the browser cookie AND be a live, unused record bound
    to THIS org (``expected_org_id=org.id``) — so a state minted for another tenant
    cannot authenticate here.
    """
    org, cfg = _resolve_sso(db, org_slug)
    if (cfg.provider or "oidc").strip().lower() != "oidc":
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Callback is only valid for OIDC")
    rec = _verify_oidc_state(db, request, state, expected_org_id=org.id)
    _clear_state_cookie(response)
    return _oidc_callback(db, org, cfg, code, nonce=rec.nonce)


@router.get("/auth/sso/callback", response_model=schemas.RegisterOut)
def sso_callback_compat(
    request: Request,
    response: Response,
    code: str = Query(""),
    state: str = Query(""),
    db: Session = Depends(get_db),
):
    """OIDC redirect handler matching :func:`app.sso.redirect_uri` (no slug in path).

    The tenant is recovered from the single-use ``state`` *record* (its bound
    ``org_id``), NEVER from the ``state`` string, so a forged/tampered state cannot
    select an org. The state is browser-bound + consumed by
    :func:`_verify_oidc_state` before the org is resolved.
    """
    rec = _verify_oidc_state(db, request, state, expected_org_id=None)
    org = crud.get_org(db, rec.org_id)
    if not org:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid SSO state")
    _, cfg = _resolve_sso(db, org.slug)  # re-assert the SSO gate for the bound org
    if (cfg.provider or "oidc").strip().lower() != "oidc":
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Callback is only valid for OIDC")
    _clear_state_cookie(response)
    return _oidc_callback(db, org, cfg, code, nonce=rec.nonce)


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
    """Create or update the org's SSO configuration (admin+).

    ``exclude_unset`` so a partial update (e.g. just ``{"enabled": true}``) never
    clobbers unspecified fields with their schema defaults. A SAML config may not
    be enabled without a signing certificate — an unsigned SAML assertion is
    attacker-forgeable, so we refuse the config at write time (fail-closed).
    """
    cfg = crud.upsert_sso_config(db, org_id, **payload.model_dump(exclude_unset=True))
    if (cfg.provider or "").strip().lower() == "saml" and cfg.enabled and not (
        (cfg.x509_cert or "").strip()
    ):
        db.rollback()
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "SAML SSO cannot be enabled without a signing certificate (x509_cert).",
        )
    crud.audit(
        db, org_id, membership.user_id,
        "sso-config", f"provider={cfg.provider} enabled={cfg.enabled}",
    )
    db.commit()
    return schemas.SsoConfigOut.from_config(cfg)

"""Provider-agnostic single sign-on (SSO) framework for the Phase 5 core.

Two protocols are supported at different levels of maturity:

* **OIDC** — fully implemented on top of the already-present ``requests``
  library (imported lazily inside each function so ``import app.sso`` never
  touches the network or requires ``requests`` at import time). Covers
  discovery, the authorization-URL builder, the code→token exchange, and the
  userinfo fetch.
* **SAML** — a clearly-labelled scaffold. :func:`parse_saml_response` decodes a
  base64 SAML ``Response`` and extracts the NameID / attribute values, but
  production-grade signature validation requires ``python3-saml`` (which pulls
  in ``xmlsec``). That validation is gated behind a try/except and a config
  flag, and an assertion is **never** trusted unsigned when a certificate is
  configured.

The testable, network-free core is :func:`provision_sso_user` — the just-in-time
(JIT) user provisioning that maps a verified external identity onto a local
:class:`~app.models.User` and org :class:`~app.models.Membership`.
"""

from __future__ import annotations

import base64
import json
import secrets
from typing import Any

from sqlalchemy.orm import Session

from . import crud, models, security

__all__ = [
    "oidc_discover",
    "build_auth_url",
    "exchange_code",
    "fetch_userinfo",
    "verify_id_token_nonce",
    "parse_saml_response",
    "provision_sso_user",
    "SsoError",
]


class SsoError(RuntimeError):
    """Raised when an SSO operation fails (discovery, exchange, parsing, ...)."""


# --------------------------------------------------------------------------- #
# OIDC (lazy `requests`)
# --------------------------------------------------------------------------- #
# Simple in-process cache of discovery documents keyed by issuer/discovery URL.
_DISCOVERY_CACHE: dict[str, dict[str, Any]] = {}


def _requests():
    """Lazily import and return the ``requests`` module (raises SsoError if absent)."""
    try:
        import requests  # noqa: PLC0415  (intentional lazy import)

        return requests
    except Exception as exc:  # pragma: no cover - requests is a base dep
        raise SsoError("The 'requests' library is required for OIDC SSO") from exc


def _cfg_get(cfg: Any, *names: str, default: Any = None) -> Any:
    """Read the first present attribute/key from ``cfg`` (ORM row or dict)."""
    for name in names:
        if isinstance(cfg, dict):
            if name in cfg and cfg[name] is not None:
                return cfg[name]
        else:
            value = getattr(cfg, name, None)
            if value is not None:
                return value
    return default


def oidc_discover(issuer: str, *, timeout: float = 10.0) -> dict[str, Any]:
    """Fetch (and cache) an OIDC provider's discovery document.

    ``issuer`` may be the bare issuer (the standard
    ``/.well-known/openid-configuration`` suffix is appended) or a full
    discovery URL. Returns the parsed JSON document. Raises :class:`SsoError` on
    any network/parse failure.
    """
    if not issuer:
        raise SsoError("OIDC issuer/discovery URL is required")
    if issuer in _DISCOVERY_CACHE:
        return _DISCOVERY_CACHE[issuer]

    url = issuer.rstrip("/")
    if not url.endswith("/.well-known/openid-configuration"):
        url = f"{url}/.well-known/openid-configuration"

    requests = _requests()
    try:
        resp = requests.get(url, timeout=timeout)
        resp.raise_for_status()
        doc = resp.json()
    except Exception as exc:
        raise SsoError(f"OIDC discovery failed for {issuer!r}: {exc}") from exc
    if not isinstance(doc, dict):
        raise SsoError("OIDC discovery document is not a JSON object")
    _DISCOVERY_CACHE[issuer] = doc
    return doc


def _resolve_endpoints(cfg: Any) -> dict[str, Any]:
    """Return the provider's OIDC endpoints, discovering them when necessary."""
    issuer = _cfg_get(cfg, "issuer", "discovery_url")
    if not issuer:
        raise SsoError("SSO config has no issuer/discovery_url")
    return oidc_discover(str(issuer))


def redirect_uri(base: str | None = None) -> str:
    """Build the OIDC redirect URI from the configured base URL."""
    from .config import settings

    root = (base or settings.OIDC_REDIRECT_BASE or "").rstrip("/")
    return f"{root}/auth/sso/callback"


def build_auth_url(cfg: Any, state: str, nonce: str, *, scope: str = "openid email profile") -> str:
    """Build the authorization-request URL to redirect the user's browser to.

    ``cfg`` is an :class:`~app.models.SsoConfig` (or dict) providing ``client_id``
    and the issuer. ``state`` and ``nonce`` are opaque CSRF/replay guards the
    caller must persist and later verify.
    """
    from urllib.parse import urlencode

    doc = _resolve_endpoints(cfg)
    authorize = doc.get("authorization_endpoint")
    if not authorize:
        raise SsoError("Provider discovery is missing 'authorization_endpoint'")
    client_id = _cfg_get(cfg, "client_id")
    if not client_id:
        raise SsoError("SSO config has no client_id")
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri(),
        "scope": scope,
        "state": state,
        "nonce": nonce,
    }
    sep = "&" if "?" in authorize else "?"
    return f"{authorize}{sep}{urlencode(params)}"


def exchange_code(cfg: Any, code: str, *, timeout: float = 10.0) -> dict[str, Any]:
    """Exchange an authorization ``code`` for the provider's token set.

    Returns the raw token endpoint JSON (``access_token``, ``id_token``, ...).
    Raises :class:`SsoError` on failure.
    """
    doc = _resolve_endpoints(cfg)
    token_endpoint = doc.get("token_endpoint")
    if not token_endpoint:
        raise SsoError("Provider discovery is missing 'token_endpoint'")
    client_id = _cfg_get(cfg, "client_id")
    client_secret = _cfg_get(cfg, "client_secret")
    if not client_id:
        raise SsoError("SSO config has no client_id")

    requests = _requests()
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri(),
        "client_id": client_id,
    }
    if client_secret:
        data["client_secret"] = client_secret
    try:
        resp = requests.post(token_endpoint, data=data, timeout=timeout)
        resp.raise_for_status()
        tokens = resp.json()
    except Exception as exc:
        raise SsoError(f"OIDC token exchange failed: {exc}") from exc
    if not isinstance(tokens, dict):
        raise SsoError("OIDC token response is not a JSON object")
    return tokens


def _claim_is_true(value: Any) -> bool:
    """True iff an OIDC boolean claim is explicitly true (JSON bool or "true").

    IdPs send booleans as a JSON ``true`` or, occasionally, the string
    ``"true"``. Anything else — ``False``, ``"false"``, ``None``, absent — is
    treated as NOT true (fail-closed).
    """
    return value is True or (isinstance(value, str) and value.strip().lower() == "true")


def fetch_userinfo(cfg: Any, tokens: dict[str, Any], *, timeout: float = 10.0) -> dict[str, Any]:
    """Fetch the end-user's profile from the userinfo endpoint.

    Returns a normalized ``{"email", "name", "sub"}`` dict. Raises
    :class:`SsoError` when no email can be determined (email is the JIT join key).
    """
    doc = _resolve_endpoints(cfg)
    userinfo_endpoint = doc.get("userinfo_endpoint")
    access_token = (tokens or {}).get("access_token")
    if not userinfo_endpoint or not access_token:
        raise SsoError("Missing userinfo endpoint or access token")

    requests = _requests()
    try:
        resp = requests.get(
            userinfo_endpoint,
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=timeout,
        )
        resp.raise_for_status()
        info = resp.json()
    except Exception as exc:
        raise SsoError(f"OIDC userinfo fetch failed: {exc}") from exc
    if not isinstance(info, dict):
        raise SsoError("OIDC userinfo response is not a JSON object")

    email = (info.get("email") or "").strip().lower()
    name = info.get("name") or info.get("preferred_username") or ""
    sub = info.get("sub") or ""
    if not email:
        raise SsoError("OIDC userinfo did not include an email claim")
    # The email is the JIT account-join key, so it MUST be proven-owned at the
    # IdP. Require the OIDC `email_verified` claim to be explicitly true; refuse
    # an email the IdP has not verified (claim false or absent). Without this a
    # misconfigured or attacker-controlled IdP could assert an unowned email and
    # have it map onto / create a local account.
    if not _claim_is_true(info.get("email_verified")):
        raise SsoError(
            "OIDC userinfo email is not verified (email_verified missing or false)"
        )
    return {"email": email, "name": name, "sub": sub}


def _decode_jwt_claims(jwt_str: str) -> dict[str, Any]:
    """Decode (WITHOUT signature verification) the claim set of a compact JWS."""
    try:
        payload_b64 = jwt_str.split(".")[1]
        payload_b64 += "=" * (-len(payload_b64) % 4)  # restore stripped base64 padding
        claims = json.loads(base64.urlsafe_b64decode(payload_b64.encode("ascii")))
    except Exception as exc:
        raise SsoError(f"OIDC id_token is malformed: {exc}") from exc
    if not isinstance(claims, dict):
        raise SsoError("OIDC id_token payload is not a JSON object")
    return claims


def verify_id_token_nonce(tokens: dict[str, Any], expected_nonce: str) -> None:
    """Verify the OIDC ``nonce`` echoed in the provider's id_token (replay guard).

    The id_token arrives in the token-endpoint response — a server-to-server HTTPS
    call to the trusted issuer — so its payload is authentic without a separate
    signature check here. (End-user identity is still taken from the TLS-
    authenticated *userinfo* endpoint, exactly as before; this adds a check and
    weakens nothing.) We require the id_token's ``nonce`` claim to equal the value
    minted for *this* login transaction, so a captured/replayed id_token from a
    different transaction is rejected.

    * No id_token in the response -> nothing to verify here (the single-use
      ``state`` record still binds the round-trip); returns quietly.
    * id_token present but nonce missing or mismatched -> raises :class:`SsoError`.
    """
    if not expected_nonce:
        raise SsoError("OIDC nonce verification requested without a stored nonce")
    id_token = (tokens or {}).get("id_token")
    if not id_token:
        return  # provider supplied no id_token; the single-use state still binds the flow
    got = _decode_jwt_claims(id_token).get("nonce")
    if not got or not secrets.compare_digest(str(got), str(expected_nonce)):
        raise SsoError("OIDC id_token nonce mismatch")


# --------------------------------------------------------------------------- #
# SAML (scaffold — production needs python3-saml/xmlsec)
# --------------------------------------------------------------------------- #
def parse_saml_response(cfg: Any, saml_response_b64: str) -> dict[str, str]:
    """Decode a base64 SAML ``Response`` and extract the identity (SCAFFOLD).

    This performs a **best-effort** parse of the NameID and common email/name
    attributes using only the standard library's XML parser. It is intentionally
    conservative:

    * When an ``x509_cert`` is configured on ``cfg`` a signature MUST be
      validated before the assertion is trusted. Real validation requires
      ``python3-saml`` (which wraps ``xmlsec``); that path is attempted behind a
      guarded import and, if the library is unavailable, this function raises
      :class:`SsoError` rather than trusting an unverified assertion.
    * When no certificate is configured the assertion is treated as untrusted
      test scaffolding and the extracted values are returned as-is. Do **not**
      enable this in production without a certificate.

    Returns ``{"email", "name"}``. Raises :class:`SsoError` on decode/parse
    failure or when a required signature cannot be verified.
    """
    import xml.etree.ElementTree as ET  # noqa: PLC0415  (stdlib, lazy)

    if not saml_response_b64:
        raise SsoError("Empty SAML response")

    try:
        raw = base64.b64decode(saml_response_b64)
    except Exception as exc:
        raise SsoError(f"SAML response is not valid base64: {exc}") from exc

    x509_cert = _cfg_get(cfg, "x509_cert")
    if x509_cert:
        # A certificate is configured: signature validation is mandatory. Try
        # the real validator; never fall through to trusting the assertion.
        try:
            from onelogin.saml2.response import (  # noqa: PLC0415
                OneLogin_Saml2_Response,
            )
        except Exception as exc:
            raise SsoError(
                "SAML signature validation requires 'python3-saml' (xmlsec); "
                "refusing to trust a signed assertion without it"
            ) from exc
        # The concrete OneLogin settings/validation wiring is deployment
        # specific; leaving the actual validate() call to the (present) library
        # keeps this scaffold honest about what production requires.
        _ = OneLogin_Saml2_Response  # referenced so the import is meaningful
        raise SsoError(
            "python3-saml is available but SAML validation wiring must be "
            "configured for this deployment before signed assertions are trusted"
        )

    # No certificate is configured. An unsigned assertion is attacker-forgeable,
    # so it must NEVER be trusted in production — refuse. The unsigned parse below
    # is reachable ONLY under DEBUG (local/test scaffolding).
    from .config import settings  # noqa: PLC0415 (lazy import, mirrors this module)

    if not settings.DEBUG:
        raise SsoError(
            "SAML requires a configured signing certificate (x509_cert) and "
            "signature verification; refusing an unsigned assertion in production."
        )

    # --- DEBUG/TEST-ONLY unsigned path: parse the XML with the stdlib. ------ #
    try:
        root = ET.fromstring(raw)
    except Exception as exc:
        raise SsoError(f"Could not parse SAML XML: {exc}") from exc

    email = ""
    name = ""

    # NameID (often the email) — namespace-agnostic local-name match.
    for elem in root.iter():
        tag = elem.tag.rsplit("}", 1)[-1]
        if tag == "NameID" and (elem.text or "").strip():
            candidate = elem.text.strip()
            if "@" in candidate and not email:
                email = candidate.lower()
        if tag == "Attribute":
            attr_name = (elem.get("Name") or "").lower()
            values = [
                (child.text or "").strip()
                for child in elem
                if child.tag.rsplit("}", 1)[-1] == "AttributeValue"
            ]
            value = next((v for v in values if v), "")
            if not value:
                continue
            if ("email" in attr_name or "emailaddress" in attr_name) and not email:
                email = value.lower()
            elif ("name" in attr_name or "displayname" in attr_name) and not name:
                name = value

    if not email:
        raise SsoError("SAML assertion did not yield an email/NameID")
    return {"email": email, "name": name}


# --------------------------------------------------------------------------- #
# JIT provisioning (the testable, pure/DB core)
# --------------------------------------------------------------------------- #
def provision_sso_user(
    db: Session,
    org: models.Organization,
    email: str,
    full_name: str = "",
) -> models.User:
    """Just-in-time provision an SSO-authenticated user into ``org``.

    Semantics:

    * Look up an existing :class:`~app.models.User` by ``email`` (case-insensitive).
    * If none exists, create one with a random (unusable) password hash — SSO
      users never authenticate with a local password — and mark it
      ``email_verified`` (this IdP login proves ownership of the address).
    * If one exists but is NOT ``email_verified``, this is the first SSO adoption
      of a possibly attacker-planted account: reset its password to a fresh
      random hash and bump ``token_version`` to revoke any pre-existing sessions,
      then mark it verified. This closes SSO account pre-hijacking. An
      already-verified account is adopted untouched, so legitimate repeat SSO
      logins never reset a password or churn sessions.
    * Ensure the user has a :class:`~app.models.Membership` in ``org``; when the
      membership is created it is granted the org's configured
      ``sso_default_role`` (falling back to ``"viewer"``).
    * Record an audit event.

    The caller commits. Returns the (existing or newly created) user.
    """
    email = (email or "").strip().lower()
    if not email:
        raise SsoError("Cannot provision an SSO user without an email")

    user = crud.get_user_by_email(db, email)
    # Mirror the password path (crud.authenticate refuses is_active=False): a
    # deactivated account must not be handed a session via SSO either. Checked
    # BEFORE any create/evict so a disabled account triggers no side effects.
    if user is not None and not user.is_active:
        raise SsoError("Account is deactivated")
    created = False
    evicted = False
    if user is None:
        # A long random secret that is hashed but never disclosed: the account
        # exists but cannot be logged into with a password. Ownership of the
        # email is proven by this IdP login, so the account is verified up front.
        random_password = secrets.token_urlsafe(32)
        user = models.User(
            email=email,
            password_hash=security.hash_password(random_password),
            full_name=full_name or "",
            email_verified=True,
        )
        db.add(user)
        db.flush()  # assign user.id
        created = True
    elif not getattr(user, "email_verified", False):
        # ACCOUNT PRE-HIJACKING DEFENSE. An existing but UNVERIFIED account may
        # have been planted by an attacker who pre-registered this email with a
        # password they know. The org's admin-configured IdP has now proven the
        # real owner controls the address, so evict any attacker foothold on the
        # FIRST adoption: neutralize the local password and revoke every session
        # minted before this login. Marking it verified makes this a one-time
        # event, so a legitimate repeat SSO login never resets anything.
        user.password_hash = security.hash_password(secrets.token_urlsafe(32))
        crud.bump_token_version(db, user)  # revoke pre-existing (attacker) sessions
        user.email_verified = True
        db.add(user)
        db.flush()
        evicted = True

    default_role = (getattr(org, "sso_default_role", None) or "viewer").strip() or "viewer"
    membership = crud.get_membership(db, user.id, org.id)
    if membership is None:
        db.add(
            models.Membership(user_id=user.id, org_id=org.id, role=default_role)
        )
        db.flush()

    crud.audit(
        db,
        org.id,
        user.id,
        "sso_login",
        f"provisioned={created} evicted={evicted} email={email} role={default_role}",
    )
    return user

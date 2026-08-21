"""Cryptographic primitives: password hashing, JWTs, API keys, and TOTP MFA.

Nothing here touches the database — these are pure functions used by the deps
and CRUD layers. Signing uses HS256 with ``settings.JWT_SECRET``.
"""

import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
import pyotp
from passlib.context import CryptContext

from .config import settings

# --------------------------------------------------------------------------- #
# Role hierarchy — higher rank implies every capability of a lower rank.
# --------------------------------------------------------------------------- #
ROLE_RANK: dict[str, int] = {
    "owner": 3,
    "admin": 2,
    "analyst": 1,
    "viewer": 0,
}

_pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# --------------------------------------------------------------------------- #
# Passwords
# --------------------------------------------------------------------------- #
def hash_password(password: str) -> str:
    """Return a bcrypt hash for ``password``."""
    return _pwd_context.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    """Return True if ``password`` matches ``password_hash``."""
    try:
        return _pwd_context.verify(password, password_hash)
    except (ValueError, TypeError):
        return False


# --------------------------------------------------------------------------- #
# JSON Web Tokens
# --------------------------------------------------------------------------- #
def _encode(payload: dict[str, Any], expires: timedelta) -> str:
    now = datetime.now(timezone.utc)
    body = {
        **payload,
        "iat": int(now.timestamp()),
        "exp": int((now + expires).timestamp()),
    }
    return jwt.encode(body, settings.JWT_SECRET, algorithm=settings.JWT_ALG)


def create_access_token(
    sub: str | int,
    org_id: int | None = None,
    token_version: int | None = None,
) -> str:
    """Mint a short-lived access token for user id ``sub`` (optional org).

    When ``token_version`` is provided the token carries a ``"ver"`` claim used
    by the Phase 5 revocation check (see :func:`app.deps.get_current_user`).
    When it is ``None`` (the default) **no** ``"ver"`` claim is added, so tokens
    remain byte-compatible with the pre-Phase-5 behavior and the existing test
    suite is unaffected.
    """
    payload: dict[str, Any] = {"sub": str(sub), "type": "access"}
    if org_id is not None:
        payload["org_id"] = org_id
    if token_version is not None:
        payload["ver"] = int(token_version)
    return _encode(payload, timedelta(minutes=settings.ACCESS_TTL_MIN))


def create_refresh_token(
    sub: str | int,
    org_id: int | None = None,
    token_version: int | None = None,
    jti: str | None = None,
    family: str | None = None,
) -> str:
    """Mint a long-lived refresh token for user id ``sub``.

    As with :func:`create_access_token`, a ``"ver"`` claim is included only when
    ``token_version`` is passed. ``jti`` (this token's unique id) and ``family``
    (its rotation lineage) are embedded when provided so the server-side store
    can rotate the token and detect replay of a consumed token (see
    :mod:`app.crud`).
    """
    payload: dict[str, Any] = {"sub": str(sub), "type": "refresh"}
    if org_id is not None:
        payload["org_id"] = org_id
    if token_version is not None:
        payload["ver"] = int(token_version)
    if jti is not None:
        payload["jti"] = jti
    if family is not None:
        payload["fam"] = family
    return _encode(payload, timedelta(days=settings.REFRESH_TTL_DAYS))


def decode_token(token: str) -> dict[str, Any]:
    """Decode & verify a JWT. Raises ``jwt.PyJWTError`` if invalid/expired."""
    return jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALG])


def is_token_revoked(payload_ver: Any, current_version: Any) -> bool:
    """Fail-CLOSED session-revocation check.

    A token is revoked unless the version it carries EQUALS the user's current
    ``token_version``. A **missing** ``ver`` claim is treated as version 0 (not a
    bypass): once a user's ``token_version`` is bumped past 0 (e.g. by
    ``/auth/logout-all``), any earlier token — versioned OR ver-less — is
    rejected. This closes the pre-existing ver-less fail-open while staying
    compatible with un-revoked (version-0) tokens.
    """
    return int(payload_ver or 0) != int(current_version or 0)


def can_manage_member(actor_role: str, target_role: str) -> bool:
    """True if a member with ``actor_role`` may mutate one with ``target_role``.

    Separation-of-duties rule: a caller may only change the role of, or remove, a
    member whose role does NOT outrank their own. Peers of equal rank may manage
    each other (owners may manage owners — the last-owner guard still applies),
    but an admin may never demote or remove an owner. Unknown roles fail closed.
    """
    return ROLE_RANK.get(target_role, 99) <= ROLE_RANK.get(actor_role, -1)


# --------------------------------------------------------------------------- #
# API keys — full key form: ``rcx_<prefix>_<secret>``. Only the hash is stored.
# --------------------------------------------------------------------------- #
def _hash_secret(secret: str) -> str:
    """SHA-256 hex digest of an API-key secret (keys are high-entropy)."""
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def new_api_key() -> tuple[str, str, str]:
    """Generate a fresh API key.

    Returns ``(full_key, prefix, key_hash)`` where ``full_key`` is shown to the
    user exactly once and never persisted.
    """
    prefix = secrets.token_hex(4)          # 8 hex chars, used for lookup
    secret = secrets.token_urlsafe(32)     # the sensitive part
    full_key = f"rcx_{prefix}_{secret}"
    return full_key, prefix, _hash_secret(secret)


def verify_api_key(full_key: str, key_hash: str) -> bool:
    """Constant-time check that ``full_key`` matches the stored ``key_hash``."""
    parts = full_key.split("_", 2)
    if len(parts) != 3 or parts[0] != "rcx":
        return False
    return secrets.compare_digest(_hash_secret(parts[2]), key_hash)


def api_key_prefix(full_key: str) -> str | None:
    """Extract the lookup prefix from a full API key, or None if malformed."""
    parts = full_key.split("_", 2)
    if len(parts) != 3 or parts[0] != "rcx":
        return None
    return parts[1]


# --------------------------------------------------------------------------- #
# TOTP MFA
# --------------------------------------------------------------------------- #
def totp_new_secret() -> str:
    """Return a fresh base32 TOTP secret."""
    return pyotp.random_base32()


def totp_uri(secret: str, email: str, issuer: str = "RECON-X") -> str:
    """Build an otpauth:// provisioning URI for authenticator apps / QR codes."""
    return pyotp.TOTP(secret).provisioning_uri(name=email, issuer_name=issuer)


def totp_verify(secret: str, code: str) -> bool:
    """Verify a 6-digit TOTP ``code`` against ``secret`` (±1 time step)."""
    if not secret or not code:
        return False
    return pyotp.TOTP(secret).verify(str(code).strip(), valid_window=1)

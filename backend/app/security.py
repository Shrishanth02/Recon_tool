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
) -> str:
    """Mint a long-lived refresh token for user id ``sub``.

    As with :func:`create_access_token`, a ``"ver"`` claim is included only when
    ``token_version`` is passed; otherwise the token is identical to what
    earlier phases produced.
    """
    payload: dict[str, Any] = {"sub": str(sub), "type": "refresh"}
    if org_id is not None:
        payload["org_id"] = org_id
    if token_version is not None:
        payload["ver"] = int(token_version)
    return _encode(payload, timedelta(days=settings.REFRESH_TTL_DAYS))


def decode_token(token: str) -> dict[str, Any]:
    """Decode & verify a JWT. Raises ``jwt.PyJWTError`` if invalid/expired."""
    return jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALG])


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

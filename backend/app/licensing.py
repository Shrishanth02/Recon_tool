"""Offline, signed license tokens for self-hosted RECON-X installs (Phase 3).

A license token is a compact, offline-verifiable entitlement grant issued by the
vendor and installed on a customer's self-hosted deployment. It carries the plan
tier and quota/feature entitlements and is signed with **Ed25519** so it can be
verified with only the vendor's public key — no phone-home, no network.

Token wire format::

    base64url(json_payload) + "." + base64url(ed25519_signature)

where ``json_payload`` is the UTF-8 JSON encoding of::

    {
      "tier":     "pro",            # a plans.PLANS id
      "org":      "acme" | null,    # optional org binding (advisory)
      "assets":   25 | null,        # quota overrides (null = unlimited)
      "seats":    10 | null,
      "scans":    2000 | null,
      "features": ["ai", ...],      # enabled boolean features
      "iat":      1737000000,       # issued-at, unix seconds
      "exp":      1768536000 | null,# expiry, unix seconds (null = never)
      "jti":      "..."             # unique token id
    }

Design constraints (obeyed exactly):

* ``cryptography`` is imported **lazily** inside each function that needs it. If
  it is not installed, functions degrade gracefully (returning failures / None);
  ``import app.licensing`` must always succeed.
* A real development vendor public key is embedded as :data:`DEFAULT_PUBLIC_PEM`
  so verification works out of the box; ``settings.LICENSE_PUBLIC_KEY`` (if set)
  overrides it.
"""

from __future__ import annotations

import base64
import json
import secrets
import time
from typing import Any

# --------------------------------------------------------------------------- #
# Embedded development vendor keypair.
#
# DEFAULT_PUBLIC_PEM is a genuine Ed25519 public key generated for local testing.
# The matching private key is recorded below ONLY so the local test/verify step
# can sign tokens. It is a throwaway dev key — a production build MUST override
# the public key via settings.LICENSE_PUBLIC_KEY and keep its own private key
# secret.
#
# DEV ISSUER KEY (for local testing only — do not ship):
# -----BEGIN PRIVATE KEY-----
# MC4CAQAwBQYDK2VwBCIEIHUUGM2m4asGcyfem8zlMlSCrjYoiulD3KjroSyFmmLD
# -----END PRIVATE KEY-----
# --------------------------------------------------------------------------- #
DEFAULT_PUBLIC_PEM = (
    "-----BEGIN PUBLIC KEY-----\n"
    "MCowBQYDK2VwAyEAHKGjolAtBPCmB212PcZqUwdLjxiMg3kFh/SQAu5M+dY=\n"
    "-----END PUBLIC KEY-----\n"
)


# --------------------------------------------------------------------------- #
# base64url helpers (no padding on the wire, tolerant on read)
# --------------------------------------------------------------------------- #
def _b64url_encode(raw: bytes) -> str:
    """URL-safe base64 without padding."""
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(text: str) -> bytes:
    """Decode URL-safe base64, tolerating missing padding."""
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


# --------------------------------------------------------------------------- #
# Key generation & issuance (vendor side)
# --------------------------------------------------------------------------- #
def generate_keypair() -> tuple[str, str]:
    """Generate a fresh Ed25519 keypair.

    Returns ``(private_pem, public_pem)`` as PEM strings. Raises
    :class:`RuntimeError` if ``cryptography`` is not installed (this is a
    vendor-side helper, so raising — rather than silently degrading — is the
    correct signal that the tooling dependency is missing).
    """
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519
    except ImportError as exc:  # pragma: no cover - depends on env
        raise RuntimeError(
            "generate_keypair requires the 'cryptography' package"
        ) from exc

    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    return private_pem, public_pem


def issue_license(entitlements: dict[str, Any], private_pem: str) -> str:
    """Issue (sign) a license token from an ``entitlements`` dict (vendor side).

    Recognized ``entitlements`` keys (all optional except ``tier``):
    ``tier``, ``org``, ``assets``, ``seats``, ``scans``, ``features`` (list),
    ``exp`` (unix seconds or ``None``), ``jti``. Missing fields are defaulted;
    ``iat`` is stamped to now and a random ``jti`` is generated if absent.

    Returns the compact ``payload.signature`` token string. Raises
    :class:`RuntimeError` if ``cryptography`` is unavailable.
    """
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519
    except ImportError as exc:  # pragma: no cover - depends on env
        raise RuntimeError(
            "issue_license requires the 'cryptography' package"
        ) from exc

    ent = dict(entitlements or {})
    payload: dict[str, Any] = {
        "tier": ent.get("tier", "free"),
        "org": ent.get("org"),
        "assets": ent.get("assets"),
        "seats": ent.get("seats"),
        "scans": ent.get("scans"),
        "features": list(ent.get("features") or []),
        "iat": int(ent.get("iat") or time.time()),
        "exp": ent.get("exp"),
        "jti": ent.get("jti") or secrets.token_hex(8),
    }

    private_key = serialization.load_pem_private_key(
        private_pem.encode("ascii"), password=None
    )
    if not isinstance(private_key, ed25519.Ed25519PrivateKey):
        raise RuntimeError("issue_license requires an Ed25519 private key")

    payload_bytes = json.dumps(
        payload, separators=(",", ":"), sort_keys=True
    ).encode("utf-8")
    signature = private_key.sign(payload_bytes)
    return f"{_b64url_encode(payload_bytes)}.{_b64url_encode(signature)}"


# --------------------------------------------------------------------------- #
# Verification (customer / server side)
# --------------------------------------------------------------------------- #
def _resolve_public_pem(public_pem: str | None) -> str:
    """Resolve which public key PEM to verify against.

    Priority: an explicit ``public_pem`` argument, then
    ``settings.LICENSE_PUBLIC_KEY`` (if configured), then the embedded
    :data:`DEFAULT_PUBLIC_PEM`.
    """
    if public_pem and public_pem.strip():
        return public_pem
    try:
        from .config import settings

        configured = (settings.LICENSE_PUBLIC_KEY or "").strip()
        if configured:
            return configured
    except Exception:  # pragma: no cover - config should always import
        pass
    return DEFAULT_PUBLIC_PEM


def verify_license(
    token: str, public_pem: str | None = None
) -> tuple[bool, Any]:
    """Verify a license ``token`` and return ``(ok, payload_or_reason)``.

    On success returns ``(True, payload_dict)``. On failure returns
    ``(False, reason_str)``. Verification steps:

    1. structural parse of the ``payload.signature`` form,
    2. Ed25519 signature check against the resolved public key
       (argument > ``settings.LICENSE_PUBLIC_KEY`` > :data:`DEFAULT_PUBLIC_PEM`),
    3. expiry check (``exp`` in the past → expired).

    Never raises: a missing ``cryptography`` package or any malformed input is
    reported as a ``(False, reason)`` pair.
    """
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ed25519
    except ImportError:
        return False, "cryptography not installed"

    if not token or "." not in token:
        return False, "malformed token"

    payload_b64, _, sig_b64 = token.partition(".")
    try:
        payload_bytes = _b64url_decode(payload_b64)
        signature = _b64url_decode(sig_b64)
    except (ValueError, TypeError):
        return False, "malformed token encoding"

    pem = _resolve_public_pem(public_pem)
    try:
        public_key = serialization.load_pem_public_key(pem.encode("ascii"))
    except Exception:
        return False, "invalid public key"
    if not isinstance(public_key, ed25519.Ed25519PublicKey):
        return False, "public key is not Ed25519"

    try:
        public_key.verify(signature, payload_bytes)
    except InvalidSignature:
        return False, "signature mismatch"
    except Exception:
        return False, "signature verification failed"

    try:
        payload = json.loads(payload_bytes.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return False, "invalid payload json"
    if not isinstance(payload, dict):
        return False, "invalid payload"

    exp = payload.get("exp")
    if exp is not None:
        try:
            if float(exp) < time.time():
                return False, "license expired"
        except (TypeError, ValueError):
            return False, "invalid exp"

    return True, payload


def load_active_license() -> dict[str, Any] | None:
    """Return the verified payload of the install's active license, or ``None``.

    Reads ``settings.LICENSE_KEY``, verifies it against the resolved public key,
    and returns the payload dict when valid (and unexpired). Returns ``None`` if
    no license is configured, verification fails, the token is expired, or
    ``cryptography`` is unavailable.
    """
    try:
        from .config import settings

        token = (settings.LICENSE_KEY or "").strip()
    except Exception:  # pragma: no cover - config should always import
        return None
    if not token:
        return None
    ok, payload = verify_license(token)
    if ok and isinstance(payload, dict):
        return payload
    return None

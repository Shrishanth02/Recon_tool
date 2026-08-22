"""At-rest authenticated encryption for credential-bearing option values.

A *scheduled* scan (unlike a one-shot scan) must retain its session credential so
the worker can re-run the authenticated scan on the next tick — masking it the way
a completed :class:`~app.models.Scan` does would break the schedule. Instead the
credential-bearing VALUES inside a ``Schedule.options`` blob are encrypted at rest
and decrypted only in memory, immediately before the worker builds the scan job.

Encryption uses Fernet (authenticated AES-128-CBC + HMAC-SHA256): tampered or
wrong-key ciphertext raises :class:`cryptography.fernet.InvalidToken` rather than
silently returning garbage. The symmetric key is derived from the deployment's
``JWT_SECRET`` via HKDF-SHA256 with a domain-separation label, so:

  * no NEW secret/config is required (``JWT_SECRET`` is already validated to be
    strong in non-DEBUG mode), and
  * the encryption key is cryptographically distinct from the token-signing key.

Rotating ``JWT_SECRET`` invalidates stored ciphertext by design — the credential
must then be re-entered. The same canonical ``SECRET_OPTION_KEYS`` set drives the
scan-record masking in :func:`app.crud.redact_scan_options`, so the persist and
schedule paths can never drift on which keys are secret.
"""

import base64

from cryptography.fernet import Fernet, InvalidToken  # noqa: F401  (re-exported)
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .config import settings

# Option keys whose VALUE is a live credential/secret.
SECRET_OPTION_KEYS = frozenset({"cookie", "auth_header", "password", "token"})

_MASK = "***"
_ENC_PREFIX = "enc:v1:"                       # marks a value as ciphertext
_HKDF_INFO = b"reconx.options.secretbox.v1"   # domain separation from JWT signing


def _fernet() -> Fernet:
    """Derive the Fernet instance for the CURRENT ``JWT_SECRET`` (re-derived each
    call so a rotated secret takes effect — and so a wrong key fails closed)."""
    secret = (settings.JWT_SECRET or "").encode() or b"reconx-empty-secret"
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=_HKDF_INFO).derive(secret)
    return Fernet(base64.urlsafe_b64encode(key))


def _is_secret(key: str, value) -> bool:
    return key in SECRET_OPTION_KEYS and isinstance(value, str) and value != ""


def is_encrypted(value) -> bool:
    return isinstance(value, str) and value.startswith(_ENC_PREFIX)


def encrypt_value(plaintext):
    """Encrypt a single secret STRING for at-rest storage (tagged ``enc:v1:``).
    Idempotent: empty strings, non-strings and already-encrypted values pass
    through unchanged."""
    if not isinstance(plaintext, str) or plaintext == "" or is_encrypted(plaintext):
        return plaintext
    return _ENC_PREFIX + _fernet().encrypt(plaintext.encode()).decode()


def decrypt_value(stored):
    """Decrypt a single at-rest secret string for in-memory USE. A value without
    the ``enc:v1:`` prefix is treated as LEGACY PLAINTEXT and returned unchanged
    (empties/non-strings too); ``enc:v1:`` ciphertext is decrypted and raises
    :class:`cryptography.fernet.InvalidToken` on tamper / wrong key."""
    if not isinstance(stored, str) or not is_encrypted(stored):
        return stored
    return _fernet().decrypt(stored[len(_ENC_PREFIX):].encode()).decode()


def encrypt_options(options) -> dict:
    """Return a copy of ``options`` with credential VALUES encrypted for at-rest
    storage (idempotent; non-secret keys pass through). Non-dict input -> ``{}``."""
    if not isinstance(options, dict):
        return {}
    return {k: (encrypt_value(v) if k in SECRET_OPTION_KEYS else v) for k, v in options.items()}


def decrypt_options(options) -> dict:
    """Return a copy of ``options`` with credential VALUES decrypted for USE at
    execution. Raises :class:`cryptography.fernet.InvalidToken` on tampered or
    wrong-key ciphertext; legacy plaintext passes through. Non-dict input -> ``{}``."""
    if not isinstance(options, dict):
        return {}
    return {k: (decrypt_value(v) if k in SECRET_OPTION_KEYS else v) for k, v in options.items()}


def mask_options(options) -> dict:
    """Return a copy of ``options`` with credential VALUES masked to ``"***"`` for
    API/log output — presence kept, value hidden, whether the stored form is
    ciphertext or legacy plaintext. Non-dict input yields ``{}``."""
    if not isinstance(options, dict):
        return {}
    return {k: (_MASK if _is_secret(k, v) else v) for k, v in options.items()}

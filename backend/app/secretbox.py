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


def encrypt_options(options) -> dict:
    """Return a copy of ``options`` with credential VALUES encrypted for at-rest
    storage. Idempotent (an already-``enc:v1:`` value is left as-is); non-secret
    keys and empty values pass through. Non-dict input yields ``{}``."""
    if not isinstance(options, dict):
        return {}
    f = _fernet()
    out = {}
    for k, v in options.items():
        if _is_secret(k, v) and not is_encrypted(v):
            out[k] = _ENC_PREFIX + f.encrypt(v.encode()).decode()
        else:
            out[k] = v
    return out


def decrypt_options(options) -> dict:
    """Return a copy of ``options`` with credential VALUES decrypted for USE at
    execution. Raises :class:`cryptography.fernet.InvalidToken` on tampered or
    wrong-key ciphertext. A value without the ``enc:v1:`` prefix is treated as
    legacy plaintext and passed through unchanged. Non-dict input yields ``{}``."""
    if not isinstance(options, dict):
        return {}
    f = _fernet()
    out = {}
    for k, v in options.items():
        if k in SECRET_OPTION_KEYS and is_encrypted(v):
            out[k] = f.decrypt(v[len(_ENC_PREFIX):].encode()).decode()
        else:
            out[k] = v
    return out


def mask_options(options) -> dict:
    """Return a copy of ``options`` with credential VALUES masked to ``"***"`` for
    API/log output — presence kept, value hidden, whether the stored form is
    ciphertext or legacy plaintext. Non-dict input yields ``{}``."""
    if not isinstance(options, dict):
        return {}
    return {k: (_MASK if _is_secret(k, v) else v) for k, v in options.items()}

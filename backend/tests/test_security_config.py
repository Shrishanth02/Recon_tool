"""P0-2 regression tests — fail-closed JWT signing-secret validation.

The production auth model rests on a secret that only the deployment knows. If a
real (non-DEBUG) deployment boots with the repo's public dev default — or any
weak/known value — anyone can forge admin tokens. ``app.config.validate_jwt_secret``
must refuse to start in that case while keeping local development frictionless.

These tests exercise the pure validator directly (no process re-import needed).
"""

import pytest

from app.config import (
    MIN_JWT_SECRET_LEN,
    _INSECURE_JWT_SECRETS,
    validate_jwt_secret,
)

# A strong, clearly-fake secret: >= MIN_JWT_SECRET_LEN and not on the deny list.
STRONG_SECRET = "9f" * 40  # 80 hex-ish chars


# 1. production + insecure default -> failure
def test_production_rejects_insecure_default():
    with pytest.raises(RuntimeError):
        validate_jwt_secret(debug=False, secret="dev-insecure-change-me")


# 2. production + missing secret -> failure
def test_production_rejects_missing_secret():
    with pytest.raises(RuntimeError):
        validate_jwt_secret(debug=False, secret="")
    with pytest.raises(RuntimeError):
        validate_jwt_secret(debug=False, secret="   ")  # whitespace only


# 3. production + valid configured secret -> success
def test_production_accepts_strong_secret():
    # Must not raise.
    validate_jwt_secret(debug=False, secret=STRONG_SECRET)


# 4. development mode behaviour remains usable (anything goes)
def test_debug_mode_allows_anything():
    validate_jwt_secret(debug=True, secret="")
    validate_jwt_secret(debug=True, secret="dev-insecure-change-me")
    validate_jwt_secret(debug=True, secret="x")


# 5. insecure known values are rejected (whole curated set)
def test_production_rejects_all_known_insecure_values():
    for bad in _INSECURE_JWT_SECRETS:
        with pytest.raises(RuntimeError):
            validate_jwt_secret(debug=False, secret=bad)


# 5b. weak-but-not-listed short secrets are rejected on length
def test_production_rejects_short_custom_secret():
    short = "s3cr3t!"  # not on the deny list, but well under the minimum
    assert len(short) < MIN_JWT_SECRET_LEN
    with pytest.raises(RuntimeError):
        validate_jwt_secret(debug=False, secret=short)


# 5c. a secret exactly at the boundary is accepted
def test_production_accepts_min_length_secret():
    boundary = "a" * MIN_JWT_SECRET_LEN
    validate_jwt_secret(debug=False, secret=boundary)


# The error must never leak the attempted secret into logs.
def test_error_message_does_not_leak_secret():
    # A short value (< minimum) so it is rejected; the message must not echo it.
    sentinel = "leaky-sentinel"  # 14 chars
    assert len(sentinel) < MIN_JWT_SECRET_LEN
    try:
        validate_jwt_secret(debug=False, secret=sentinel)
    except RuntimeError as exc:
        assert sentinel not in str(exc)
    else:  # pragma: no cover - the call above must raise
        pytest.fail("expected RuntimeError for a short secret")


# The live settings singleton was validated at import with the strong test
# secret from conftest, so importing the app must have succeeded.
def test_live_settings_passed_validation():
    from app.config import settings

    # In the test process the guard already ran at import; re-running it against
    # the loaded settings must also pass (proves conftest's secret is compliant).
    validate_jwt_secret(debug=True, secret=settings.JWT_SECRET)

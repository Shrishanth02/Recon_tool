"""Offline signed-license tests (:mod:`app.licensing`).

Exercises the Ed25519 issue/verify roundtrip and the failure modes that keep a
self-hosted entitlement trustworthy: tampering, expiry, and verification against
the wrong public key. Also checks that a token signed with the embedded DEV
ISSUER private key validates against the shipped :data:`DEFAULT_PUBLIC_PEM`.

The whole module is skipped when ``cryptography`` is unavailable (issuance is a
vendor-side helper that raises without it), so this never blocks a minimal env.
"""

import time

import pytest

pytest.importorskip("cryptography")

from app import licensing  # noqa: E402

# The throwaway DEV ISSUER private key whose public half is the module's
# embedded DEFAULT_PUBLIC_PEM. Signing with it must verify out of the box.
DEV_PRIVATE_PEM = (
    "-----BEGIN PRIVATE KEY-----\n"
    "MC4CAQAwBQYDK2VwBCIEIHUUGM2m4asGcyfem8zlMlSCrjYoiulD3KjroSyFmmLD\n"
    "-----END PRIVATE KEY-----\n"
)


def test_generate_issue_verify_roundtrip():
    private_pem, public_pem = licensing.generate_keypair()
    assert "PRIVATE KEY" in private_pem
    assert "PUBLIC KEY" in public_pem

    token = licensing.issue_license(
        {"tier": "pro", "assets": 25, "features": ["ai", "continuous"]},
        private_pem,
    )
    assert "." in token

    ok, payload = licensing.verify_license(token, public_pem)
    assert ok is True
    assert isinstance(payload, dict)
    assert payload["tier"] == "pro"
    assert payload["assets"] == 25
    assert payload["features"] == ["ai", "continuous"]
    # iat/jti are stamped by the issuer.
    assert payload["jti"]
    assert isinstance(payload["iat"], int)


def test_tampered_token_is_rejected():
    private_pem, public_pem = licensing.generate_keypair()
    token = licensing.issue_license({"tier": "pro"}, private_pem)

    payload_b64, _, sig_b64 = token.partition(".")
    # Re-sign nothing: swap the payload for a higher tier while keeping the old
    # signature. The signature no longer matches the payload bytes.
    forged_payload = licensing._b64url_encode(
        b'{"tier":"mssp","assets":null,"seats":null,"scans":null,'
        b'"features":["white_label"],"iat":0,"exp":null,"jti":"x"}'
    )
    forged = f"{forged_payload}.{sig_b64}"

    ok, reason = licensing.verify_license(forged, public_pem)
    assert ok is False
    assert isinstance(reason, str)


def test_expired_token_is_rejected():
    private_pem, public_pem = licensing.generate_keypair()
    token = licensing.issue_license(
        {"tier": "pro", "exp": int(time.time()) - 3600}, private_pem
    )
    ok, reason = licensing.verify_license(token, public_pem)
    assert ok is False
    assert reason == "license expired"

    # A future expiry is fine.
    good = licensing.issue_license(
        {"tier": "pro", "exp": int(time.time()) + 3600}, private_pem
    )
    ok2, payload = licensing.verify_license(good, public_pem)
    assert ok2 is True
    assert payload["tier"] == "pro"


def test_verify_against_different_public_key_is_rejected():
    private_a, _public_a = licensing.generate_keypair()
    _private_b, public_b = licensing.generate_keypair()

    token = licensing.issue_license({"tier": "pro"}, private_a)
    ok, reason = licensing.verify_license(token, public_b)
    assert ok is False
    assert reason == "signature mismatch"


def test_dev_issuer_key_validates_against_embedded_default_public_pem():
    # A token signed by the DEV ISSUER private key must verify with NO explicit
    # public key argument, i.e. against the shipped DEFAULT_PUBLIC_PEM (settings
    # LICENSE_PUBLIC_KEY is empty in tests).
    token = licensing.issue_license(
        {"tier": "starter", "seats": 3}, DEV_PRIVATE_PEM
    )
    ok, payload = licensing.verify_license(token)  # resolves DEFAULT_PUBLIC_PEM
    assert ok is True, payload
    assert payload["tier"] == "starter"
    assert payload["seats"] == 3

    # Sanity: the same token also verifies when the default PEM is passed
    # explicitly.
    ok2, _ = licensing.verify_license(token, licensing.DEFAULT_PUBLIC_PEM)
    assert ok2 is True


def test_malformed_token_is_rejected_without_raising():
    ok, reason = licensing.verify_license("not-a-token")
    assert ok is False
    assert reason == "malformed token"

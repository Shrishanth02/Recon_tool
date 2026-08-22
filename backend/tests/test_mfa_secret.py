"""MFA (TOTP) secret encrypted at rest (P2).

Exercises the full lifecycle through the real endpoints: enrollment stores the
secret ENCRYPTED (plaintext returned once for provisioning), verification/login
decrypt it in memory only, the API never exposes the secret, tampered/rotated-key
ciphertext fails closed, and legacy bare-plaintext rows still verify. No Docker,
no external network.
"""

import pyotp

import app.config as cfg
from app import models
from app.database import SessionLocal


def _user(uid):
    db = SessionLocal()
    try:
        return db.get(models.User, uid)
    finally:
        db.close()


def _set_mfa(uid, secret_value, enabled=True):
    db = SessionLocal()
    try:
        u = db.get(models.User, uid)
        u.mfa_secret = secret_value
        u.mfa_enabled = enabled
        db.add(u)
        db.commit()
    finally:
        db.close()


def _enroll(client, auth):
    r = client.post("/auth/mfa/enroll", headers=auth["headers"])
    assert r.status_code == 200, r.text
    return r.json()["secret"]        # plaintext base32 delivered ONCE for setup


def test_enroll_stores_ciphertext_not_plaintext(client, auth):
    secret = _enroll(client, auth)
    assert secret and secret.isalnum()               # base32 plaintext to the user
    u = _user(auth["user_id"])
    assert u.mfa_secret.startswith("enc:v1:")        # persisted ENCRYPTED
    assert secret not in u.mfa_secret                # plaintext absent at rest
    assert u.mfa_enabled is False                    # not enabled until verified


def test_verify_enables_and_login_requires_code(client, auth):
    secret = _enroll(client, auth)
    r = client.post("/auth/mfa/verify", headers=auth["headers"],
                    json={"code": pyotp.TOTP(secret).now()})
    assert r.status_code == 200, r.text
    assert _user(auth["user_id"]).mfa_enabled is True
    email = auth["email"]
    # login without a code is refused ...
    assert client.post("/auth/login",
                       json={"email": email, "password": "password123"}).status_code == 401
    # ... and succeeds with a valid TOTP derived from the (decrypted) secret
    ok = client.post("/auth/login", json={
        "email": email, "password": "password123", "mfa_code": pyotp.TOTP(secret).now()})
    assert ok.status_code == 200, ok.text


def test_verify_rejects_wrong_code(client, auth):
    secret = _enroll(client, auth)
    real = pyotp.TOTP(secret).now()
    wrong = f"{(int(real) + 500000) % 1000000:06d}"   # guaranteed-different digits
    r = client.post("/auth/mfa/verify", headers=auth["headers"], json={"code": wrong})
    assert r.status_code == 400
    assert _user(auth["user_id"]).mfa_enabled is False


def test_login_fails_closed_on_tampered_secret(client, auth):
    secret = _enroll(client, auth)
    client.post("/auth/mfa/verify", headers=auth["headers"],
                json={"code": pyotp.TOTP(secret).now()})
    enc = _user(auth["user_id"]).mfa_secret
    tampered = enc[:-2] + ("AA" if enc[-2:] != "AA" else "BB")
    _set_mfa(auth["user_id"], tampered, enabled=True)
    # even a correct-for-the-original code cannot log in — the secret no longer
    # decrypts, so MFA fails closed (deny), never bypasses.
    r = client.post("/auth/login", json={
        "email": auth["email"], "password": "password123", "mfa_code": pyotp.TOTP(secret).now()})
    assert r.status_code == 401


def test_legacy_plaintext_secret_still_verifies(client, auth):
    # A pre-encryption row: bare base32 plaintext, MFA already enabled.
    secret = pyotp.random_base32()
    _set_mfa(auth["user_id"], secret, enabled=True)
    r = client.post("/auth/login", json={
        "email": auth["email"], "password": "password123", "mfa_code": pyotp.TOTP(secret).now()})
    assert r.status_code == 200, r.text


def test_key_rotation_invalidates_stored_secret(client, auth):
    secret = _enroll(client, auth)
    client.post("/auth/mfa/verify", headers=auth["headers"],
                json={"code": pyotp.TOTP(secret).now()})
    orig = cfg.settings.JWT_SECRET
    cfg.settings.JWT_SECRET = "rotated-strong-secret-value-of-length-32ch"
    try:
        r = client.post("/auth/login", json={
            "email": auth["email"], "password": "password123",
            "mfa_code": pyotp.TOTP(secret).now()})
        assert r.status_code == 401     # undecryptable under the new key -> fail closed
    finally:
        cfg.settings.JWT_SECRET = orig


def test_me_endpoint_never_exposes_mfa_secret(client, auth):
    secret = _enroll(client, auth)
    r = client.get("/auth/me", headers=auth["headers"])
    assert r.status_code == 200
    body = r.text
    assert "mfa_secret" not in body        # field is not serialized
    assert secret not in body              # no plaintext
    assert "enc:v1:" not in body           # no ciphertext
    assert "mfa_enabled" in r.json()["user"]

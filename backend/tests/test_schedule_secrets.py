"""At-rest encryption of credential-bearing Schedule.options (P2 #1).

Covers the whole path: create (encrypt at rest), the toggle "update" (ciphertext
preserved), the worker's decrypt-for-use step, wrong-key / tampered-ciphertext
failure (fail closed), API masking (ScheduleOut), and that non-secret scheduling
options are never transformed. No Docker, no network — pure crypto + DB.
"""

import json

import pytest
from cryptography.fernet import InvalidToken

import app.config as cfg
from app import crud, schemas, secretbox
from app.database import SessionLocal


# --------------------------------------------------------------------------- #
# secretbox unit behaviour
# --------------------------------------------------------------------------- #
def test_encrypt_decrypt_round_trip_hides_plaintext():
    opts = {"cookie": "session=SECRET123", "auth_header": "Bearer JWTsecret",
            "password": "pw!", "token": "eyJ.a.b", "scan_type": "quick",
            "login_url": "https://x/login", "user_sel": "#u"}
    enc = secretbox.encrypt_options(opts)
    # secrets become ciphertext; the plaintext appears nowhere
    for k in ("cookie", "auth_header", "password", "token"):
        assert enc[k].startswith("enc:v1:")
    blob = json.dumps(enc)
    for secret in ("SECRET123", "JWTsecret", "pw!", "eyJ.a.b"):
        assert secret not in blob
    # non-secret scheduling options are untouched
    assert enc["scan_type"] == "quick" and enc["login_url"] == "https://x/login"
    assert enc["user_sel"] == "#u"
    # exact round-trip back to plaintext
    assert secretbox.decrypt_options(enc) == opts


def test_encrypt_is_idempotent():
    enc = secretbox.encrypt_options({"cookie": "c=1"})
    assert secretbox.encrypt_options(enc) == enc          # not double-wrapped


def test_decrypt_passes_through_legacy_plaintext():
    # A pre-existing (unencrypted) row must still be usable by the worker.
    assert secretbox.decrypt_options({"cookie": "c=1", "scan_type": "q"}) == {
        "cookie": "c=1", "scan_type": "q"}


def test_decrypt_tampered_ciphertext_raises():
    enc = secretbox.encrypt_options({"cookie": "session=abc"})
    tampered = {"cookie": enc["cookie"][:-2] + ("AA" if enc["cookie"][-2:] != "AA" else "BB")}
    with pytest.raises(InvalidToken):
        secretbox.decrypt_options(tampered)


def test_decrypt_wrong_key_raises():
    enc = secretbox.encrypt_options({"cookie": "session=abc"})
    orig = cfg.settings.JWT_SECRET
    cfg.settings.JWT_SECRET = "a-different-strong-secret-value-length-32ch"
    try:
        with pytest.raises(InvalidToken):
            secretbox.decrypt_options(enc)
    finally:
        cfg.settings.JWT_SECRET = orig


def test_mask_hides_ciphertext_and_plaintext():
    enc = secretbox.encrypt_options({"cookie": "session=abc", "scan_type": "quick"})
    masked = secretbox.mask_options(enc)
    assert masked["cookie"] == "***" and masked["scan_type"] == "quick"
    assert "enc:v1:" not in json.dumps(masked)
    # also masks legacy plaintext
    assert secretbox.mask_options({"token": "raw"}) == {"token": "***"}


def test_scalar_encrypt_decrypt_value_round_trip():
    enc = secretbox.encrypt_value("JBSWY3DPEHPK3PXP")
    assert enc.startswith("enc:v1:") and "JBSWY3DPEHPK3PXP" not in enc
    assert secretbox.decrypt_value(enc) == "JBSWY3DPEHPK3PXP"
    # idempotent + legacy/empty/non-str passthrough
    assert secretbox.encrypt_value(enc) == enc
    assert secretbox.decrypt_value("bare-plaintext") == "bare-plaintext"
    assert secretbox.encrypt_value("") == "" and secretbox.decrypt_value("") == ""
    assert secretbox.encrypt_value(None) is None


def test_scalar_decrypt_value_tampered_raises():
    enc = secretbox.encrypt_value("SECRET")
    with pytest.raises(InvalidToken):
        secretbox.decrypt_value(enc[:-2] + ("AA" if enc[-2:] != "AA" else "BB"))


def test_non_secret_options_never_transformed():
    plain = {"scan_type": "quick", "login_url": "https://x/login", "user_sel": "#u",
             "severity": "high", "username": "alice"}
    assert secretbox.encrypt_options(plain) == plain
    assert secretbox.decrypt_options(plain) == plain
    assert secretbox.mask_options(plain) == plain


# --------------------------------------------------------------------------- #
# End-to-end via the DB (create -> at-rest -> worker decrypt / update / API)
# --------------------------------------------------------------------------- #
def _ws(db, email):
    _u, _o, ws = crud.create_user_with_org(db, email, "password123")
    db.commit()
    return ws


def test_create_schedule_encrypts_at_rest_and_worker_decrypts():
    db = SessionLocal()
    try:
        ws = _ws(db, "sched-create@example.com")
        sched = crud.create_schedule(
            db, workspace_id=ws.id, tool="auth_crawl", target="https://app.example.com",
            cron="0 0 * * *",
            options={"cookie": "session=SECRETvalue", "auth_header": "Bearer TOPSECRET",
                     "login_url": "https://app.example.com/login", "user_sel": "#u"},
            enabled=True, created_by=None,
        )
        db.commit()
        db.refresh(sched)
        stored = sched.options
        # at rest: ciphertext, no plaintext anywhere; non-secret preserved
        assert stored["cookie"].startswith("enc:v1:")
        assert stored["auth_header"].startswith("enc:v1:")
        assert stored["login_url"] == "https://app.example.com/login" and stored["user_sel"] == "#u"
        assert "SECRETvalue" not in json.dumps(stored) and "TOPSECRET" not in json.dumps(stored)
        # the exact call the worker makes before building the scan job -> plaintext
        used = secretbox.decrypt_options(stored)
        assert used["cookie"] == "session=SECRETvalue"
        assert used["auth_header"] == "Bearer TOPSECRET"
        assert used["login_url"] == "https://app.example.com/login"
    finally:
        db.close()


def test_toggle_update_preserves_encrypted_options():
    db = SessionLocal()
    try:
        ws = _ws(db, "sched-toggle@example.com")
        sched = crud.create_schedule(
            db, workspace_id=ws.id, tool="auth_crawl", target="https://x", cron="0 0 * * *",
            options={"cookie": "session=abc"}, enabled=True, created_by=None,
        )
        db.commit()
        ct = sched.options["cookie"]
        assert ct.startswith("enc:v1:")
        crud.set_schedule_enabled(db, sched, False)   # the only "update" path
        db.commit()
        db.refresh(sched)
        # options untouched by the toggle and still decryptable
        assert sched.options["cookie"] == ct and sched.enabled is False
        assert secretbox.decrypt_options(sched.options)["cookie"] == "session=abc"
    finally:
        db.close()


def test_worker_rejects_schedule_when_key_rotated():
    db = SessionLocal()
    try:
        ws = _ws(db, "sched-rotate@example.com")
        sched = crud.create_schedule(
            db, workspace_id=ws.id, tool="auth_crawl", target="https://x", cron="0 0 * * *",
            options={"cookie": "session=abc"}, enabled=True, created_by=None,
        )
        db.commit()
        stored = dict(sched.options)
        orig = cfg.settings.JWT_SECRET
        cfg.settings.JWT_SECRET = "rotated-strong-secret-value-of-length-32ch"
        try:
            with pytest.raises(InvalidToken):     # worker catches this -> rejects the leg
                secretbox.decrypt_options(stored)
        finally:
            cfg.settings.JWT_SECRET = orig
    finally:
        db.close()


def test_schedule_out_masks_secret_options():
    db = SessionLocal()
    try:
        ws = _ws(db, "sched-out@example.com")
        sched = crud.create_schedule(
            db, workspace_id=ws.id, tool="auth_crawl", target="https://x", cron="0 0 * * *",
            options={"cookie": "session=abc", "token": "eyJ.a.b", "scan_type": "quick"},
            enabled=True, created_by=None,
        )
        db.commit()
        out = schemas.ScheduleOut.model_validate(sched)
        assert out.options["cookie"] == "***" and out.options["token"] == "***"
        assert out.options["scan_type"] == "quick"
        blob = json.dumps(out.options)
        assert "enc:v1:" not in blob and "abc" not in blob and "eyJ.a.b" not in blob
    finally:
        db.close()

"""Phase 5: SSO — JIT provisioning core + no-network OIDC helpers + callback.

``sso.provision_sso_user`` is the testable, network-free heart of SSO: on first
login it creates a user + org membership with the org's configured default role,
and on repeat it reuses the existing user. The OIDC helpers are exercised with
``oidc_discover``/``_requests`` monkeypatched so NO network is touched, and the
router callback is driven end-to-end with ``exchange_code``/``fetch_userinfo``
stubbed.
"""

from app import crud, sso
from app.config import settings as app_settings
from app.database import SessionLocal


# --------------------------------------------------------------------------- #
# JIT provisioning core
# --------------------------------------------------------------------------- #
def test_provision_creates_then_reuses_user():
    db = SessionLocal()
    try:
        _user, org, _ws = crud.create_user_with_org(
            db, "owner@example.com", "password123", "Owner"
        )
        db.commit()

        # First login: a new user + membership is created with the default role.
        u1 = sso.provision_sso_user(db, org, "Alice@Corp.com", "Alice")
        db.commit()
        assert u1.id is not None
        assert u1.email == "alice@corp.com"  # normalized lower-case
        m1 = crud.get_membership(db, u1.id, org.id)
        assert m1 is not None
        assert m1.role == "viewer"  # org.sso_default_role default

        # Repeat login: the SAME user is reused (no duplicate account/membership).
        u2 = sso.provision_sso_user(db, org, "alice@corp.com")
        db.commit()
        assert u2.id == u1.id
        assert crud.get_user_by_email(db, "alice@corp.com").id == u1.id
    finally:
        db.close()


def test_provision_honors_org_sso_default_role():
    db = SessionLocal()
    try:
        _user, org, _ws = crud.create_user_with_org(
            db, "owner2@example.com", "password123", "Owner2"
        )
        org.sso_default_role = "analyst"
        db.add(org)
        db.commit()

        u = sso.provision_sso_user(db, org, "bob@corp.com", "Bob")
        db.commit()
        m = crud.get_membership(db, u.id, org.id)
        assert m.role == "analyst"
    finally:
        db.close()


# --------------------------------------------------------------------------- #
# OIDC helpers — no network (discovery / userinfo monkeypatched)
# --------------------------------------------------------------------------- #
class _FakeResp:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self._payload


def test_build_auth_url_no_network(monkeypatch):
    monkeypatch.setattr(
        sso,
        "oidc_discover",
        lambda issuer, **kw: {"authorization_endpoint": "https://idp.example/authorize"},
    )
    url = sso.build_auth_url(
        {"issuer": "https://idp.example", "client_id": "cid-123"},
        state="st",
        nonce="nc",
    )
    assert url.startswith("https://idp.example/authorize?")
    assert "client_id=cid-123" in url
    assert "state=st" in url
    assert "nonce=nc" in url
    assert "response_type=code" in url


def test_fetch_userinfo_no_network(monkeypatch):
    monkeypatch.setattr(
        sso,
        "oidc_discover",
        lambda issuer, **kw: {"userinfo_endpoint": "https://idp.example/userinfo"},
    )

    class _FakeRequests:
        def get(self, url, **kw):
            return _FakeResp({"email": "Carol@Corp.com", "name": "Carol", "sub": "42"})

    monkeypatch.setattr(sso, "_requests", lambda: _FakeRequests())

    info = sso.fetch_userinfo(
        {"issuer": "https://idp.example"}, {"access_token": "at"}
    )
    assert info == {"email": "carol@corp.com", "name": "Carol", "sub": "42"}


# --------------------------------------------------------------------------- #
# End-to-end OIDC callback (double-gated, network stubbed)
# --------------------------------------------------------------------------- #
def test_oidc_callback_provisions_and_issues_tokens(client, monkeypatch):
    monkeypatch.setattr(app_settings, "SSO_ENABLED", True)
    # DEBUG => the browser-binding state cookie is non-Secure, so it rides the
    # http test client back to the callback (in production it is Secure/https).
    monkeypatch.setattr(app_settings, "DEBUG", True)

    reg = client.post(
        "/auth/register",
        json={
            "email": "owner-sso@example.com",
            "password": "password123",
            "full_name": "Owner SSO",
        },
    )
    assert reg.status_code == 201, reg.text
    payload = reg.json()
    org_id = payload["org"]["id"]
    slug = payload["org"]["slug"]
    headers = {"Authorization": f"Bearer {payload['access_token']}"}

    # Owner (admin+) enables an OIDC SsoConfig for the org.
    put = client.put(
        f"/orgs/{org_id}/sso",
        headers=headers,
        json={
            "provider": "oidc",
            "issuer": "https://idp.example",
            "client_id": "cid",
            "client_secret": "shh",
            "enabled": True,
        },
    )
    assert put.status_code == 200, put.text
    # Secrets are masked in the response.
    assert put.json()["client_secret_set"] is True
    assert "client_secret" not in put.json()

    # Begin the login: mints the single-use state record + sets the state cookie.
    # build_auth_url is stubbed so /login never touches the network (discovery).
    monkeypatch.setattr(
        sso, "build_auth_url", lambda cfg, state, nonce, **kw: "https://idp.example/authorize"
    )
    login = client.get(f"/auth/sso/{slug}/login", follow_redirects=False)
    assert login.status_code == 302
    state = login.cookies.get("reconx_oidc_state")
    assert state  # browser-binding cookie was set

    # Stub the two network calls so the callback is fully hermetic (no id_token ->
    # nonce check is a no-op; dedicated nonce cases live in test_oidc_state.py).
    monkeypatch.setattr(
        sso, "exchange_code", lambda cfg, code, **kw: {"access_token": "at"}
    )
    monkeypatch.setattr(
        sso,
        "fetch_userinfo",
        lambda cfg, tokens, **kw: {"email": "dana@corp.com", "name": "Dana", "sub": "7"},
    )

    # The cookie set at /login rides the jar back here; state param matches it.
    resp = client.get(
        f"/auth/sso/{slug}/callback",
        params={"code": "authcode", "state": state},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["access_token"]
    assert body["refresh_token"]
    assert body["user"]["email"] == "dana@corp.com"


def test_sso_login_404_when_master_switch_off(client):
    # SSO_ENABLED defaults OFF -> the whole surface 404s (existence-hiding).
    resp = client.get("/auth/sso/any-org/login")
    assert resp.status_code == 404


# --------------------------------------------------------------------------- #
# Account pre-hijacking (P1): evict-on-first-SSO-adoption.
# A password account for an email carries email_verified=False until the org's
# IdP proves ownership. The first SSO adoption of an unverified account must
# neutralize any pre-set password and revoke its sessions; verified accounts and
# repeat SSO logins are untouched; password login is never gated on the flag.
# --------------------------------------------------------------------------- #
def test_sso_adoption_of_unverified_password_account_evicts_attacker():
    """NEGATIVE / attack-closed: an attacker pre-registers victim@corp.com with a
    known password; the victim's first real SSO login evicts that foothold."""
    db = SessionLocal()
    try:
        _u, org, _ws = crud.create_user_with_org(
            db, "sso-owner1@example.com", "password123", "Owner"
        )
        db.commit()
        # Attacker plants a password account for the victim's email.
        victim, _vorg, _vws = crud.create_user_with_org(
            db, "victim@corp.com", "attacker-known-pw", "Victim"
        )
        db.commit()
        assert victim.email_verified is False           # unproven ownership
        old_hash = victim.password_hash
        old_version = victim.token_version

        # The real owner logs in via the org's SSO for the first time.
        u = sso.provision_sso_user(db, org, "victim@corp.com", "Victim")
        db.commit()

        assert u.id == victim.id                        # same account/data kept
        assert u.email_verified is True                 # now proven
        assert u.password_hash != old_hash              # attacker password reset
        assert crud.authenticate(db, "victim@corp.com", "attacker-known-pw") is None
        assert u.token_version == old_version + 1       # attacker sessions revoked
    finally:
        db.close()


def test_sso_first_login_creates_verified_user():
    """POSITIVE: an SSO-first account (no pre-existing row) is created verified."""
    db = SessionLocal()
    try:
        _u, org, _ws = crud.create_user_with_org(
            db, "sso-owner2@example.com", "password123", "Owner"
        )
        db.commit()
        u = sso.provision_sso_user(db, org, "Fresh@Corp.com", "Fresh")
        db.commit()
        assert u.id is not None
        assert u.email == "fresh@corp.com"
        assert u.email_verified is True
        assert crud.get_membership(db, u.id, org.id) is not None
    finally:
        db.close()


def test_repeat_sso_login_does_not_reset_password_or_bump_version():
    """POSITIVE: eviction is one-time; a verified account's repeat SSO login does
    not reset its password or bump its token_version (no multi-device churn)."""
    db = SessionLocal()
    try:
        _u, org, _ws = crud.create_user_with_org(
            db, "sso-owner3@example.com", "password123", "Owner"
        )
        db.commit()
        u1 = sso.provision_sso_user(db, org, "repeat@corp.com", "Repeat")
        db.commit()
        assert u1.email_verified is True
        hash_after_first = u1.password_hash
        ver_after_first = u1.token_version

        u2 = sso.provision_sso_user(db, org, "repeat@corp.com", "Repeat")
        db.commit()
        assert u2.id == u1.id
        assert u2.password_hash == hash_after_first     # unchanged
        assert u2.token_version == ver_after_first      # unchanged
        assert u2.email_verified is True
    finally:
        db.close()


def test_password_only_user_login_unaffected_by_verified_flag():
    """REGRESSION: login is NOT gated on email_verified — a password-only user
    (never touched by SSO, so email_verified stays False) still authenticates."""
    db = SessionLocal()
    try:
        user, _org, _ws = crud.create_user_with_org(
            db, "pw-only@corp.com", "goodpass123", "PwOnly"
        )
        db.commit()
        assert user.email_verified is False
        authed = crud.authenticate(db, "pw-only@corp.com", "goodpass123")
        assert authed is not None and authed.id == user.id
    finally:
        db.close()

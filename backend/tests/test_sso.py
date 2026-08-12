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

    # Stub the two network calls so the callback is fully hermetic.
    monkeypatch.setattr(
        sso, "exchange_code", lambda cfg, code, **kw: {"access_token": "at", "id_token": "it"}
    )
    monkeypatch.setattr(
        sso,
        "fetch_userinfo",
        lambda cfg, tokens, **kw: {"email": "dana@corp.com", "name": "Dana", "sub": "7"},
    )

    resp = client.get(
        f"/auth/sso/{slug}/callback",
        params={"code": "authcode", "state": f"{slug}:random"},
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

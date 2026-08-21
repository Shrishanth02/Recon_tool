"""OIDC state/nonce hardening — CSRF + replay protection on the SSO login flow.

Each OIDC ``/login`` mints a server-side :class:`app.models.SsoState` (single-use,
org-bound, short-lived) and sets a matching httpOnly ``reconx_oidc_state`` cookie.
The callback must present BOTH — a cookie that equals the returned ``state`` (binds
the round-trip to the initiating browser) AND a live/unused record for the right
org — and only then verifies the id_token ``nonce``. Anything missing, tampered,
expired, replayed, or cross-tenant is rejected, and NO tokens are ever issued on
failure. These tests cover exactly those cases.

The browser flow is exercised through the TestClient's cookie jar. ``DEBUG`` is
forced on so the state cookie is non-Secure and therefore rides the http test
transport (in production it is ``Secure`` and only travels over https).
"""

import base64
import json
from datetime import datetime, timedelta, timezone

from app import models, sso
from app.config import settings as app_settings
from app.database import SessionLocal

_COOKIE = "reconx_oidc_state"


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _mk_id_token(claims: dict) -> str:
    """A compact JWS whose payload carries ``claims`` (signature is not verified).

    The nonce guard decodes the payload of the id_token returned by the (trusted,
    TLS) token endpoint; it does not re-verify the IdP signature here, so a plain
    base64url payload with a dummy header/signature is a faithful stand-in.
    """
    payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
    return f"eyJhbGciOiJSUzI1NiJ9.{payload}.sig"


def _enable_oidc(client, monkeypatch, *, email, org_name=None):
    """Register a user, enable an OIDC SsoConfig, and make /login network-free.

    Returns ``(slug, org_id)``. ``build_auth_url`` is stubbed so /login never hits
    discovery; individual tests stub ``exchange_code``/``fetch_userinfo``.
    """
    monkeypatch.setattr(app_settings, "SSO_ENABLED", True)
    monkeypatch.setattr(app_settings, "DEBUG", True)  # non-Secure cookie for http tests
    monkeypatch.setattr(
        sso, "build_auth_url", lambda cfg, state, nonce, **kw: "https://idp.example/authorize"
    )
    body = {"email": email, "password": "password123", "full_name": "SSO User"}
    if org_name:
        body["org_name"] = org_name
    reg = client.post("/auth/register", json=body)
    assert reg.status_code == 201, reg.text
    p = reg.json()
    org_id, slug = p["org"]["id"], p["org"]["slug"]
    headers = {"Authorization": f"Bearer {p['access_token']}"}
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
    return slug, org_id


def _login(client, slug) -> str:
    """Drive OIDC /login and return the minted state id (also now in the jar)."""
    r = client.get(f"/auth/sso/{slug}/login", follow_redirects=False)
    assert r.status_code == 302, r.text
    state = r.cookies.get(_COOKIE)
    assert state
    return state


def _cookie(client, state):
    """Clear the jar and return headers presenting exactly ``state`` as the cookie.

    Seeding httpx's jar for the dotless ``testserver`` host is unreliable
    (http.cookiejar special-cases dotless domains), so we send the browser-binding
    cookie as an explicit header. The natural server-set jar round-trip is covered
    separately in ``test_sso.py::test_oidc_callback_provisions_and_issues_tokens``.
    """
    client.cookies.clear()
    return {"Cookie": f"{_COOKIE}={state}"}


def _stub_exchange(monkeypatch, *, id_token=None, email="dana@corp.com"):
    """Stub the token exchange + userinfo. With no id_token the nonce check is a no-op."""
    tokens = {"access_token": "at"}
    if id_token is not None:
        tokens["id_token"] = id_token
    monkeypatch.setattr(sso, "exchange_code", lambda cfg, code, **kw: tokens)
    monkeypatch.setattr(
        sso, "fetch_userinfo",
        lambda cfg, t, **kw: {"email": email, "name": "Dana", "sub": "7"},
    )


def _nonce_for(state) -> str:
    db = SessionLocal()
    try:
        return db.query(models.SsoState).filter_by(state_id=state).one().nonce
    finally:
        db.close()


def _expire(state):
    db = SessionLocal()
    try:
        rec = db.query(models.SsoState).filter_by(state_id=state).one()
        rec.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        db.add(rec)
        db.commit()
    finally:
        db.close()


# --------------------------------------------------------------------------- #
# 1. Valid state -> tokens issued
# --------------------------------------------------------------------------- #
def test_valid_state_issues_tokens(client, monkeypatch):
    slug, _org = _enable_oidc(client, monkeypatch, email="a@example.com")
    state = _login(client, slug)
    _stub_exchange(monkeypatch)  # no id_token -> nonce check skipped
    r = client.get(f"/auth/sso/{slug}/callback", params={"code": "c", "state": state})
    assert r.status_code == 200, r.text
    b = r.json()
    assert b["access_token"] and b["refresh_token"]
    assert b["user"]["email"] == "dana@corp.com"


# --------------------------------------------------------------------------- #
# 2. Missing state (and no cookie) -> rejected, no tokens
# --------------------------------------------------------------------------- #
def test_missing_state_rejected(client, monkeypatch):
    slug, _org = _enable_oidc(client, monkeypatch, email="b@example.com")
    _login(client, slug)
    _stub_exchange(monkeypatch)
    client.cookies.clear()
    r = client.get(f"/auth/sso/{slug}/callback", params={"code": "c"})  # no state
    assert r.status_code == 400
    assert "access_token" not in r.json()


# --------------------------------------------------------------------------- #
# 3. Missing cookie (state present) -> login-CSRF guard rejects
# --------------------------------------------------------------------------- #
def test_missing_cookie_rejected(client, monkeypatch):
    slug, _org = _enable_oidc(client, monkeypatch, email="k@example.com")
    state = _login(client, slug)
    _stub_exchange(monkeypatch)
    client.cookies.clear()  # a live server record exists, but this browser has no cookie
    r = client.get(f"/auth/sso/{slug}/callback", params={"code": "c", "state": state})
    assert r.status_code == 400
    assert "access_token" not in r.json()


# --------------------------------------------------------------------------- #
# 4. Tampered state (cookie != returned state) -> rejected
# --------------------------------------------------------------------------- #
def test_tampered_state_rejected(client, monkeypatch):
    slug, _org = _enable_oidc(client, monkeypatch, email="c@example.com")
    state = _login(client, slug)  # jar holds the real cookie
    _stub_exchange(monkeypatch)
    r = client.get(
        f"/auth/sso/{slug}/callback", params={"code": "c", "state": state + "x"}
    )
    assert r.status_code == 400
    assert "access_token" not in r.json()


# --------------------------------------------------------------------------- #
# 5. Expired state -> rejected
# --------------------------------------------------------------------------- #
def test_expired_state_rejected(client, monkeypatch):
    slug, _org = _enable_oidc(client, monkeypatch, email="d@example.com")
    state = _login(client, slug)
    _expire(state)  # age out the server record; the cookie is untouched
    _stub_exchange(monkeypatch)
    r = client.get(f"/auth/sso/{slug}/callback", params={"code": "c", "state": state})
    assert r.status_code == 400
    assert "access_token" not in r.json()


# --------------------------------------------------------------------------- #
# 6. Replayed state (single use) -> second callback rejected
# --------------------------------------------------------------------------- #
def test_replayed_state_rejected(client, monkeypatch):
    slug, _org = _enable_oidc(client, monkeypatch, email="e@example.com")
    state = _login(client, slug)
    _stub_exchange(monkeypatch)
    first = client.get(f"/auth/sso/{slug}/callback", params={"code": "c", "state": state})
    assert first.status_code == 200, first.text
    # Success cleared the cookie; re-present it so the SINGLE-USE record (not the
    # missing cookie) is what rejects the replay.
    r = client.get(
        f"/auth/sso/{slug}/callback",
        params={"code": "c", "state": state},
        headers=_cookie(client, state),
    )
    assert r.status_code == 400
    assert "access_token" not in r.json()


# --------------------------------------------------------------------------- #
# 7. State bound to org A cannot authenticate into org B
# --------------------------------------------------------------------------- #
def test_state_bound_to_wrong_org_rejected(client, monkeypatch):
    slug_a, _a = _enable_oidc(client, monkeypatch, email="fa@example.com", org_name="Org A")
    slug_b, _b = _enable_oidc(client, monkeypatch, email="fb@example.com", org_name="Org B")
    state_a = _login(client, slug_a)  # minted for org A
    _stub_exchange(monkeypatch)

    # Present org A's state (+cookie) at org B's callback -> tenant mismatch.
    wrong = client.get(
        f"/auth/sso/{slug_b}/callback",
        params={"code": "c", "state": state_a},
        headers=_cookie(client, state_a),
    )
    assert wrong.status_code == 400
    assert "access_token" not in wrong.json()

    # The cross-tenant probe did NOT burn org A's state: it still works at its own
    # callback, so a legitimate user is never denied by someone else's mistake.
    ok = client.get(
        f"/auth/sso/{slug_a}/callback",
        params={"code": "c", "state": state_a},
        headers=_cookie(client, state_a),
    )
    assert ok.status_code == 200, ok.text


# --------------------------------------------------------------------------- #
# 8. Nonce mismatch -> rejected; nonce match -> accepted
# --------------------------------------------------------------------------- #
def test_nonce_mismatch_rejected(client, monkeypatch):
    slug, _org = _enable_oidc(client, monkeypatch, email="g@example.com")
    state = _login(client, slug)
    _stub_exchange(monkeypatch, id_token=_mk_id_token({"nonce": "not-the-real-one"}))
    r = client.get(f"/auth/sso/{slug}/callback", params={"code": "c", "state": state})
    assert r.status_code == 400
    assert "access_token" not in r.json()


def test_nonce_match_accepted(client, monkeypatch):
    slug, _org = _enable_oidc(client, monkeypatch, email="h@example.com")
    state = _login(client, slug)
    _stub_exchange(monkeypatch, id_token=_mk_id_token({"nonce": _nonce_for(state)}))
    r = client.get(f"/auth/sso/{slug}/callback", params={"code": "c", "state": state})
    assert r.status_code == 200, r.text
    assert r.json()["access_token"]


# --------------------------------------------------------------------------- #
# 9. A failed callback issues no tokens AND still burns the state (single use is
#    locked in before any token work, so a transient failure is not retryable).
# --------------------------------------------------------------------------- #
def test_failed_callback_issues_no_tokens(client, monkeypatch):
    slug, _org = _enable_oidc(client, monkeypatch, email="i@example.com")
    state = _login(client, slug)

    def _boom(cfg, code, **kw):
        raise sso.SsoError("token endpoint unavailable")

    monkeypatch.setattr(sso, "exchange_code", _boom)
    r = client.get(f"/auth/sso/{slug}/callback", params={"code": "c", "state": state})
    assert r.status_code == 400
    body = r.json()
    assert "access_token" not in body and "refresh_token" not in body

    # Even though the exchange failed, the state was consumed first -> no retry.
    _stub_exchange(monkeypatch)
    retry = client.get(
        f"/auth/sso/{slug}/callback",
        params={"code": "c", "state": state},
        headers=_cookie(client, state),
    )
    assert retry.status_code == 400
    assert "access_token" not in retry.json()


# --------------------------------------------------------------------------- #
# 10. Separate/concurrent login transactions do not interfere
# --------------------------------------------------------------------------- #
def test_separate_transactions_do_not_interfere(client, monkeypatch):
    slug, _org = _enable_oidc(client, monkeypatch, email="j@example.com")
    state1 = _login(client, slug)
    state2 = _login(client, slug)
    assert state1 != state2
    _stub_exchange(monkeypatch)

    # Consume the second transaction first...
    r2 = client.get(
        f"/auth/sso/{slug}/callback",
        params={"code": "c", "state": state2},
        headers=_cookie(client, state2),
    )
    assert r2.status_code == 200, r2.text

    # ...the first is untouched and still authenticates.
    r1 = client.get(
        f"/auth/sso/{slug}/callback",
        params={"code": "c", "state": state1},
        headers=_cookie(client, state1),
    )
    assert r1.status_code == 200, r1.text


# --------------------------------------------------------------------------- #
# 11. Fixed-redirect callback (no slug — the production redirect_uri) recovers the
#     tenant from the state RECORD, never from the URL, and authenticates into it.
# --------------------------------------------------------------------------- #
def test_compat_callback_recovers_org_from_state(client, monkeypatch):
    slug, org_id = _enable_oidc(
        client, monkeypatch, email="m@example.com", org_name="Compat Org"
    )
    state = _login(client, slug)  # cookie rides the natural jar to /auth/sso/callback
    _stub_exchange(monkeypatch, email="compat-user@corp.com")
    r = client.get("/auth/sso/callback", params={"code": "c", "state": state})
    assert r.status_code == 200, r.text
    b = r.json()
    assert b["access_token"] and b["refresh_token"]
    assert b["org"]["id"] == org_id  # tenant recovered from the state record
    assert b["user"]["email"] == "compat-user@corp.com"

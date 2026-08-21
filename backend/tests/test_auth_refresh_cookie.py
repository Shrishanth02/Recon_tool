"""STEP 4: refresh token delivered via an httpOnly cookie (out of localStorage).

The refresh token is the long-lived (14-day) credential. Moving it into an
httpOnly, Secure, SameSite=Strict cookie scoped to ``/auth/refresh`` means an XSS
on the SPA origin can no longer read or exfiltrate it. Access tokens stay Bearer.

Cookie tests force ``DEBUG=True`` so the cookie is non-Secure and therefore rides
the http test transport (in production it is ``Secure`` and only travels https),
mirroring the OIDC-state cookie tests. The CSRF-origin test instead presents the
cookie via an explicit header (so it is sent under DEBUG=False, where the Origin
check is active).
"""

import uuid

from app.config import settings as app_settings

_COOKIE = "reconx_refresh"


def _register(client, monkeypatch_debug=None):
    email = f"rc-{uuid.uuid4().hex[:10]}@example.com"
    reg = client.post(
        "/auth/register",
        json={"email": email, "password": "password123", "full_name": "RC"},
    )
    assert reg.status_code == 201, reg.text
    return reg


def test_login_sets_httponly_refresh_cookie(client, monkeypatch):
    monkeypatch.setattr(app_settings, "DEBUG", True)
    reg = _register(client)
    set_cookie = reg.headers.get("set-cookie", "").lower()
    assert f"{_COOKIE}=" in set_cookie
    assert "httponly" in set_cookie
    assert "samesite=strict" in set_cookie
    assert "path=/auth" in set_cookie
    # Body still carries the refresh token for the harness/legacy clients.
    assert reg.json()["refresh_token"]


def test_refresh_via_cookie_returns_access_only(client, monkeypatch):
    monkeypatch.setattr(app_settings, "DEBUG", True)  # non-Secure cookie rides http
    _register(client)
    # The login cookie is in the jar (path=/auth/refresh); send NO body.
    r = client.post("/auth/refresh")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["access_token"]
    assert body.get("refresh_token") is None  # refresh is in the cookie, NOT the body
    assert f"{_COOKIE}=" in r.headers.get("set-cookie", "")  # rotated cookie re-set


def test_refresh_via_body_still_works_for_legacy_clients(client):
    # DEBUG off -> Secure cookie not sent over http; clear the jar to be sure.
    reg = _register(client)
    refresh_token = reg.json()["refresh_token"]
    client.cookies.clear()
    r = client.post("/auth/refresh", json={"refresh_token": refresh_token})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["access_token"] and body["refresh_token"]  # body path returns both


def test_refresh_cookie_path_enforces_origin_allowlist(client, monkeypatch):
    # Force DEBUG off (a local .env may set it on) so the Origin CSRF check is
    # active. Present the cookie explicitly (sent despite Secure) + a foreign
    # Origin -> rejected.
    monkeypatch.setattr(app_settings, "DEBUG", False)
    reg = _register(client)
    refresh_token = reg.json()["refresh_token"]
    client.cookies.clear()
    bad = client.post(
        "/auth/refresh",
        headers={"Cookie": f"{_COOKIE}={refresh_token}", "Origin": "https://evil.example"},
    )
    assert bad.status_code == 403
    # An allowed app origin proceeds.
    ok = client.post(
        "/auth/refresh",
        headers={"Cookie": f"{_COOKIE}={refresh_token}", "Origin": "http://localhost:5173"},
    )
    assert ok.status_code == 200, ok.text


def test_logout_all_delivers_refresh_only_via_cookie(client, auth, monkeypatch):
    monkeypatch.setattr(app_settings, "DEBUG", True)
    r = client.post("/auth/logout-all", headers=auth["headers"])
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["access_token"]
    assert body.get("refresh_token") is None  # refresh only in the cookie
    assert f"{_COOKIE}=" in r.headers.get("set-cookie", "")


def test_logout_clears_cookie_and_revokes_family(client, monkeypatch):
    monkeypatch.setattr(app_settings, "DEBUG", True)
    reg = _register(client)
    refresh_token = reg.json()["refresh_token"]
    # The login cookie (path=/auth) is sent to /auth/logout.
    r = client.post("/auth/logout")
    assert r.status_code == 204
    assert f"{_COOKIE}=" in r.headers.get("set-cookie", "")  # a clearing Set-Cookie
    # The session family was revoked -> the old refresh token is now dead.
    client.cookies.clear()
    dead = client.post("/auth/refresh", json={"refresh_token": refresh_token})
    assert dead.status_code == 401

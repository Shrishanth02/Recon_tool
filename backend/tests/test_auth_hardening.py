"""STEP 2 — auth/session/SSO hardening regression tests.

Covers SAML (cert-less config rejected; unsigned assertions refused in prod),
JWT revocation fail-closed on every auth surface, refresh-token rotation +
replay detection, and the owner/RBAC boundary. Tenant isolation is re-checked.
"""

import base64
import types

import pytest

from app import security, sso
from app.config import settings as app_settings


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _forged_saml(email: str = "attacker@evil.test") -> str:
    xml = (
        '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
        'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saml:Assertion>'
        f'<saml:Subject><saml:NameID>{email}</saml:NameID></saml:Subject>'
        "</saml:Assertion></samlp:Response>"
    )
    return base64.b64encode(xml.encode()).decode()


def _add_member(client, owner, email, role):
    return client.post(
        f"/orgs/{owner['org_id']}/members",
        headers=owner["headers"],
        json={"email": email, "role": role},
    )


def _org_slug(client, ctx):
    me = client.get("/auth/me", headers=ctx["headers"]).json()
    return me["orgs"][0]["slug"]


# --------------------------------------------------------------------------- #
# 1. SAML security
# --------------------------------------------------------------------------- #
def test_saml_config_without_cert_cannot_be_enabled(client, auth):
    r = client.put(
        f"/orgs/{auth['org_id']}/sso",
        headers=auth["headers"],
        json={"provider": "saml", "enabled": True},
    )
    assert r.status_code == 422
    assert "certificate" in r.json()["detail"].lower()


def test_saml_config_with_cert_can_be_enabled(client, auth):
    r = client.put(
        f"/orgs/{auth['org_id']}/sso",
        headers=auth["headers"],
        json={"provider": "saml", "enabled": True, "x509_cert": "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"},
    )
    assert r.status_code == 200, r.text


def test_parse_saml_refuses_unsigned_in_production(monkeypatch):
    monkeypatch.setattr(app_settings, "DEBUG", False)
    cfg = types.SimpleNamespace(x509_cert=None)
    with pytest.raises(sso.SsoError):
        sso.parse_saml_response(cfg, _forged_saml())


def test_parse_saml_with_cert_never_trusts_unwired_scaffold(monkeypatch):
    monkeypatch.setattr(app_settings, "DEBUG", False)
    cfg = types.SimpleNamespace(x509_cert="-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----")
    with pytest.raises(sso.SsoError):
        sso.parse_saml_response(cfg, _forged_saml())


def test_parse_saml_unsigned_allowed_only_in_debug(monkeypatch):
    monkeypatch.setattr(app_settings, "DEBUG", True)
    cfg = types.SimpleNamespace(x509_cert=None)
    identity = sso.parse_saml_response(cfg, _forged_saml("dev@example.com"))
    assert identity["email"] == "dev@example.com"  # test-only path


def test_saml_acs_forged_assertion_issues_no_tokens(client, auth, monkeypatch):
    # A valid (cert-bearing) enabled SAML config, but a forged assertion must NOT
    # mint tokens — the cert scaffold refuses signature-less trust.
    slug = _org_slug(client, auth)
    assert client.put(
        f"/orgs/{auth['org_id']}/sso", headers=auth["headers"],
        json={"provider": "saml", "enabled": True,
              "x509_cert": "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"},
    ).status_code == 200
    monkeypatch.setattr(app_settings, "SSO_ENABLED", True)
    monkeypatch.setattr(app_settings, "DEBUG", False)
    resp = client.post(f"/auth/sso/{slug}/acs", json={"SAMLResponse": _forged_saml()})
    assert resp.status_code == 400
    assert "access_token" not in resp.json()


# --------------------------------------------------------------------------- #
# 2. JWT revocation fail-closed (also see test_revocation.py)
# --------------------------------------------------------------------------- #
def test_get_principal_fail_closed_after_revocation(client, auth):
    # /tools uses get_principal — which previously skipped the ver check.
    assert client.get("/tools", headers=auth["headers"]).status_code == 200
    client.post("/auth/logout-all", headers=auth["headers"])
    assert client.get("/tools", headers=auth["headers"]).status_code == 401


def test_ws_fail_closed_after_revocation(client, auth):
    old = auth["access_token"]
    # The token is valid pre-revocation (HTTP path).
    assert client.get("/auth/me", headers=auth["headers"]).status_code == 200
    client.post("/auth/logout-all", headers=auth["headers"])  # bump token_version
    # After revocation the WS auth rejects the now-stale token (accept -> error).
    with client.websocket_connect(f"/ws/scan?token={old}") as ws:
        msg = ws.receive_json()
    assert msg["type"] == "error" and "authentication" in msg["data"].lower()


# --------------------------------------------------------------------------- #
# 3. Refresh-token rotation + replay detection
# --------------------------------------------------------------------------- #
def test_refresh_rotates_and_returns_new_token(client, auth):
    r = client.post("/auth/refresh", json={"refresh_token": auth["refresh_token"]})
    assert r.status_code == 200
    d = r.json()
    assert d["refresh_token"] and d["refresh_token"] != auth["refresh_token"]


def test_rotated_old_token_is_consumed(client, auth):
    old = auth["refresh_token"]
    new = client.post("/auth/refresh", json={"refresh_token": old}).json()["refresh_token"]
    # the successor still works...
    assert client.post("/auth/refresh", json={"refresh_token": new}).status_code == 200
    # ...but replaying the consumed `old` is rejected.
    assert client.post("/auth/refresh", json={"refresh_token": old}).status_code == 401


def test_refresh_reuse_revokes_the_whole_family(client, auth):
    old = auth["refresh_token"]
    new = client.post("/auth/refresh", json={"refresh_token": old}).json()["refresh_token"]
    # Replay the consumed token -> reuse detected -> family revoked.
    reuse = client.post("/auth/refresh", json={"refresh_token": old})
    assert reuse.status_code == 401
    assert "reuse" in reuse.json()["detail"].lower()
    # The successor (same family) is now dead too — the theft is contained.
    assert client.post("/auth/refresh", json={"refresh_token": new}).status_code == 401


def test_logout_all_revokes_refresh_tokens(client, auth):
    old = auth["refresh_token"]
    assert client.post("/auth/logout-all", headers=auth["headers"]).status_code == 200
    assert client.post("/auth/refresh", json={"refresh_token": old}).status_code == 401


def test_refresh_without_jti_is_rejected(client, auth):
    # A refresh token minted without a jti (non-rotatable) is refused fail-closed.
    tok = security.create_refresh_token(auth["user_id"], token_version=0)
    assert "refresh_token" not in client.post("/auth/refresh", json={"refresh_token": tok}).json()
    assert client.post("/auth/refresh", json={"refresh_token": tok}).status_code == 401


def test_concurrent_refresh_of_same_token_no_double_spend(client, auth):
    import threading
    old = auth["refresh_token"]
    results: list[int] = []
    lock = threading.Lock()

    def worker():
        r = client.post("/auth/refresh", json={"refresh_token": old})
        with lock:
            results.append(r.status_code)

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # A single refresh token can be spent at most once (the atomic claim / replay
    # check prevents two live successors); the loser is rejected.
    assert results.count(200) <= 1, results
    assert any(s == 401 for s in results), results


# --------------------------------------------------------------------------- #
# 4. Owner / RBAC boundary
# --------------------------------------------------------------------------- #
def test_admin_cannot_demote_or_remove_owner(client, auth, make_user):
    org = auth["org_id"]
    admin = make_user()
    owner2 = make_user()
    assert _add_member(client, auth, admin["email"], "admin").status_code == 201
    assert _add_member(client, auth, owner2["email"], "owner").status_code == 201
    # admin -> demote owner2 : 403
    assert client.patch(
        f"/orgs/{org}/members/{owner2['user_id']}",
        headers=admin["headers"], json={"role": "viewer"},
    ).status_code == 403
    # admin -> remove owner2 : 403
    assert client.delete(
        f"/orgs/{org}/members/{owner2['user_id']}", headers=admin["headers"]
    ).status_code == 403


def test_owner_can_manage_owner_but_last_owner_protected(client, auth, make_user):
    org = auth["org_id"]
    owner2 = make_user()
    assert _add_member(client, auth, owner2["email"], "owner").status_code == 201
    # owner demotes the OTHER owner (2 -> 1) : allowed
    assert client.patch(
        f"/orgs/{org}/members/{owner2['user_id']}",
        headers=auth["headers"], json={"role": "admin"},
    ).status_code == 200
    # auth is now the LAST owner; self-demotion : 400
    assert client.patch(
        f"/orgs/{org}/members/{auth['user_id']}",
        headers=auth["headers"], json={"role": "admin"},
    ).status_code == 400


def test_admin_can_manage_lower_ranked_members(client, auth, make_user):
    org = auth["org_id"]
    admin = make_user()
    viewer = make_user()
    _add_member(client, auth, admin["email"], "admin")
    _add_member(client, auth, viewer["email"], "viewer")
    # legitimate: admin promotes viewer -> analyst
    assert client.patch(
        f"/orgs/{org}/members/{viewer['user_id']}",
        headers=admin["headers"], json={"role": "analyst"},
    ).status_code == 200
    # legitimate: admin removes the lower-ranked member
    assert client.delete(
        f"/orgs/{org}/members/{viewer['user_id']}", headers=admin["headers"]
    ).status_code == 200


def test_admin_cannot_grant_owner(client, auth, make_user):
    org = auth["org_id"]
    admin = make_user()
    viewer = make_user()
    _add_member(client, auth, admin["email"], "admin")
    _add_member(client, auth, viewer["email"], "viewer")
    assert client.patch(
        f"/orgs/{org}/members/{viewer['user_id']}",
        headers=admin["headers"], json={"role": "owner"},
    ).status_code == 403


def test_rbac_tenant_isolation_preserved(client, auth, make_user):
    # A user from a DIFFERENT org cannot mutate members of auth's org.
    outsider = make_user()
    victim = make_user()
    _add_member(client, auth, victim["email"], "viewer")
    r = client.patch(
        f"/orgs/{auth['org_id']}/members/{victim['user_id']}",
        headers=outsider["headers"], json={"role": "admin"},
    )
    assert r.status_code == 403

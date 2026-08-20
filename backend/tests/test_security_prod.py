"""End-to-end security regression tests — production hardening (2026-08).

Locks in the fixes from the pre-sale security audit so they cannot silently
regress:

* SSRF / egress: netguard blocks the cloud-metadata endpoint on the emulate path.
* The global ``*`` scope authorizes any target BUT does NOT bypass netguard.
* Argument-injection: option-like targets (leading ``-``) are refused by the
  scanner target sanitizers.
* Role-gating: only admins may create/delete notification channels (exfil sink);
  only owners may grant the ``owner`` role.
* Auth: a JWT signed with the wrong secret is rejected; the app refuses to boot
  with the insecure dev secret in a non-DEBUG (production) environment.
"""

import os
import subprocess
import sys

import jwt
import pytest

from app import scope as scope_mod
from app.scanners import base as scanner_base

METADATA_IP = "169.254.169.254"


def _add_member(client, auth, email, role):
    r = client.post(
        f"/orgs/{auth['org_id']}/members",
        headers=auth["headers"],
        json={"email": email, "role": role},
    )
    assert r.status_code == 201, r.text
    return r.json()


# --------------------------------------------------------------------------- #
# SSRF / egress safety
# --------------------------------------------------------------------------- #
def test_emulate_blocks_cloud_metadata(client, auth):
    """netguard must reject the cloud-metadata endpoint on a scanning path."""
    r = client.post(
        f"/workspaces/{auth['ws_id']}/emulate",
        headers=auth["headers"],
        json={"target": METADATA_IP},
    )
    assert r.status_code == 403, r.text


def test_wildcard_scope_does_not_bypass_netguard(client, auth):
    """Even with scope='*' (authorize anything), netguard still blocks metadata."""
    up = client.put(
        f"/workspaces/{auth['ws_id']}/scope",
        headers=auth["headers"],
        json={"scope": ["*"]},
    )
    assert up.status_code == 200, up.text

    r = client.post(
        f"/workspaces/{auth['ws_id']}/emulate",
        headers=auth["headers"],
        json={"target": METADATA_IP},
    )
    assert r.status_code == 403, r.text


def test_scope_wildcard_authorizes_any_target():
    for t in ("example.com", "10.1.2.3", "evil.attacker.com", "8.8.8.8"):
        ok, _reason = scope_mod.check(t, ["*"])
        assert ok, f"{t} should be authorized by a '*' scope"


# --------------------------------------------------------------------------- #
# Argument-injection defense (scanner target sanitizers)
# --------------------------------------------------------------------------- #
def test_scanner_rejects_optionlike_target():
    for bad in ("-oX", "--script=evil", "-sV"):
        with pytest.raises(ValueError):
            scanner_base.clean_target(bad)
    with pytest.raises(ValueError):
        scanner_base.ensure_url("--data=x")
    # Legitimate targets are unaffected.
    assert scanner_base.clean_target("http://example.com/path") == "example.com"
    assert scanner_base.ensure_url("example.com") == "https://example.com"


# --------------------------------------------------------------------------- #
# Role-gating: notification channels (exfil sink) are admin-only
# --------------------------------------------------------------------------- #
def test_analyst_cannot_create_notification_channel(client, auth, make_user):
    analyst = make_user()
    _add_member(client, auth, analyst["email"], "analyst")
    r = client.post(
        f"/orgs/{auth['org_id']}/notifications",
        headers=analyst["headers"],
        json={"ctype": "webhook", "config": {"url": "https://attacker.tld/x"}},
    )
    assert r.status_code == 403, r.text


def test_admin_can_create_notification_channel(client, auth, make_user):
    admin = make_user()
    _add_member(client, auth, admin["email"], "admin")
    r = client.post(
        f"/orgs/{auth['org_id']}/notifications",
        headers=admin["headers"],
        json={"ctype": "webhook", "config": {"url": "https://hooks.example/ok"}},
    )
    assert r.status_code == 201, r.text


# --------------------------------------------------------------------------- #
# Role-hierarchy: only owners may grant the owner role
# --------------------------------------------------------------------------- #
def test_admin_cannot_grant_owner_role(client, auth, make_user):
    admin = make_user()
    _add_member(client, auth, admin["email"], "admin")
    victim = make_user()
    r = client.post(
        f"/orgs/{auth['org_id']}/members",
        headers=admin["headers"],
        json={"email": victim["email"], "role": "owner"},
    )
    assert r.status_code == 403, r.text


def test_owner_can_grant_owner_role(client, auth, make_user):
    newuser = make_user()
    r = client.post(
        f"/orgs/{auth['org_id']}/members",
        headers=auth["headers"],
        json={"email": newuser["email"], "role": "owner"},
    )
    assert r.status_code == 201, r.text


# --------------------------------------------------------------------------- #
# Auth: forged token rejection + prod boot guard
# --------------------------------------------------------------------------- #
def test_forged_jwt_is_rejected(client, auth):
    forged = jwt.encode(
        {"sub": "1", "type": "access"}, "attacker-guessed-secret", algorithm="HS256"
    )
    r = client.get(
        f"/orgs/{auth['org_id']}/members",
        headers={"Authorization": f"Bearer {forged}"},
    )
    assert r.status_code == 401, r.text


def test_app_refuses_to_boot_with_insecure_secret_in_prod(tmp_path):
    """The config module must RAISE (not warn) on the dev secret when DEBUG=false."""
    env = dict(
        os.environ,
        DEBUG="false",
        JWT_SECRET="dev-insecure-change-me",
        DATABASE_URL=f"sqlite:///{(tmp_path / 'bg.db').as_posix()}",
    )
    r = subprocess.run(
        [sys.executable, "-c", "import app.config"],
        env=env, capture_output=True, text=True, cwd=os.getcwd(),
    )
    assert r.returncode != 0, "app.config must fail to import with the insecure secret"
    assert "JWT_SECRET" in (r.stderr + r.stdout)


def test_app_boots_with_strong_secret_in_prod(tmp_path):
    env = dict(
        os.environ,
        DEBUG="false",
        JWT_SECRET="a-strong-random-secret-value-1234567890",
        DATABASE_URL=f"sqlite:///{(tmp_path / 'ok.db').as_posix()}",
    )
    r = subprocess.run(
        [sys.executable, "-c", "import app.config"],
        env=env, capture_output=True, text=True, cwd=os.getcwd(),
    )
    assert r.returncode == 0, r.stderr

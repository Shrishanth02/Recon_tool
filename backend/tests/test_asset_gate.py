"""Verified-asset authorization gate tests (:func:`crud.is_target_authorized`).

The gate is a no-op while ``settings.REQUIRE_VERIFIED_ASSET`` is off (the
default, so Phase 0/1 behavior is unchanged). When on, a target is authorized
only if each of its hosts exactly matches, or is a subdomain of, a **verified**
asset in the workspace.

The setting is toggled by monkeypatching ``app.config.settings`` — the running
app and ``crud`` both read that same singleton — so the REST ``/scan`` case
exercises the gate through the real router without any global config change.
"""


from app import crud
from app.config import settings
from app.database import SessionLocal


def _workspace_with_asset(value="example.com", verified=True):
    """Create an org/workspace and (optionally verified) asset; return (db, ws_id)."""
    db = SessionLocal()
    _user, _org, ws = crud.create_user_with_org(
        db, "asset-owner@example.com", "password123"
    )
    asset = crud.create_asset(db, ws.id, value)
    if verified:
        crud.mark_asset_verified(db, asset)
    db.commit()
    return db, ws.id


def test_authorized_when_flag_off_is_noop():
    # Default: REQUIRE_VERIFIED_ASSET is False -> everything authorized.
    assert settings.REQUIRE_VERIFIED_ASSET is False
    db, ws_id = _workspace_with_asset(verified=False)
    try:
        assert crud.is_target_authorized(db, ws_id, "anything.example.org") is True
    finally:
        db.close()


def test_verified_asset_authorizes_exact_host(monkeypatch):
    monkeypatch.setattr(settings, "REQUIRE_VERIFIED_ASSET", True)
    db, ws_id = _workspace_with_asset("example.com", verified=True)
    try:
        assert crud.is_target_authorized(db, ws_id, "example.com") is True
    finally:
        db.close()


def test_verified_asset_authorizes_subdomain(monkeypatch):
    monkeypatch.setattr(settings, "REQUIRE_VERIFIED_ASSET", True)
    db, ws_id = _workspace_with_asset("example.com", verified=True)
    try:
        assert crud.is_target_authorized(db, ws_id, "api.staging.example.com") is True
        # URL form + port are normalized to the bare host before matching.
        assert crud.is_target_authorized(db, ws_id, "https://shop.example.com:8443/x") is True
    finally:
        db.close()


def test_unrelated_host_denied(monkeypatch):
    monkeypatch.setattr(settings, "REQUIRE_VERIFIED_ASSET", True)
    db, ws_id = _workspace_with_asset("example.com", verified=True)
    try:
        assert crud.is_target_authorized(db, ws_id, "evil.com") is False
        # A lookalike suffix must not match (notexample.com endswith example.com
        # only via the dot-boundary rule, which this violates).
        assert crud.is_target_authorized(db, ws_id, "notexample.com") is False
    finally:
        db.close()


def test_unverified_asset_does_not_authorize(monkeypatch):
    monkeypatch.setattr(settings, "REQUIRE_VERIFIED_ASSET", True)
    db, ws_id = _workspace_with_asset("example.com", verified=False)
    try:
        assert crud.is_target_authorized(db, ws_id, "example.com") is False
    finally:
        db.close()


def test_no_assets_denied_when_flag_on(monkeypatch):
    monkeypatch.setattr(settings, "REQUIRE_VERIFIED_ASSET", True)
    db = SessionLocal()
    try:
        _u, _o, ws = crud.create_user_with_org(db, "empty@example.com", "password123")
        db.commit()
        assert crud.is_target_authorized(db, ws.id, "example.com") is False
    finally:
        db.close()


def test_list_target_requires_every_host_authorized(monkeypatch):
    monkeypatch.setattr(settings, "REQUIRE_VERIFIED_ASSET", True)
    db, ws_id = _workspace_with_asset("example.com", verified=True)
    try:
        assert crud.is_target_authorized(db, ws_id, "a.example.com b.example.com") is True
        # One out-of-scope host in the list fails the whole target.
        assert crud.is_target_authorized(db, ws_id, "a.example.com evil.com") is False
    finally:
        db.close()


# --------------------------------------------------------------------------- #
# REST /scan enforces the gate when the flag is on.
# --------------------------------------------------------------------------- #
def _add_verified_asset(ws_id, value):
    db = SessionLocal()
    try:
        asset = crud.create_asset(db, ws_id, value)
        crud.mark_asset_verified(db, asset)
        db.commit()
    finally:
        db.close()


def test_rest_scan_403_for_unauthorized_target(monkeypatch, client, auth, fake_scanner):
    monkeypatch.setattr(settings, "REQUIRE_VERIFIED_ASSET", True)
    # No verified asset in this workspace -> the (public, resolvable) target is
    # refused by the asset gate with 403, before any scan runs.
    resp = client.get(
        "/scan/nuclei",
        headers=auth["headers"],
        params={"target": "example.com", "workspace_id": auth["ws_id"]},
    )
    assert resp.status_code == 403, resp.text

    # Nothing persisted for the refused scan.
    history = client.get(
        f"/workspaces/{auth['ws_id']}/scans", headers=auth["headers"]
    )
    assert history.json() == []


def test_rest_scan_allows_verified_target(monkeypatch, client, auth, fake_scanner):
    monkeypatch.setattr(settings, "REQUIRE_VERIFIED_ASSET", True)
    _add_verified_asset(auth["ws_id"], "example.com")

    resp = client.get(
        "/scan/nuclei",
        headers=auth["headers"],
        params={"target": "example.com", "workspace_id": auth["ws_id"]},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["status"] == "done"

"""Quota-enforcement tests at the HTTP boundary (402 Payment Required).

Each scanning/asset/seat mutation consults ``billing.check_quota`` before doing
work. The scans/assets/orgs routers all import the billing module and call
``billing.check_quota(...)`` by attribute at request time, so monkeypatching
``app.billing.check_quota`` is what the guards actually see — that is the symbol
patched here.

For each resource:
* with billing "cloud" and a stub that denies that resource -> the endpoint 402s;
* with billing disabled (the default, no patch) -> the same call succeeds.
"""

from app import billing
from app.config import settings


def _deny_only(resource_to_deny):
    """Return a ``check_quota`` stub that denies exactly one resource."""

    def _stub(_db, _org, resource):
        if resource == resource_to_deny:
            return False, f"{resource} quota reached (test); upgrade to add more"
        return True, "within quota"

    return _stub


# --------------------------------------------------------------------------- #
# scan -> GET /scan/{tool}
# --------------------------------------------------------------------------- #
def test_scan_denied_returns_402(monkeypatch, client, auth, fake_scanner):
    monkeypatch.setattr(settings, "BILLING_MODE", "cloud")
    monkeypatch.setattr(billing, "check_quota", _deny_only("scan"))

    resp = client.get(
        "/scan/nuclei",
        headers=auth["headers"],
        params={"target": "example.com", "workspace_id": auth["ws_id"]},
    )
    assert resp.status_code == 402, resp.text

    # Nothing was persisted for the refused scan.
    history = client.get(
        f"/workspaces/{auth['ws_id']}/scans", headers=auth["headers"]
    )
    assert history.json() == []


def test_scan_succeeds_when_billing_disabled(client, auth, fake_scanner):
    # Default BILLING_MODE == "none": the quota gate is a no-op.
    resp = client.get(
        "/scan/nuclei",
        headers=auth["headers"],
        params={"target": "example.com", "workspace_id": auth["ws_id"]},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["status"] == "done"


# --------------------------------------------------------------------------- #
# asset -> POST /workspaces/{id}/assets
# --------------------------------------------------------------------------- #
def test_asset_create_denied_returns_402(monkeypatch, client, auth):
    monkeypatch.setattr(settings, "BILLING_MODE", "cloud")
    monkeypatch.setattr(billing, "check_quota", _deny_only("asset"))

    resp = client.post(
        f"/workspaces/{auth['ws_id']}/assets",
        headers=auth["headers"],
        json={"value": "example.com", "atype": "domain"},
    )
    assert resp.status_code == 402, resp.text

    # No asset was created.
    listed = client.get(
        f"/workspaces/{auth['ws_id']}/assets", headers=auth["headers"]
    )
    assert listed.json() == []


def test_asset_create_succeeds_when_billing_disabled(client, auth):
    resp = client.post(
        f"/workspaces/{auth['ws_id']}/assets",
        headers=auth["headers"],
        json={"value": "example.com", "atype": "domain"},
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["value"] == "example.com"


# --------------------------------------------------------------------------- #
# seat -> POST /orgs/{id}/members
# --------------------------------------------------------------------------- #
def test_member_add_denied_returns_402(monkeypatch, client, auth, make_user):
    # A second, already-registered user to invite into auth's org.
    other = make_user()

    monkeypatch.setattr(settings, "BILLING_MODE", "cloud")
    monkeypatch.setattr(billing, "check_quota", _deny_only("seat"))

    resp = client.post(
        f"/orgs/{auth['org_id']}/members",
        headers=auth["headers"],
        json={"email": other["email"], "role": "viewer"},
    )
    assert resp.status_code == 402, resp.text

    # The invitee was not added (only the original owner remains).
    members = client.get(
        f"/orgs/{auth['org_id']}/members", headers=auth["headers"]
    ).json()
    assert len(members) == 1


def test_member_add_succeeds_when_billing_disabled(client, auth, make_user):
    other = make_user()
    resp = client.post(
        f"/orgs/{auth['org_id']}/members",
        headers=auth["headers"],
        json={"email": other["email"], "role": "viewer"},
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["email"] == other["email"]

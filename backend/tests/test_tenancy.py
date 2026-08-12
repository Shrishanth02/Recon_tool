"""Multi-tenant isolation & role-gating tests.

* A user cannot see another tenant's workspace (existence-hiding 404).
* A ``viewer`` member cannot mutate scope or run scans (403); an ``owner`` can.
"""


def test_user_cannot_read_foreign_workspace(client, auth, make_user):
    """User B must not be able to read user A's workspace -> 404 (hidden)."""
    other = make_user()
    resp = client.get(f"/workspaces/{auth['ws_id']}", headers=other["headers"])
    assert resp.status_code in (403, 404), resp.text
    # And the reverse direction is symmetric.
    resp2 = client.get(f"/workspaces/{other['ws_id']}", headers=auth["headers"])
    assert resp2.status_code in (403, 404), resp2.text


def test_foreign_user_cannot_change_scope(client, auth, make_user):
    other = make_user()
    resp = client.put(
        f"/workspaces/{auth['ws_id']}/scope",
        headers=other["headers"],
        json={"scope": ["example.com"]},
    )
    assert resp.status_code in (403, 404), resp.text


def _add_member(client, auth, email, role):
    resp = client.post(
        f"/orgs/{auth['org_id']}/members",
        headers=auth["headers"],
        json={"email": email, "role": role},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


def test_viewer_cannot_change_scope_but_owner_can(client, auth, make_user):
    """A viewer member of the org is refused scope mutation (403); owner ok."""
    viewer = make_user()
    _add_member(client, auth, viewer["email"], "viewer")

    # Viewer is a member (so it's a 403 capability failure, not a 404).
    denied = client.put(
        f"/workspaces/{auth['ws_id']}/scope",
        headers=viewer["headers"],
        json={"scope": ["example.com"]},
    )
    assert denied.status_code == 403, denied.text

    # Owner (the registering user) can set the scope.
    allowed = client.put(
        f"/workspaces/{auth['ws_id']}/scope",
        headers=auth["headers"],
        json={"scope": ["example.com"]},
    )
    assert allowed.status_code == 200, allowed.text
    assert allowed.json()["scope"] == ["example.com"]


def test_viewer_can_read_workspace(client, auth, make_user):
    """viewer+ is allowed to read the workspace it belongs to."""
    viewer = make_user()
    _add_member(client, auth, viewer["email"], "viewer")
    resp = client.get(f"/workspaces/{auth['ws_id']}", headers=viewer["headers"])
    assert resp.status_code == 200, resp.text


def test_viewer_cannot_run_scan_but_owner_can(client, auth, make_user, fake_scanner):
    """viewer role lacks analyst+ needed to run a scan (403); owner succeeds."""
    viewer = make_user()
    _add_member(client, auth, viewer["email"], "viewer")

    denied = client.get(
        "/scan/nuclei",
        headers=viewer["headers"],
        params={"target": "example.com", "workspace_id": auth["ws_id"]},
    )
    assert denied.status_code == 403, denied.text

    allowed = client.get(
        "/scan/nuclei",
        headers=auth["headers"],
        params={"target": "example.com", "workspace_id": auth["ws_id"]},
    )
    assert allowed.status_code == 200, allowed.text

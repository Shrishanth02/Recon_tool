"""API tests for Phase 4 schedules and notification channels (intel router).

Covers the workspace-scoped schedule lifecycle (create/list/toggle/delete),
the analyst+ RBAC gate on creation, and the org-scoped notification-channel
lifecycle (create/list/delete). No AI / network / SMTP.
"""


def _add_member(client, auth, email, role):
    resp = client.post(
        f"/orgs/{auth['org_id']}/members",
        headers=auth["headers"],
        json={"email": email, "role": role},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


# --------------------------------------------------------------------------- #
# Schedules
# --------------------------------------------------------------------------- #
def test_schedule_create_list_toggle_delete(client, auth):
    ws_id = auth["ws_id"]

    # Create.
    created = client.post(
        f"/workspaces/{ws_id}/schedules",
        headers=auth["headers"],
        json={
            "tool": "nuclei",
            "target": "example.com",
            "cron": "0 3 * * *",
            "options": {"depth": 2},
            "enabled": True,
        },
    )
    assert created.status_code == 201, created.text
    sched = created.json()
    sched_id = sched["id"]
    assert sched["tool"] == "nuclei"
    assert sched["target"] == "example.com"
    assert sched["cron"] == "0 3 * * *"
    assert sched["enabled"] is True
    assert sched["workspace_id"] == ws_id
    # next_run_at is derived from the cron expression.
    assert sched["next_run_at"] is not None

    # List reflects it.
    listed = client.get(f"/workspaces/{ws_id}/schedules", headers=auth["headers"])
    assert listed.status_code == 200, listed.text
    assert [s["id"] for s in listed.json()] == [sched_id]

    # Toggle disabled.
    patched = client.patch(
        f"/schedules/{sched_id}",
        headers=auth["headers"],
        json={"enabled": False},
    )
    assert patched.status_code == 200, patched.text
    assert patched.json()["enabled"] is False

    # Delete -> 204, then gone from the list.
    deleted = client.delete(f"/schedules/{sched_id}", headers=auth["headers"])
    assert deleted.status_code == 204, deleted.text
    after = client.get(f"/workspaces/{ws_id}/schedules", headers=auth["headers"])
    assert after.json() == []


def test_viewer_cannot_create_schedule(client, auth, make_user):
    viewer = make_user()
    _add_member(client, auth, viewer["email"], "viewer")

    denied = client.post(
        f"/workspaces/{auth['ws_id']}/schedules",
        headers=viewer["headers"],
        json={"tool": "nuclei", "target": "example.com", "cron": "0 3 * * *"},
    )
    assert denied.status_code == 403, denied.text

    # And nothing was persisted.
    listed = client.get(
        f"/workspaces/{auth['ws_id']}/schedules", headers=auth["headers"]
    )
    assert listed.json() == []


def test_viewer_can_list_schedules(client, auth, make_user):
    # Owner creates one; a viewer member can still read it.
    client.post(
        f"/workspaces/{auth['ws_id']}/schedules",
        headers=auth["headers"],
        json={"tool": "nuclei", "target": "example.com", "cron": "0 3 * * *"},
    )
    viewer = make_user()
    _add_member(client, auth, viewer["email"], "viewer")

    listed = client.get(
        f"/workspaces/{auth['ws_id']}/schedules", headers=viewer["headers"]
    )
    assert listed.status_code == 200, listed.text
    assert len(listed.json()) == 1


def test_foreign_user_cannot_delete_schedule(client, auth, make_user):
    created = client.post(
        f"/workspaces/{auth['ws_id']}/schedules",
        headers=auth["headers"],
        json={"tool": "nuclei", "target": "example.com", "cron": "0 3 * * *"},
    )
    sched_id = created.json()["id"]

    other = make_user()  # unrelated org, not a member
    denied = client.delete(f"/schedules/{sched_id}", headers=other["headers"])
    # Existence-hidden 404 for a non-member.
    assert denied.status_code == 404, denied.text


# --------------------------------------------------------------------------- #
# Notification channels (org-scoped)
# --------------------------------------------------------------------------- #
def test_channel_create_list_delete(client, auth):
    org_id = auth["org_id"]

    created = client.post(
        f"/orgs/{org_id}/notifications",
        headers=auth["headers"],
        json={
            "ctype": "slack",
            "config": {"url": "https://hooks.example/abc"},
            "events": ["new_finding"],
            "enabled": True,
        },
    )
    assert created.status_code == 201, created.text
    channel = created.json()
    channel_id = channel["id"]
    assert channel["ctype"] == "slack"
    assert channel["org_id"] == org_id
    assert channel["events"] == ["new_finding"]

    listed = client.get(f"/orgs/{org_id}/notifications", headers=auth["headers"])
    assert listed.status_code == 200, listed.text
    assert [c["id"] for c in listed.json()] == [channel_id]

    deleted = client.delete(
        f"/notifications/{channel_id}", headers=auth["headers"]
    )
    assert deleted.status_code == 204, deleted.text
    after = client.get(f"/orgs/{org_id}/notifications", headers=auth["headers"])
    assert after.json() == []


def test_viewer_cannot_create_channel_but_can_list(client, auth, make_user):
    viewer = make_user()
    _add_member(client, auth, viewer["email"], "viewer")

    denied = client.post(
        f"/orgs/{auth['org_id']}/notifications",
        headers=viewer["headers"],
        json={"ctype": "webhook", "config": {"url": "https://x/y"}},
    )
    assert denied.status_code == 403, denied.text

    # viewer+ may list.
    listed = client.get(
        f"/orgs/{auth['org_id']}/notifications", headers=viewer["headers"]
    )
    assert listed.status_code == 200, listed.text
    assert listed.json() == []

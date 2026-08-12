"""Phase 5: enterprise governance — audit log + GDPR export, admin-gated.

``GET /orgs/{id}/audit`` returns recent audit entries after auditable actions.
``GET /orgs/{id}/export`` produces the GDPR-style bundle (org + members +
workspaces + findings). Both are admin+; a viewer is forbidden (403).
"""


def test_audit_returns_entries_after_actions(client, auth):
    org_id = auth["org_id"]

    # Perform an auditable action (branding update -> audits "branding").
    upd = client.put(
        f"/orgs/{org_id}/branding",
        headers=auth["headers"],
        json={"brand_name": "Auditable Co"},
    )
    assert upd.status_code == 200, upd.text

    resp = client.get(f"/orgs/{org_id}/audit", headers=auth["headers"])
    assert resp.status_code == 200, resp.text
    entries = resp.json()
    assert isinstance(entries, list) and len(entries) >= 1
    actions = {e["action"] for e in entries}
    # Registration and the branding update are both recorded.
    assert "branding" in actions
    assert "register" in actions


def test_export_contains_org_members_workspaces_findings(client, auth, fake_scanner):
    org_id = auth["org_id"]

    # Seed a finding so the export's findings array is non-empty.
    scan = client.get(
        "/scan/nuclei",
        headers=auth["headers"],
        params={"target": "example.com", "workspace_id": auth["ws_id"]},
    )
    assert scan.status_code == 200, scan.text

    resp = client.get(f"/orgs/{org_id}/export", headers=auth["headers"])
    assert resp.status_code == 200, resp.text
    data = resp.json()

    assert data["organization"]["id"] == org_id
    assert auth["email"] in [m["email"] for m in data["members"]]

    assert len(data["workspaces"]) >= 1
    ws = next(w for w in data["workspaces"] if w["id"] == auth["ws_id"])
    assert len(ws["findings"]) >= 1
    assert ws["findings"][0]["severity"] == "high"

    # The export itself is audited.
    audit = client.get(f"/orgs/{org_id}/audit", headers=auth["headers"]).json()
    assert "data-export" in {e["action"] for e in audit}


def test_governance_endpoints_are_admin_only(client, auth, make_user):
    org_id = auth["org_id"]

    # Register a second user and add them to the owner's org as a viewer.
    viewer = make_user()
    add = client.post(
        f"/orgs/{org_id}/members",
        headers=auth["headers"],
        json={"email": viewer["email"], "role": "viewer"},
    )
    assert add.status_code == 201, add.text

    # A viewer is forbidden from the admin-gated governance endpoints.
    assert client.get(f"/orgs/{org_id}/audit", headers=viewer["headers"]).status_code == 403
    assert client.get(f"/orgs/{org_id}/export", headers=viewer["headers"]).status_code == 403

    # But a viewer *may* read branding (viewer+).
    assert client.get(f"/orgs/{org_id}/branding", headers=viewer["headers"]).status_code == 200

"""Scan-execution tests using the fake scanner (no external tools / network).

Covers: an in-scope REST scan persists a scan + derives findings, and an
out-of-scope target is refused with 403.
"""


def _set_scope(client, auth, scope_list):
    resp = client.put(
        f"/workspaces/{auth['ws_id']}/scope",
        headers=auth["headers"],
        json={"scope": scope_list},
    )
    assert resp.status_code == 200, resp.text


def test_in_scope_scan_persists_and_derives_findings(client, auth, fake_scanner):
    _set_scope(client, auth, ["example.com"])

    resp = client.get(
        "/scan/nuclei",
        headers=auth["headers"],
        params={"target": "example.com", "workspace_id": auth["ws_id"]},
    )
    assert resp.status_code == 200, resp.text
    scan = resp.json()
    assert scan["tool"] == "nuclei"
    assert scan["target"] == "example.com"
    assert scan["status"] == "done"
    assert scan["error"] is None
    # The fake scanner emitted a log line and a structured result.
    assert scan["logs"]
    assert scan["result"]["total"] == 1

    scan_id = scan["id"]

    # The scan shows up in the workspace history.
    history = client.get(f"/workspaces/{auth['ws_id']}/scans", headers=auth["headers"])
    assert history.status_code == 200
    ids = [s["id"] for s in history.json()]
    assert scan_id in ids

    # Findings were derived from the nuclei-shaped result.
    findings = client.get(f"/workspaces/{auth['ws_id']}/findings", headers=auth["headers"])
    assert findings.status_code == 200
    fdata = findings.json()
    assert len(fdata) == 1
    finding = fdata[0]
    assert finding["scan_id"] == scan_id
    assert finding["severity"] == "high"
    assert finding["name"] == "Fake High Severity Finding"
    assert finding["status"] == "open"
    assert finding["cve"] == ["CVE-2024-0001"]

    # The workspace summary reflects the new counts.
    ws = client.get(f"/workspaces/{auth['ws_id']}", headers=auth["headers"]).json()
    assert ws["scan_count"] == 1
    assert ws["finding_count"] == 1
    assert ws["severity_counts"].get("high") == 1


def test_out_of_scope_target_is_refused(client, auth, fake_scanner):
    _set_scope(client, auth, ["example.com"])

    resp = client.get(
        "/scan/nuclei",
        headers=auth["headers"],
        params={"target": "attacker.net", "workspace_id": auth["ws_id"]},
    )
    assert resp.status_code == 403, resp.text

    # Nothing was persisted for the refused scan.
    history = client.get(f"/workspaces/{auth['ws_id']}/scans", headers=auth["headers"])
    assert history.json() == []
    findings = client.get(f"/workspaces/{auth['ws_id']}/findings", headers=auth["headers"])
    assert findings.json() == []


def test_scan_with_empty_scope_is_unrestricted(client, auth, fake_scanner):
    # Default workspace has empty scope -> any target is allowed.
    resp = client.get(
        "/scan/nuclei",
        headers=auth["headers"],
        params={"target": "anything.example.org", "workspace_id": auth["ws_id"]},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["status"] == "done"


def test_unknown_tool_is_rejected(client, auth):
    resp = client.get(
        "/scan/does-not-exist",
        headers=auth["headers"],
        params={"target": "example.com", "workspace_id": auth["ws_id"]},
    )
    assert resp.status_code == 400, resp.text


def test_scan_requires_authentication(client, auth, fake_scanner):
    resp = client.get(
        "/scan/nuclei",
        params={"target": "example.com", "workspace_id": auth["ws_id"]},
    )
    assert resp.status_code == 401, resp.text


def test_scan_via_api_key(client, auth, fake_scanner):
    """An X-API-Key principal can run a scoped scan (created_by is None)."""
    created = client.post(
        f"/orgs/{auth['org_id']}/apikeys",
        headers=auth["headers"],
        json={"name": "ci-key"},
    )
    assert created.status_code == 201, created.text
    full_key = created.json()["key"]
    assert full_key and full_key.startswith("rcx_")

    resp = client.get(
        "/scan/nuclei",
        headers={"X-API-Key": full_key},
        params={"target": "example.com", "workspace_id": auth["ws_id"]},
    )
    assert resp.status_code == 200, resp.text
    scan = resp.json()
    assert scan["status"] == "done"
    assert scan["created_by"] is None

"""Purple-Team P1 tests: MITRE ATT&CK mapping.

Unit-level coverage of :func:`app.attack.map_finding` for the fixed-tool
mappings and the nuclei keyword rules, plus an end-to-end check that running a
scan through the REST ``/scan`` flow tags the persisted findings and that
``GET /workspaces/{id}/attack-coverage`` rolls those tags into a matrix.
"""

from app import attack


# --------------------------------------------------------------------------- #
# Unit: attack.map_finding
# --------------------------------------------------------------------------- #
def test_map_finding_nmap_open_port_is_network_service_discovery():
    mapping = attack.map_finding("nmap", {"name": "Open port 22/tcp (ssh)"})
    assert mapping == {
        "technique_id": "T1046",
        "technique": "Network Service Discovery",
        "tactic": "discovery",
    }


def test_map_finding_whois_is_search_open_technical_databases():
    mapping = attack.map_finding("whois", {"name": "whois record"})
    assert mapping["technique_id"] == "T1596"
    assert mapping["tactic"] == "reconnaissance"


def test_map_finding_dirbuster_is_file_and_directory_discovery():
    mapping = attack.map_finding("dirbuster", {"name": "Discovered path /admin"})
    assert mapping["technique_id"] == "T1083"
    assert mapping["tactic"] == "discovery"


def test_map_finding_nuclei_sqli_tag_is_exploit_public_facing_application():
    mapping = attack.map_finding(
        "nuclei", {"name": "Some finding", "tags": ["sqli"]}
    )
    assert mapping["technique_id"] == "T1190"
    assert mapping["tactic"] == "initial-access"


def test_map_finding_unknown_tool_returns_none():
    assert attack.map_finding("totally-unknown-tool", {"name": "x"}) is None


# --------------------------------------------------------------------------- #
# Integration: scan -> tagged findings -> coverage matrix
# --------------------------------------------------------------------------- #
def test_scan_tags_findings_and_attack_coverage_matrix(client, auth, fake_scanner):
    # Run the fake nuclei scanner through the REST /scan flow so a finding
    # persists. The fake finding's name carries no nuclei keyword, so it maps to
    # the nuclei default technique T1595.002 (reconnaissance).
    resp = client.get(
        "/scan/nuclei",
        headers=auth["headers"],
        params={"target": "example.com", "workspace_id": auth["ws_id"]},
    )
    assert resp.status_code == 200, resp.text

    # FindingOut exposes technique_id/tactic and they are populated.
    findings = client.get(
        f"/workspaces/{auth['ws_id']}/findings", headers=auth["headers"]
    )
    assert findings.status_code == 200, findings.text
    fdata = findings.json()
    assert len(fdata) == 1
    finding = fdata[0]
    assert "technique_id" in finding
    assert "tactic" in finding
    assert finding["technique_id"] == "T1595.002"
    assert finding["tactic"] == "reconnaissance"

    # The coverage matrix rolls the tagged finding into a tactic/technique.
    cov = client.get(
        f"/workspaces/{auth['ws_id']}/attack-coverage", headers=auth["headers"]
    )
    assert cov.status_code == 200, cov.text
    data = cov.json()
    assert data["total_findings"] == 1
    assert data["total_techniques"] == 1
    assert len(data["tactics"]) == 1

    tactic = data["tactics"][0]
    assert tactic["tactic"] == "reconnaissance"
    assert tactic["name"] == "Reconnaissance"
    assert len(tactic["techniques"]) == 1

    technique = tactic["techniques"][0]
    assert technique["technique_id"] == "T1595.002"
    assert technique["count"] == 1
    assert technique["severities"] == {"high": 1}


def test_attack_coverage_empty_when_no_findings(client, auth):
    cov = client.get(
        f"/workspaces/{auth['ws_id']}/attack-coverage", headers=auth["headers"]
    )
    assert cov.status_code == 200, cov.text
    data = cov.json()
    assert data == {"tactics": [], "total_techniques": 0, "total_findings": 0}


def test_attack_coverage_requires_membership(client, auth, make_user):
    # A user from a different org must not see this workspace's coverage (404
    # hides existence from non-members).
    other = make_user()
    resp = client.get(
        f"/workspaces/{auth['ws_id']}/attack-coverage", headers=other["headers"]
    )
    assert resp.status_code == 404, resp.text

"""Phase 5: white-label branding — config round-trip + branded report.

An admin sets an org's branding via ``PUT /orgs/{id}/branding`` and reads it back
via ``GET``. The workspace HTML report then carries the custom ``brand_name`` and
footer, while ``report.generate(..., branding=None)`` remains the unbranded
RECON-X default (byte-compatible with pre-Phase-5 output).
"""

from app import report


def test_branding_put_then_get_roundtrip(client, auth):
    org_id = auth["org_id"]
    put = client.put(
        f"/orgs/{org_id}/branding",
        headers=auth["headers"],
        json={
            "brand_name": "Acme Security",
            "brand_primary_color": "#123456",
            "report_footer": "Confidential — Acme Security",
        },
    )
    assert put.status_code == 200, put.text
    assert put.json()["brand_name"] == "Acme Security"
    assert put.json()["brand_primary_color"] == "#123456"

    got = client.get(f"/orgs/{org_id}/branding", headers=auth["headers"])
    assert got.status_code == 200, got.text
    data = got.json()
    assert data["brand_name"] == "Acme Security"
    assert data["report_footer"] == "Confidential — Acme Security"


def test_report_html_contains_custom_branding(client, auth, fake_scanner):
    # Seed a finding so the report has content.
    scan = client.get(
        "/scan/nuclei",
        headers=auth["headers"],
        params={"target": "example.com", "workspace_id": auth["ws_id"]},
    )
    assert scan.status_code == 200, scan.text

    client.put(
        f"/orgs/{auth['org_id']}/branding",
        headers=auth["headers"],
        json={
            "brand_name": "Acme Security",
            "report_footer": "Prepared exclusively for the client",
        },
    )

    rep = client.get(
        f"/workspaces/{auth['ws_id']}/report", headers=auth["headers"]
    )
    assert rep.status_code == 200, rep.text
    html = rep.text
    assert "Acme Security" in html
    assert "Prepared exclusively for the client" in html


def test_report_default_brand_when_unbranded():
    html = report.generate(
        {"name": "Demo Engagement", "description": "", "scope": []},
        findings=[],
        scans=[],
        branding=None,
    )
    # The unbranded report carries the product's default brand (RedOpsX).
    assert "RedOpsX" in html
    assert "RECON-X" not in html

"""P0-5 regression tests — brand color / logo injection into reports.

Organization branding is attacker-controllable and rendered into report HTML/CSS.
The color lands inside a ``<style>`` block, so HTML-escaping is not enough. These
tests prove the two-layer defense:

* the API/schema boundary REJECTS a non-hex color / unsafe logo (422); and
* the report layer FALLS BACK to a safe default for any legacy stored value, so a
  malicious value can never escape the CSS property or the ``<img src>``.
"""

import pytest
from pydantic import ValidationError

from app import crud, report
from app.branding import (
    DEFAULT_ACCENT,
    is_hex_color,
    is_safe_logo_url,
    safe_color,
    safe_logo_url,
)
from app.database import SessionLocal
from app.schemas import BrandingIn

# Payloads that must NEVER be accepted as a color nor rendered into a report.
COLOR_ATTACKS = [
    "red}</style><svg/onload=alert(1)>",       # style termination + SVG
    "#fff;}body{display:none}",                # CSS injection / extra declaration
    "url(javascript:alert(1))",                # url() + javascript
    "expression(alert(1))",                    # legacy IE expression()
    '#fff" onmouseover="alert(1)',             # attribute breakout attempt
    "<script>alert(1)</script>",               # HTML
    "javascript:alert(1)",                     # scheme
    "  #fff ; color: red ",                    # extra declarations
    "#" + "a" * 5000,                          # long value
    "rgba(0,0,0,0)",                           # function form (not our hex allow-list)
    "teal",                                    # named color (app expects hex)
]


# --------------------------------------------------------------------------- #
# Unit — the color allow-list
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("good", ["#fff", "#FFFF", "#0d9488", "#0D9488", "#0d9488ff"])
def test_valid_hex_colors_are_accepted(good):
    assert is_hex_color(good)
    assert safe_color(good) == good.strip().lower()


@pytest.mark.parametrize("bad", COLOR_ATTACKS + ["", "   ", None, 123, [], {}])
def test_invalid_colors_fall_back_to_default(bad):
    # safe_color never raises and never echoes the attacker value.
    out = safe_color(bad, "#0d9488")
    assert out == "#0d9488"
    assert not is_hex_color(bad) or bad is None


def test_safe_color_uses_the_caller_default():
    assert safe_color("nope", "#7c3aed") == "#7c3aed"


# --------------------------------------------------------------------------- #
# Unit — the logo URL allow-list
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "url",
    ["https://cdn.example.com/logo.png", "http://x.example/y.jpg",
     "data:image/png;base64,iVBORw0KGgoAAAANSUhEUg=="],
)
def test_safe_logo_urls_pass(url):
    assert is_safe_logo_url(url)
    assert safe_logo_url(url) == url


@pytest.mark.parametrize(
    "url",
    ["javascript:alert(1)",
     "data:text/html;base64,PHNjcmlwdD4=",
     "data:image/svg+xml;base64,PHN2Zz48L3N2Zz4=",   # SVG can carry script -> blocked
     "url(https://x/y.png)",
     'https://x/"><img src=x onerror=alert(1)>',
     "  ", ""],
)
def test_unsafe_logo_urls_are_rejected(url):
    assert not is_safe_logo_url(url)
    assert safe_logo_url(url) == ""


# --------------------------------------------------------------------------- #
# Schema — reject at the write boundary
# --------------------------------------------------------------------------- #
def test_schema_accepts_valid_hex_and_normalizes():
    m = BrandingIn(brand_primary_color="#0D9488")
    assert m.brand_primary_color == "#0d9488"


@pytest.mark.parametrize("empty", [None, "", "   "])
def test_schema_empty_color_clears(empty):
    assert BrandingIn(brand_primary_color=empty).brand_primary_color is None


@pytest.mark.parametrize("bad", COLOR_ATTACKS)
def test_schema_rejects_malicious_color(bad):
    with pytest.raises(ValidationError):
        BrandingIn(brand_primary_color=bad)


def test_schema_rejects_unsafe_logo():
    with pytest.raises(ValidationError):
        BrandingIn(brand_logo_url="javascript:alert(1)")
    with pytest.raises(ValidationError):
        BrandingIn(brand_logo_url="data:image/svg+xml;base64,PHN2Zz4=")
    # a safe one is fine
    assert BrandingIn(brand_logo_url="https://x/y.png").brand_logo_url == "https://x/y.png"


# --------------------------------------------------------------------------- #
# API — PUT /orgs/{id}/branding rejects injection with 422
# --------------------------------------------------------------------------- #
def test_branding_endpoint_accepts_valid_hex(client, auth):
    r = client.put(f"/orgs/{auth['org_id']}/branding", headers=auth["headers"],
                   json={"brand_primary_color": "#123abc"})
    assert r.status_code == 200, r.text
    assert r.json()["brand_primary_color"] == "#123abc"


@pytest.mark.parametrize("bad", ["red}</style><svg/onload=alert(1)>", "#fff;}x{y:z}",
                                 "url(javascript:alert(1))", "<script>alert(1)</script>"])
def test_branding_endpoint_rejects_injection(client, auth, bad):
    r = client.put(f"/orgs/{auth['org_id']}/branding", headers=auth["headers"],
                   json={"brand_primary_color": bad})
    assert r.status_code == 422, r.text


# --------------------------------------------------------------------------- #
# Report — a LEGACY stored malicious value can never escape the CSS
# --------------------------------------------------------------------------- #
def _store_raw_branding(org_id: int, **fields) -> None:
    """Write branding straight to the org, bypassing schema validation, to
    simulate a value persisted before P0-5 validation existed."""
    db = SessionLocal()
    try:
        crud.set_org_branding(db, org_id, **fields)
        db.commit()
    finally:
        db.close()


def test_report_endpoint_neutralizes_legacy_malicious_color(client, auth):
    payload = "red}</style><svg/onload=alert(1)>"
    _store_raw_branding(auth["org_id"], brand_primary_color=payload,
                        brand_logo_url="javascript:alert(1)")

    resp = client.get(f"/workspaces/{auth['ws_id']}/report", headers=auth["headers"])
    assert resp.status_code == 200, resp.text
    html = resp.text
    # The malicious value never reaches the output; the safe default is used.
    assert payload not in html
    assert "</style><svg" not in html
    assert "onload=alert" not in html
    assert "javascript:alert(1)" not in html
    assert "--accent:#0d9488" in html  # fell back to the default accent


def test_report_generate_direct_falls_back_and_still_renders():
    project = {"name": "Acme Engagement", "scope": []}
    html = report.generate(
        project, findings=[], scans=[],
        branding={"brand_primary_color": "#fff;}body{display:none}",
                  "brand_logo_url": "data:image/svg+xml;base64,PHN2Zz4="},
    )
    assert "body{display:none}" not in html
    assert "svg" not in html.lower().split("engagement")[0][-200:]  # no SVG smuggled near head
    assert f"--accent:{DEFAULT_ACCENT}" in html   # safe default applied


def test_report_generate_preserves_valid_branding():
    project = {"name": "Acme", "scope": []}
    html = report.generate(project, findings=[], scans=[],
                           branding={"brand_primary_color": "#123abc"})
    assert "--accent:#123abc" in html   # legitimate branding still works

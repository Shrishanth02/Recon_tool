"""Billing-core tests (:mod:`app.billing`) + the billing status routes.

Covers three things:

* ``BILLING_MODE == "none"`` — every quota/feature check is a no-op and needs no
  DB (the default that keeps the historical suite green).
* ``BILLING_MODE == "cloud"`` with a free-plan org — when usage is stubbed over
  the free limits, ``check_quota`` denies both ``scan`` and ``asset``.
* The HTTP surface: ``GET /billing/plans`` (public catalog) and
  ``GET /orgs/{id}/billing`` (mode/plan/limits/usage/features).

Billing mode is toggled by monkeypatching the shared ``billing.settings``
singleton; usage is stubbed by monkeypatching ``billing.usage`` (the symbol
``check_quota`` resolves at call time within the module).
"""

from app import billing, crud
from app.database import SessionLocal


# --------------------------------------------------------------------------- #
# BILLING_MODE == "none": no-op, no DB required.
# --------------------------------------------------------------------------- #
def test_billing_disabled_check_quota_always_allows_without_db():
    # Default mode is "none" -> short-circuits before touching db/org, so None
    # arguments are safe.
    assert billing.settings.billing_enabled is False
    for resource in ("scan", "asset", "seat"):
        allowed, reason = billing.check_quota(None, None, resource)
        assert allowed is True
        assert reason == "billing disabled"


def test_billing_disabled_feature_allowed_always_true_without_db():
    for feature in ("ai", "continuous", "integrations", "white_label"):
        assert billing.feature_allowed(None, None, feature) is True


# --------------------------------------------------------------------------- #
# BILLING_MODE == "cloud": a free-plan org over its limits is denied.
# --------------------------------------------------------------------------- #
def test_cloud_free_plan_over_usage_denies_scan_and_asset(monkeypatch):
    monkeypatch.setattr(billing.settings, "BILLING_MODE", "cloud")
    assert billing.settings.billing_enabled is True

    db = SessionLocal()
    try:
        _user, org, _ws = crud.create_user_with_org(
            db, "billing-cloud@example.com", "password123"
        )
        db.commit()

        # No subscription -> effective plan is "free" (assets=1, scans/mo=20).
        assert billing.effective_plan(db, org) == "free"

        # Stub usage well past every free limit.
        monkeypatch.setattr(
            billing,
            "usage",
            lambda _db, _org: {
                "scans_this_period": 999,
                "assets": 999,
                "seats": 999,
            },
        )

        scan_ok, scan_reason = billing.check_quota(db, org, "scan")
        assert scan_ok is False
        assert "quota reached" in scan_reason

        asset_ok, asset_reason = billing.check_quota(db, org, "asset")
        assert asset_ok is False
        assert "quota reached" in asset_reason
    finally:
        db.close()


def test_cloud_free_plan_within_usage_allows(monkeypatch):
    monkeypatch.setattr(billing.settings, "BILLING_MODE", "cloud")
    db = SessionLocal()
    try:
        _user, org, _ws = crud.create_user_with_org(
            db, "billing-within@example.com", "password123"
        )
        db.commit()
        monkeypatch.setattr(
            billing,
            "usage",
            lambda _db, _org: {
                "scans_this_period": 0,
                "assets": 0,
                "seats": 0,
            },
        )
        assert billing.check_quota(db, org, "scan")[0] is True
        assert billing.check_quota(db, org, "asset")[0] is True
    finally:
        db.close()


# --------------------------------------------------------------------------- #
# HTTP: public plan catalog.
# --------------------------------------------------------------------------- #
def test_get_billing_plans_returns_catalog(client):
    resp = client.get("/billing/plans")
    assert resp.status_code == 200, resp.text
    catalog = resp.json()
    by_id = {p["id"]: p for p in catalog}
    assert {"free", "starter", "pro", "mssp"} <= set(by_id)
    # Each entry carries name/price/limits.
    free = by_id["free"]
    assert free["name"] == "Free"
    assert free["price_usd_month"] == 0
    assert free["limits"]["scans_per_month"] == 20
    assert by_id["pro"]["limits"]["ai"] is True


# --------------------------------------------------------------------------- #
# HTTP: per-org billing status (viewer+).
# --------------------------------------------------------------------------- #
def test_get_org_billing_status_shape(client, auth):
    resp = client.get(f"/orgs/{auth['org_id']}/billing", headers=auth["headers"])
    assert resp.status_code == 200, resp.text
    body = resp.json()
    # All five documented sections are present.
    assert set(body) >= {"mode", "plan", "limits", "usage", "features"}
    # Default deployment: billing off, free plan.
    assert body["mode"] == "none"
    assert body["plan"] == "free"
    assert set(body["usage"]) == {"scans_this_period", "assets", "seats"}
    assert set(body["features"]) == {
        "ai",
        "continuous",
        "integrations",
        "white_label",
    }
    assert "scans_per_month" in body["limits"]

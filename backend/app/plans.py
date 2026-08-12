"""Static billing-plan catalog for RECON-X (Phase 3).

This module is a **pure, stdlib-only** catalog: it declares the concrete plans
that both the SaaS (Stripe) and self-hosted (license) billing modes map onto,
plus two small helpers for reading a plan's limits and feature flags. It has no
database, network, or third-party dependencies and is always import-safe.

A limit value of ``None`` means *unlimited*. Feature limits are plain booleans.
The catalog is intentionally duplicated here (rather than derived from Stripe or
a license) so entitlement decisions never require an external service.
"""

from __future__ import annotations

from typing import Any

# --------------------------------------------------------------------------- #
# Plan catalog
#
# ``limits`` keys:
#   assets           int | None   max verified/tracked assets in the org (None = ∞)
#   seats            int | None   max org memberships (None = ∞)
#   scans_per_month  int | None   max scans per calendar month (None = ∞)
#   ai               bool         AI triage available
#   continuous       bool         scheduled / continuous scanning available
#   integrations     bool         notification channels / webhooks available
#   white_label      bool         white-labelling / MSSP branding available
# --------------------------------------------------------------------------- #
PLANS: dict[str, dict[str, Any]] = {
    "free": {
        "name": "Free",
        "price_usd_month": 0,
        "limits": {
            "assets": 1,
            "seats": 2,
            "scans_per_month": 20,
            "ai": False,
            "continuous": False,
            "integrations": False,
            "white_label": False,
        },
    },
    "starter": {
        "name": "Starter",
        "price_usd_month": 49,
        "limits": {
            "assets": 3,
            "seats": 3,
            "scans_per_month": 200,
            "ai": False,
            "continuous": True,
            "integrations": False,
            "white_label": False,
        },
    },
    "pro": {
        "name": "Pro",
        "price_usd_month": 299,
        "limits": {
            "assets": 25,
            "seats": 10,
            "scans_per_month": 2000,
            "ai": True,
            "continuous": True,
            "integrations": True,
            "white_label": False,
        },
    },
    "mssp": {
        "name": "MSSP",
        "price_usd_month": 999,
        "limits": {
            "assets": None,
            "seats": None,
            "scans_per_month": None,
            "ai": True,
            "continuous": True,
            "integrations": True,
            "white_label": True,
        },
    },
}

# The plan used whenever an unknown/empty plan id is requested.
DEFAULT_PLAN_ID = "free"

# The set of boolean feature keys (as opposed to numeric quota keys).
FEATURE_KEYS = ("ai", "continuous", "integrations", "white_label")


def plan_ids() -> list[str]:
    """Return every known plan id, in catalog (ascending-tier) order."""
    return list(PLANS.keys())


def plan_limits(plan_id: str | None) -> dict[str, Any]:
    """Return a copy of the limits dict for ``plan_id``.

    Falls back to the ``free`` plan for any unknown, empty, or ``None`` id so
    callers always receive a well-formed limits mapping.
    """
    plan = PLANS.get((plan_id or "").strip().lower()) or PLANS[DEFAULT_PLAN_ID]
    # Return a shallow copy so callers cannot mutate the catalog in place.
    return dict(plan["limits"])


def feature_enabled(plan_id: str | None, feature: str) -> bool:
    """Return whether ``feature`` (e.g. ``"ai"``) is enabled for ``plan_id``.

    Unknown features return ``False``. Unknown plans fall back to ``free``.
    """
    return bool(plan_limits(plan_id).get(feature, False))

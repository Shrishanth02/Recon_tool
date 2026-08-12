"""Billing core: effective plan resolution, quotas, and Stripe glue (Phase 3).

This module is the single decision point for "what is this org allowed to do?".
It unifies three billing modes behind one API:

* ``none``        — billing disabled. **Every quota/feature check is a no-op**
                    (allowed). The historical inline/auth flows are untouched.
* ``cloud``       — SaaS. The effective plan comes from the org's active Stripe
                    :class:`~app.models.Subscription`.
* ``self_hosted`` — offline. The effective plan comes from a signed license
                    token (see :mod:`app.licensing`).

Every enforcement helper first consults ``settings.billing_enabled``: when
billing is off they short-circuit to "allowed / unlimited", which is what keeps
the existing 125 tests (which never set ``BILLING_MODE``) green.

Stripe is imported **lazily** and every Stripe entry point returns an
``{"error": ...}`` dict instead of raising when ``stripe`` is absent or no API
key is configured.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from . import crud, licensing, models
from .config import settings
from .plans import DEFAULT_PLAN_ID, feature_enabled, plan_limits

# Subscription statuses that grant the paid plan in cloud mode.
_ACTIVE_STATUSES = {"active", "trialing"}


# --------------------------------------------------------------------------- #
# Effective plan / limits
# --------------------------------------------------------------------------- #
def effective_plan(db: Session, org: models.Organization) -> str:
    """Return the plan id that currently governs ``org``.

    Resolution depends on ``settings.BILLING_MODE``:

    * ``self_hosted``: the ``tier`` of a valid active license, else ``free``.
    * ``cloud``: the plan of the org's :class:`~app.models.Subscription` when its
      status is active/trialing, else the org's stored ``plan`` (or ``free``).
    * ``none``: the org's stored ``plan`` (or ``free``). Callers gate on
      :attr:`Settings.billing_enabled`, so no limits are actually applied here.
    """
    mode = (settings.BILLING_MODE or "none").strip().lower()

    if mode == "self_hosted":
        payload = licensing.load_active_license()
        if payload and payload.get("tier"):
            return str(payload["tier"])
        return DEFAULT_PLAN_ID

    if mode == "cloud":
        sub = crud.get_subscription(db, org.id)
        if sub and (sub.status or "").strip().lower() in _ACTIVE_STATUSES:
            return sub.plan or DEFAULT_PLAN_ID
        return getattr(org, "plan", None) or DEFAULT_PLAN_ID

    # mode == "none" (or anything unrecognized): stored plan, defaulting to free.
    return getattr(org, "plan", None) or DEFAULT_PLAN_ID


def current_limits(db: Session, org: models.Organization) -> dict[str, Any]:
    """Return the concrete limits dict for ``org``'s effective plan.

    In ``self_hosted`` mode a valid license may override the plan's numeric
    quotas (``assets``/``seats``/``scans``) and feature list; those overrides are
    merged on top of the base plan limits.
    """
    plan = effective_plan(db, org)
    limits = plan_limits(plan)

    mode = (settings.BILLING_MODE or "none").strip().lower()
    if mode == "self_hosted":
        payload = licensing.load_active_license()
        if payload:
            limits = _apply_license_overrides(limits, payload)
    return limits


def _apply_license_overrides(
    limits: dict[str, Any], payload: dict[str, Any]
) -> dict[str, Any]:
    """Merge a license payload's explicit entitlements over base plan limits.

    A key present in the payload (even as ``None``, meaning unlimited) wins over
    the base plan value. ``features`` — when supplied as a list — replaces the
    boolean feature flags: a feature is enabled iff it appears in the list.
    """
    merged = dict(limits)
    # Numeric quotas: license key -> limits key.
    for lic_key, lim_key in (
        ("assets", "assets"),
        ("seats", "seats"),
        ("scans", "scans_per_month"),
    ):
        if lic_key in payload:
            merged[lim_key] = payload[lic_key]

    features = payload.get("features")
    if isinstance(features, list):
        for feat in ("ai", "continuous", "integrations", "white_label"):
            merged[feat] = feat in features
    return merged


# --------------------------------------------------------------------------- #
# Usage accounting
# --------------------------------------------------------------------------- #
def usage(db: Session, org: models.Organization) -> dict[str, int]:
    """Return the org's current usage counters.

    Keys: ``scans_this_period`` (scans started this calendar month),
    ``assets`` (assets across the org's workspaces), and ``seats`` (memberships).
    """
    return {
        "scans_this_period": crud.count_org_scans_this_month(db, org.id),
        "assets": crud.count_org_assets(db, org.id),
        "seats": crud.count_org_seats(db, org.id),
    }


# Maps a quota "resource" to its (usage key, limits key) pair.
_RESOURCE_MAP: dict[str, tuple[str, str]] = {
    "scan": ("scans_this_period", "scans_per_month"),
    "asset": ("assets", "assets"),
    "seat": ("seats", "seats"),
}


def check_quota(
    db: Session, org: models.Organization, resource: str
) -> tuple[bool, str]:
    """Return ``(allowed, reason)`` for consuming one more ``resource``.

    ``resource`` is one of ``"scan"``, ``"asset"``, ``"seat"``. When billing is
    disabled the answer is always ``(True, "billing disabled")``. Otherwise the
    org's current usage is compared against its effective-plan limit; a ``None``
    limit means unlimited. The check is a *pre-consumption* gate: creating the
    Nth resource is allowed while current usage is strictly below the limit.
    """
    if not settings.billing_enabled:
        return True, "billing disabled"

    mapping = _RESOURCE_MAP.get(resource)
    if mapping is None:
        return False, f"unknown resource '{resource}'"
    usage_key, limit_key = mapping

    limits = current_limits(db, org)
    limit = limits.get(limit_key)
    if limit is None:  # unlimited
        return True, "unlimited"

    used = usage(db, org).get(usage_key, 0)
    if used >= limit:
        plan = effective_plan(db, org)
        return (
            False,
            f"{resource} quota reached for plan '{plan}' "
            f"({used}/{limit} {usage_key}); upgrade to add more",
        )
    return True, "within quota"


def feature_allowed(
    db: Session, org: models.Organization, feature: str
) -> bool:
    """Return whether a boolean ``feature`` is enabled for ``org``.

    Features are ``ai``, ``continuous``, ``integrations``, ``white_label``. When
    billing is disabled everything is allowed. In ``self_hosted`` mode license
    overrides apply via :func:`current_limits`.
    """
    if not settings.billing_enabled:
        return True

    mode = (settings.BILLING_MODE or "none").strip().lower()
    if mode == "self_hosted":
        # Honor license feature overrides.
        return bool(current_limits(db, org).get(feature, False))
    return feature_enabled(effective_plan(db, org), feature)


# --------------------------------------------------------------------------- #
# Stripe integration (lazy import; never raises)
# --------------------------------------------------------------------------- #
def _load_stripe() -> Any | None:
    """Import and configure the ``stripe`` SDK, or return ``None``.

    Returns the configured module when both ``stripe`` is importable and
    ``settings.stripe_enabled`` (an API key is set); otherwise ``None``.
    """
    if not settings.stripe_enabled:
        return None
    try:
        import stripe
    except ImportError:
        return None
    stripe.api_key = settings.STRIPE_SECRET_KEY
    return stripe


def _price_id_for_plan(plan: str) -> str:
    """Map a plan id to its configured Stripe price id (``""`` if unmapped)."""
    return {
        "starter": settings.STRIPE_PRICE_STARTER,
        "pro": settings.STRIPE_PRICE_PRO,
    }.get((plan or "").strip().lower(), "")


def _ensure_customer(stripe: Any, db: Session, org: models.Organization) -> str:
    """Return the Stripe customer id for ``org``, creating one if needed.

    The id is persisted on the org's :class:`~app.models.Subscription` row so it
    is reused across checkout/portal sessions. The caller commits.
    """
    sub = crud.get_subscription(db, org.id)
    if sub and sub.customer_id:
        return sub.customer_id
    customer = stripe.Customer.create(
        name=org.name, metadata={"org_id": str(org.id)}
    )
    crud.upsert_subscription(db, org.id, customer_id=customer["id"])
    return customer["id"]


def create_checkout_session(
    db: Session, org: models.Organization, plan: str
) -> dict[str, Any]:
    """Create a Stripe Checkout session to subscribe ``org`` to ``plan``.

    Returns ``{"url": ...}`` on success or ``{"error": ...}`` if Stripe is
    unavailable, unconfigured, the plan has no price id, or the API call fails.
    Never raises.
    """
    stripe = _load_stripe()
    if stripe is None:
        return {"error": "stripe not configured"}

    price_id = _price_id_for_plan(plan)
    if not price_id:
        return {"error": f"no Stripe price configured for plan '{plan}'"}

    try:
        customer_id = _ensure_customer(stripe, db, org)
        session = stripe.checkout.Session.create(
            mode="subscription",
            customer=customer_id,
            line_items=[{"price": price_id, "quantity": 1}],
            success_url=settings.BILLING_SUCCESS_URL,
            cancel_url=settings.BILLING_CANCEL_URL,
            metadata={"org_id": str(org.id), "plan": plan},
        )
    except Exception as exc:  # pragma: no cover - network/SDK failure
        return {"error": f"stripe error: {exc}"}
    return {"url": session.get("url", "")}


def create_portal_session(
    db: Session, org: models.Organization
) -> dict[str, Any]:
    """Create a Stripe Billing Portal session for ``org`` to manage its plan.

    Returns ``{"url": ...}`` or ``{"error": ...}``. Never raises.
    """
    stripe = _load_stripe()
    if stripe is None:
        return {"error": "stripe not configured"}

    sub = crud.get_subscription(db, org.id)
    if not sub or not sub.customer_id:
        return {"error": "no Stripe customer for this org"}

    try:
        session = stripe.billing_portal.Session.create(
            customer=sub.customer_id,
            return_url=settings.BILLING_SUCCESS_URL,
        )
    except Exception as exc:  # pragma: no cover - network/SDK failure
        return {"error": f"stripe error: {exc}"}
    return {"url": session.get("url", "")}


def _coerce_period_end(value: Any) -> datetime | None:
    """Convert a Stripe unix ``current_period_end`` to an aware datetime."""
    if value is None:
        return None
    try:
        return datetime.fromtimestamp(int(value), tz=timezone.utc)
    except (TypeError, ValueError, OSError):
        return None


def _plan_from_price_id(price_id: str | None) -> str | None:
    """Reverse-map a Stripe price id to a local plan id, or ``None``."""
    if not price_id:
        return None
    if price_id == settings.STRIPE_PRICE_STARTER and price_id:
        return "starter"
    if price_id == settings.STRIPE_PRICE_PRO and price_id:
        return "pro"
    return None


def handle_webhook(payload: bytes, sig: str) -> dict[str, Any]:
    """Verify and process a Stripe webhook; upsert the org's Subscription.

    Verifies the signature against ``settings.STRIPE_WEBHOOK_SECRET`` and handles
    ``checkout.session.completed`` and ``customer.subscription.updated|deleted``
    by upserting the org's :class:`~app.models.Subscription` via
    :mod:`app.crud`. Returns a small status dict and **never raises** — any error
    is reported as ``{"error": ...}`` so the webhook route can always 200/400
    cleanly.

    A short-lived DB session is opened internally so this can be called directly
    from a router without threading a session through.
    """
    stripe = _load_stripe()
    if stripe is None:
        return {"error": "stripe not configured"}
    if not settings.STRIPE_WEBHOOK_SECRET:
        return {"error": "no webhook secret configured"}

    try:
        event = stripe.Webhook.construct_event(
            payload, sig, settings.STRIPE_WEBHOOK_SECRET
        )
    except Exception as exc:
        return {"error": f"signature verification failed: {exc}"}

    etype = event.get("type", "")
    obj = (event.get("data") or {}).get("object") or {}

    from .database import SessionLocal

    db = SessionLocal()
    try:
        if etype == "checkout.session.completed":
            handled = _apply_checkout_completed(db, obj)
        elif etype in (
            "customer.subscription.updated",
            "customer.subscription.deleted",
        ):
            handled = _apply_subscription_change(db, etype, obj)
        else:
            return {"ok": True, "ignored": etype}
        db.commit()
        return {"ok": True, "type": etype, **handled}
    except Exception as exc:  # pragma: no cover - defensive
        db.rollback()
        return {"error": f"webhook handling failed: {exc}"}
    finally:
        db.close()


def _org_id_from_metadata(obj: dict[str, Any]) -> int | None:
    """Extract our ``org_id`` from a Stripe object's metadata, if present."""
    meta = obj.get("metadata") or {}
    raw = meta.get("org_id")
    try:
        return int(raw) if raw is not None else None
    except (TypeError, ValueError):
        return None


def _apply_checkout_completed(
    db: Session, obj: dict[str, Any]
) -> dict[str, Any]:
    """Handle ``checkout.session.completed``: activate the org's subscription."""
    org_id = _org_id_from_metadata(obj)
    if org_id is None:
        return {"note": "no org_id in metadata"}
    plan = (obj.get("metadata") or {}).get("plan") or "free"
    crud.upsert_subscription(
        db,
        org_id,
        customer_id=obj.get("customer"),
        subscription_id=obj.get("subscription"),
        plan=plan,
        status="active",
    )
    return {"org_id": org_id, "plan": plan}


def _apply_subscription_change(
    db: Session, etype: str, obj: dict[str, Any]
) -> dict[str, Any]:
    """Handle subscription updated/deleted: sync plan/status/period end."""
    org_id = _org_id_from_metadata(obj)
    fields: dict[str, Any] = {
        "subscription_id": obj.get("id"),
        "customer_id": obj.get("customer"),
        "current_period_end": _coerce_period_end(obj.get("current_period_end")),
    }
    if etype == "customer.subscription.deleted":
        fields["status"] = "canceled"
        fields["plan"] = "free"
    else:
        fields["status"] = obj.get("status") or "active"
        # Best-effort: derive plan from the first line-item price id.
        items = ((obj.get("items") or {}).get("data")) or []
        price_id = None
        if items:
            price_id = (items[0].get("price") or {}).get("id")
        plan = _plan_from_price_id(price_id)
        if plan:
            fields["plan"] = plan

    if org_id is not None:
        crud.upsert_subscription(db, org_id, **fields)
        return {"org_id": org_id, "status": fields.get("status")}

    # Fall back to locating the org by its Stripe customer id.
    sub = crud.get_subscription_by_customer(db, obj.get("customer"))
    if sub is not None:
        crud.upsert_subscription(db, sub.org_id, **fields)
        return {"org_id": sub.org_id, "status": fields.get("status")}
    return {"note": "no matching subscription for customer"}

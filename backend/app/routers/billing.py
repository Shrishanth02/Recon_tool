"""Billing, quota, and licensing routes (Phase 3).

These endpoints surface the billing core (:mod:`app.billing`, :mod:`app.plans`,
:mod:`app.licensing`) over HTTP. They are additive and safe in every billing
mode:

* The plan catalog (``GET /billing/plans``) is public and pure-data.
* Per-org status/checkout/portal/license routes are tenant-scoped via the same
  :func:`app.deps.require_role` gate the rest of the platform uses (reads need
  ``viewer+``; state changes need ``admin+``).
* The Stripe webhook is unauthenticated at the HTTP layer but authenticated by
  signature inside :func:`app.billing.handle_webhook`.

When ``BILLING_MODE == "none"`` the status route still answers (reporting the
disabled mode and generous no-op limits) and the Stripe/license routes degrade
gracefully — nothing here can regress the inline scanning or auth flows.
"""

from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Path, Request, status
from sqlalchemy.orm import Session

from .. import billing, crud, licensing, models, plans, schemas
from ..config import settings
from ..deps import get_db, require_role

router = APIRouter(tags=["billing"])


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _load_org(db: Session, org_id: int) -> models.Organization:
    """Load the org row or raise 404 (the caller's membership is already checked)."""
    org = crud.get_org(db, org_id)
    if not org:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Organization not found")
    return org


def _exp_to_datetime(exp: Any) -> datetime | None:
    """Convert a license payload's unix ``exp`` to an aware datetime (or None)."""
    if exp is None:
        return None
    try:
        return datetime.fromtimestamp(int(exp), tz=timezone.utc)
    except (TypeError, ValueError, OSError):
        return None


# --------------------------------------------------------------------------- #
# Public plan catalog
# --------------------------------------------------------------------------- #
@router.get("/billing/plans", response_model=list[schemas.PlanOut])
def list_plans():
    """Return the static plan catalog (public, no auth)."""
    return [
        schemas.PlanOut(
            id=plan_id,
            name=plan["name"],
            price_usd_month=plan["price_usd_month"],
            limits=dict(plan["limits"]),
        )
        for plan_id, plan in plans.PLANS.items()
    ]


# --------------------------------------------------------------------------- #
# Org billing status
# --------------------------------------------------------------------------- #
@router.get("/orgs/{org_id}/billing", response_model=schemas.BillingStatusOut)
def org_billing_status(
    org_id: int = Path(...),
    membership: models.Membership = Depends(require_role("viewer")),
    db: Session = Depends(get_db),
):
    """Return the org's billing posture: mode, effective plan, limits, usage (viewer+)."""
    org = _load_org(db, org_id)
    limits = billing.current_limits(db, org)
    features = {
        feat: billing.feature_allowed(db, org, feat) for feat in plans.FEATURE_KEYS
    }
    return schemas.BillingStatusOut(
        mode=(settings.BILLING_MODE or "none"),
        plan=billing.effective_plan(db, org),
        limits=limits,
        usage=billing.usage(db, org),
        features=features,
    )


# --------------------------------------------------------------------------- #
# Stripe checkout / portal (cloud mode)
# --------------------------------------------------------------------------- #
@router.post("/orgs/{org_id}/billing/checkout", response_model=schemas.CheckoutOut)
def create_checkout(
    payload: schemas.CheckoutIn,
    org_id: int = Path(...),
    membership: models.Membership = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    """Start a Stripe Checkout session to subscribe the org to ``plan`` (admin+).

    Returns the hosted checkout URL. If Stripe is unavailable/unconfigured or the
    plan is not purchasable, responds 400 with the error from the billing core
    (never a 500).
    """
    org = _load_org(db, org_id)
    result = billing.create_checkout_session(db, org, payload.plan)
    if "error" in result:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, result["error"])
    db.commit()  # persist any customer row created by _ensure_customer
    crud.audit(db, org_id, membership.user_id, "billing-checkout", payload.plan)
    db.commit()
    return schemas.CheckoutOut(url=result.get("url", ""))


@router.post("/orgs/{org_id}/billing/portal", response_model=schemas.CheckoutOut)
def create_portal(
    org_id: int = Path(...),
    membership: models.Membership = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    """Open a Stripe Billing Portal session for the org to manage its plan (admin+)."""
    org = _load_org(db, org_id)
    result = billing.create_portal_session(db, org)
    if "error" in result:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, result["error"])
    return schemas.CheckoutOut(url=result.get("url", ""))


# --------------------------------------------------------------------------- #
# Stripe webhook (signature-authenticated inside the billing core)
# --------------------------------------------------------------------------- #
@router.post("/billing/webhook")
async def stripe_webhook(request: Request):
    """Receive and process a Stripe webhook.

    The raw request body is read verbatim (signature verification requires the
    exact bytes) and passed with the ``Stripe-Signature`` header to
    :func:`app.billing.handle_webhook`, which verifies and applies the event and
    never raises. Always returns ``{"received": True}`` so Stripe does not retry
    on our processing errors; verification failures are reflected in the body.
    """
    payload = await request.body()
    sig = request.headers.get("stripe-signature", "")
    result = billing.handle_webhook(payload, sig)
    return {"received": True, **result}


# --------------------------------------------------------------------------- #
# Offline license (self-hosted mode)
# --------------------------------------------------------------------------- #
@router.get("/orgs/{org_id}/license", response_model=schemas.LicenseOut)
def get_license(
    org_id: int = Path(...),
    membership: models.Membership = Depends(require_role("viewer")),
    db: Session = Depends(get_db),
):
    """Return the install's active license, or the org's stored license (viewer+).

    Prefers the live, signature-verified ``settings.LICENSE_KEY`` payload (the
    authoritative source in self-hosted mode). Falls back to the most recent
    stored :class:`~app.models.License` row for the org. Reports ``valid: False``
    with an empty entitlement set when neither is present.
    """
    _load_org(db, org_id)

    payload = licensing.load_active_license()
    if payload:
        return schemas.LicenseOut(
            tier=str(payload.get("tier") or "free"),
            entitlements=payload,
            expires_at=_exp_to_datetime(payload.get("exp")),
            valid=True,
        )

    lic = crud.get_org_license(db, org_id)
    if lic:
        return schemas.LicenseOut(
            tier=lic.tier,
            entitlements=lic.entitlements or {},
            expires_at=lic.expires_at,
            valid=not lic.revoked,
        )

    return schemas.LicenseOut(tier="free", entitlements={}, expires_at=None, valid=False)


@router.post("/orgs/{org_id}/license", response_model=schemas.LicenseOut)
def install_license(
    payload: schemas.LicenseInstallIn,
    org_id: int = Path(...),
    membership: models.Membership = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    """Verify and record a signed license token for the org (admin+).

    The token is verified against the configured/default vendor public key. On a
    valid signature (and unexpired token) the decoded entitlements are persisted
    via :func:`app.crud.save_license` and returned. An invalid/expired/malformed
    token yields 400 with the verification reason.
    """
    org = _load_org(db, org_id)

    ok, result = licensing.verify_license(payload.token)
    if not ok or not isinstance(result, dict):
        reason = result if isinstance(result, str) else "invalid license token"
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(reason))

    key_id = str(result.get("jti") or "")
    if not key_id:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "license token has no id (jti)")

    expires_at = _exp_to_datetime(result.get("exp"))
    crud.save_license(
        db,
        org_id=org.id,
        key_id=key_id,
        tier=str(result.get("tier") or "free"),
        entitlements=result,
        expires_at=expires_at,
    )
    crud.audit(db, org_id, membership.user_id, "license-install", key_id)
    db.commit()

    return schemas.LicenseOut(
        tier=str(result.get("tier") or "free"),
        entitlements=result,
        expires_at=expires_at,
        valid=True,
    )

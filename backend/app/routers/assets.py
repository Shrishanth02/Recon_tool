"""Asset ownership-verification routes (the "moat").

An asset is a domain/IP a workspace claims to own. Ownership is proven by
publishing a DNS TXT record ``_reconx-verify.<domain>`` containing the asset's
verification token. This is Phase-1 scaffolding: the flow is fully implemented,
but the DNS lookup is best-effort (uses ``dnspython`` when available, otherwise
reports that it could not check).

Role gating: list — ``viewer+``; create/verify — ``analyst+``.
"""

from fastapi import APIRouter, Depends, HTTPException, Path, status
from sqlalchemy.orm import Session

from .. import billing, crud, models, schemas, security
from ..deps import get_current_user, get_db, get_workspace_for_user

router = APIRouter(tags=["assets"])

_TXT_PREFIX = "_reconx-verify"


def _require_ws_role(membership: models.Membership, min_role: str) -> None:
    if security.ROLE_RANK.get(membership.role, -1) < security.ROLE_RANK[min_role]:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, f"Requires role '{min_role}' or higher"
        )


def _asset_out(asset: models.Asset, *, with_instructions: bool = False) -> schemas.AssetOut:
    out = schemas.AssetOut.model_validate(asset)
    if with_instructions:
        record_name = f"{_TXT_PREFIX}.{asset.value}"
        out.dns_record_name = record_name
        out.dns_record_value = asset.verification_token
        out.instructions = (
            f'Create a DNS TXT record at "{record_name}" with the value '
            f'"{asset.verification_token}", then POST to '
            f"/assets/{asset.id}/verify."
        )
    return out


def _lookup_txt(name: str) -> tuple[list[str], str | None]:
    """Return ``(txt_values, error)`` for a DNS TXT lookup (best-effort).

    Uses ``dnspython`` if installed. ``error`` is a human-readable reason when
    the records could not be resolved (missing library, NXDOMAIN, timeout).
    """
    try:
        import dns.resolver  # type: ignore
    except Exception:
        return [], "DNS resolver (dnspython) is not available on the server."
    try:
        answers = dns.resolver.resolve(name, "TXT")
    except Exception as exc:  # noqa: BLE001 - NXDOMAIN, timeout, no-answer, ...
        return [], f"TXT lookup failed for {name}: {exc}"
    values: list[str] = []
    for rdata in answers:
        # Each TXT record may be split into multiple quoted strings.
        parts = getattr(rdata, "strings", None)
        if parts:
            values.append(b"".join(parts).decode("utf-8", "replace"))
        else:
            values.append(str(rdata).strip('"'))
    return values, None


@router.get("/workspaces/{ws_id}/assets", response_model=list[schemas.AssetOut])
def list_assets(
    ctx: tuple[models.Workspace, models.Membership] = Depends(get_workspace_for_user),
    db: Session = Depends(get_db),
):
    """List the assets registered under a workspace."""
    ws, _membership = ctx
    return [_asset_out(a) for a in crud.list_assets(db, ws.id)]


@router.post("/workspaces/{ws_id}/assets", response_model=schemas.AssetOut, status_code=201)
def create_asset(
    payload: schemas.AssetIn,
    ctx: tuple[models.Workspace, models.Membership] = Depends(get_workspace_for_user),
    db: Session = Depends(get_db),
):
    """Register an asset and return the DNS TXT proof it must publish."""
    ws, membership = ctx
    _require_ws_role(membership, "analyst")

    # --- Billing quota gate (Phase 3) --------------------------------------- #
    # No-op unless settings.billing_enabled; over the plan's asset limit -> 402.
    org = crud.get_org(db, ws.org_id)
    allowed, reason = billing.check_quota(db, org, "asset")
    if not allowed:
        crud.audit(db, ws.org_id, membership.user_id, "quota-denied", f"asset: {reason}")
        db.commit()
        raise HTTPException(status.HTTP_402_PAYMENT_REQUIRED, reason)

    asset = crud.create_asset(db, ws.id, payload.value, payload.atype)
    crud.audit(db, ws.org_id, membership.user_id, "asset-create", asset.value)
    db.commit()
    return _asset_out(asset, with_instructions=True)


@router.post("/assets/{asset_id}/verify", response_model=schemas.AssetOut)
def verify_asset(
    asset_id: int = Path(...),
    user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Resolve the asset's DNS TXT record and mark it verified on a match."""
    asset = crud.get_asset(db, asset_id)
    if not asset:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Asset not found")

    ws = crud.get_workspace(db, asset.workspace_id)
    membership = crud.get_membership(db, user.id, ws.org_id) if ws else None
    if not membership:
        # Same existence-hiding behavior as get_workspace_for_user.
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Asset not found")
    _require_ws_role(membership, "analyst")

    if asset.verified:
        return _asset_out(asset)

    record_name = f"{_TXT_PREFIX}.{asset.value}"
    values, error = _lookup_txt(record_name)
    if asset.verification_token in values:
        crud.mark_asset_verified(db, asset)
        crud.audit(db, ws.org_id, user.id, "asset-verify", asset.value)
        db.commit()
        return _asset_out(asset)

    detail = error or (
        f"No TXT record at {record_name} matched the expected token. "
        f"Publish the record and try again."
    )
    raise HTTPException(status.HTTP_400_BAD_REQUEST, detail)

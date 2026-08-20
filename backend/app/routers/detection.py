"""Purple-Team P3: detection-validation / SIEM-connector routes (BLUE side).

These routes turn the platform *purple*: after the SAFE emulation engine (P2)
fires ATT&CK techniques at an authorized target, the correlation engine
(:mod:`app.detection`) asks a defender SIEM/EDR connector, per technique, "did
you detect it?" and records the detected/missed verdict.

Two resource groups:

* **Detection connectors** — org-scoped SIEM/EDR integrations. Listing is
  member-gated (``viewer+``); creation and deletion are ``admin+``. Secrets in a
  connector's ``config`` are masked by :class:`schemas.DetectionConnectorOut` and
  never echoed back.
* **Validation** — ``POST /emulations/{run_id}/validate`` (``analyst+``) runs a
  connector against an emulation run and persists the results; ``GET
  /emulations/{run_id}/detections`` reads them back (member).

Role gating for the org-scoped connector routes reuses :func:`deps.require_role`.
The connector- and run-addressed routes (no ``org_id`` in the path) resolve the
owning org from the resource and enforce membership + role by hand, mirroring the
existing :func:`app.routers.emulation.get_emulation` pattern (404 hides existence
from non-members).
"""

from fastapi import APIRouter, Depends, HTTPException, Path, Query, status
from sqlalchemy.orm import Session

from .. import connectors, crud, detection, models, schemas, security
from ..deps import get_current_user, get_db, require_role

router = APIRouter(tags=["detection"])


# --------------------------------------------------------------------------- #
# Detection connectors (org-scoped)
# --------------------------------------------------------------------------- #
@router.get(
    "/orgs/{org_id}/detection-connectors",
    response_model=list[schemas.DetectionConnectorOut],
)
def list_detection_connectors(
    org_id: int = Path(...),
    membership: models.Membership = Depends(require_role("viewer")),
    db: Session = Depends(get_db),
):
    """List an org's detection connectors (member; secrets masked)."""
    return [
        schemas.DetectionConnectorOut.from_connector(c)
        for c in crud.list_detection_connectors(db, org_id)
    ]


@router.post(
    "/orgs/{org_id}/detection-connectors",
    response_model=schemas.DetectionConnectorOut,
    status_code=201,
)
def create_detection_connector(
    payload: schemas.DetectionConnectorIn,
    org_id: int = Path(...),
    membership: models.Membership = Depends(require_role("admin")),
    db: Session = Depends(get_db),
):
    """Create a detection connector for an org (admin+; ``ctype`` validated)."""
    if payload.ctype not in connectors.CONNECTOR_TYPES:
        known = ", ".join(sorted(connectors.CONNECTOR_TYPES))
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"Unknown connector type '{payload.ctype}'. Known types: {known}",
        )
    connector = crud.create_detection_connector(
        db,
        org_id=org_id,
        name=payload.name,
        ctype=payload.ctype,
        config=payload.config,
        enabled=payload.enabled,
    )
    crud.audit(
        db, org_id, membership.user_id,
        "detection-connector-create", f"{payload.name} ({payload.ctype})",
    )
    db.commit()
    db.refresh(connector)
    return schemas.DetectionConnectorOut.from_connector(connector)


@router.delete("/detection-connectors/{connector_id}")
def delete_detection_connector(
    connector_id: int = Path(...),
    user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Delete a detection connector (admin+ of its owning org).

    The connector's org is resolved from the row; a non-member gets a 404 (so
    connector existence isn't leaked), and a member below ``admin`` gets a 403.
    Historical detection results survive (their FK is SET NULL).
    """
    connector = crud.get_detection_connector(db, connector_id)
    if not connector:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Connector not found")
    membership = crud.get_membership(db, user.id, connector.org_id)
    if not membership:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Connector not found")
    if security.ROLE_RANK.get(membership.role, -1) < security.ROLE_RANK["admin"]:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, "Requires role 'admin' or higher"
        )
    crud.delete_detection_connector(db, connector)
    crud.audit(
        db, connector.org_id, user.id,
        "detection-connector-delete", f"{connector.name} ({connector.ctype})",
    )
    db.commit()
    return {"deleted": connector_id}


# --------------------------------------------------------------------------- #
# Validation (run-scoped)
# --------------------------------------------------------------------------- #
def _run_org_and_membership(
    db: Session, user: models.User, run: models.EmulationRun
) -> tuple[models.Workspace, models.Membership]:
    """Resolve an emulation run's workspace + the caller's membership (404 else)."""
    ws = crud.get_workspace(db, run.workspace_id)
    if not ws:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Emulation run not found")
    membership = crud.get_membership(db, user.id, ws.org_id)
    if not membership:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Emulation run not found")
    return ws, membership


@router.post(
    "/emulations/{run_id}/validate",
    response_model=schemas.DetectionValidateOut,
)
def validate_emulation(
    run_id: int = Path(...),
    connector_id: int = Query(..., description="Detection connector to query"),
    user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Validate an emulation run against a SIEM/EDR connector (analyst+).

    Resolves the run -> workspace -> org, enforces the analyst role, loads the
    (same-org) connector, runs :func:`app.detection.validate_emulation`, persists
    a :class:`~app.models.DetectionResult` per technique, and returns
    ``{results, summary}``.
    """
    run = crud.get_emulation_run(db, run_id)
    if not run:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Emulation run not found")
    ws, membership = _run_org_and_membership(db, user, run)

    if security.ROLE_RANK.get(membership.role, -1) < security.ROLE_RANK["analyst"]:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, "Requires role 'analyst' or higher"
        )

    connector_row = crud.get_detection_connector(db, connector_id)
    # The connector must exist and belong to the run's org (cross-tenant use is a
    # 404, not a 403, to avoid leaking connector existence across tenants).
    if not connector_row or connector_row.org_id != ws.org_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Connector not found")
    if not connector_row.enabled:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, "Connector is disabled"
        )

    try:
        connector = connectors.get_connector(
            connector_row.ctype, connector_row.config
        )
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc))

    results, summary = detection.validate_emulation(db, run, connector)
    crud.save_detection_results(db, run.id, connector_row.id, results)
    crud.audit(
        db, ws.org_id, user.id, "detection-validate",
        f"run {run.id} via {connector_row.ctype}: "
        f"{summary['detected']}/{summary['total']} detected "
        f"({summary['coverage_pct']}%)",
    )
    db.commit()
    return schemas.DetectionValidateOut(
        results=[schemas.DetectionResultOut.model_validate(r) for r in
                 crud.list_detection_results(db, run.id)],
        summary=schemas.DetectionSummaryOut(**summary),
    )


@router.get(
    "/emulations/{run_id}/detections",
    response_model=list[schemas.DetectionResultOut],
)
def list_emulation_detections(
    run_id: int = Path(...),
    user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List the persisted detection results for an emulation run (member)."""
    run = crud.get_emulation_run(db, run_id)
    if not run:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Emulation run not found")
    _run_org_and_membership(db, user, run)
    return [
        schemas.DetectionResultOut.model_validate(r)
        for r in crud.list_detection_results(db, run.id)
    ]

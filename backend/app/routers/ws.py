"""Real-time scan streaming over WebSocket.

``WS /ws/scan`` authenticates via a query parameter (browsers cannot set custom
WebSocket headers): ``?token=<access JWT>`` **or** ``?key=<rcx_ api key>``. The
first JSON message is the scan request ``{tool, target, options, workspace_id}``.

Live scan execution is delegated to :func:`app.execution.stream`, which owns the
netguard SSRF check, the shared inline concurrency cap, the threaded scanner
pump, and the ``start → log/result/error → saved → done`` event handshake. This
router keeps the transport concerns: principal authentication, workspace
resolution + scope enforcement, the Phase 2 verified-asset gate, wiring
``{"action":"stop"}`` to the job's cancel handle, and persisting through
``crud.save_scan`` with ``workspace_id`` + ``created_by``. In inline mode
(the default) the observable behavior is byte-for-byte what it was before.
"""

import asyncio

import jwt
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from .. import billing, crud, execution, models, scope, security
from ..database import SessionLocal
from ..scanners import get_scanner

router = APIRouter()


def _authenticate(db, token: str | None, key: str | None) -> tuple[models.User | None, models.ApiKey | None]:
    """Resolve a WebSocket caller from ``?token=`` or ``?key=``.

    Returns ``(user, api_key)`` with exactly one populated, or ``(None, None)``
    when authentication fails.
    """
    if key:
        api_key = crud.resolve_api_key(db, key.strip())
        db.commit()  # persist last_used_at bump
        if api_key:
            return None, api_key
        return None, None
    if token:
        try:
            claims = security.decode_token(token)
        except jwt.PyJWTError:
            return None, None
        if claims.get("type") != "access":
            return None, None
        user = crud.get_user(db, int(claims.get("sub", 0)))
        if user and user.is_active:
            return user, None
    return None, None


def _resolve_workspace(db, user, api_key, ws_id: int) -> models.Workspace | None:
    """Resolve + authorize the target workspace for the authenticated caller."""
    if not ws_id:
        if api_key is not None:
            org_id = api_key.org_id
        else:
            orgs = crud.list_user_orgs(db, user)
            org_id = orgs[0].id if orgs else None
        if org_id is None:
            return None
        ws_id = crud.default_workspace_id_for_org(db, org_id)
        if not ws_id:
            return None

    ws = crud.get_workspace(db, ws_id)
    if not ws:
        return None
    if api_key is not None:
        return ws if api_key.org_id == ws.org_id else None

    membership = crud.get_membership(db, user.id, ws.org_id)
    if not membership:
        return None
    if security.ROLE_RANK.get(membership.role, -1) < security.ROLE_RANK["analyst"]:
        return None
    return ws


@router.websocket("/ws/scan")
async def ws_scan(websocket: WebSocket):
    """Authenticate, run one scan, stream its events, and persist the result."""
    await websocket.accept()

    db = SessionLocal()
    try:
        # --- Authentication (query params, since WS can't carry headers) ----- #
        token = websocket.query_params.get("token")
        key = websocket.query_params.get("key")
        user, api_key = _authenticate(db, token, key)
        if user is None and api_key is None:
            await websocket.send_json({"type": "error", "data": "Authentication failed."})
            await websocket.send_json({"type": "done"})
            await websocket.close()
            return

        # --- Scan request ---------------------------------------------------- #
        try:
            request = await websocket.receive_json()
        except Exception:
            await websocket.close()
            return

        tool_id = request.get("tool")
        target = (request.get("target") or "").strip()
        options = request.get("options") or {}
        ws_id = request.get("workspace_id") or 0

        async def reject(message: str):
            await websocket.send_json({"type": "error", "data": message})
            await websocket.send_json({"type": "done"})
            await websocket.close()

        scanner = get_scanner(tool_id)
        if scanner is None:
            await reject(f"Unknown tool: {tool_id}")
            return
        if not target:
            await reject("A target is required.")
            return

        workspace = _resolve_workspace(db, user, api_key, ws_id)
        if workspace is None:
            await reject("Workspace not found or insufficient permissions.")
            return

        # --- Scope enforcement ---------------------------------------------- #
        allowed, reason = scope.check(target, workspace.scope)
        if not allowed:
            crud.audit(
                db, workspace.org_id, user.id if user else None,
                "scope-denied", f"{tool_id} {target}: {reason}",
            )
            db.commit()
            await reject(f"⛔ {reason}")
            return

        # --- Verified-asset gate (Phase 2) ---------------------------------- #
        # No-op unless settings.REQUIRE_VERIFIED_ASSET is on; enforced here (the
        # router owns this gate, per the contract) before any execution begins.
        if not crud.is_target_authorized(db, workspace.id, target):
            crud.audit(
                db, workspace.org_id, user.id if user else None,
                "asset-denied", f"{tool_id} {target}",
            )
            db.commit()
            await reject("⛔ Target is not a verified asset for this workspace.")
            return

        # --- Billing quota gate (Phase 3) ----------------------------------- #
        # No-op unless settings.billing_enabled; billing.check_quota returns
        # (True, "billing disabled") when off. When active, a scan over the
        # plan's monthly limit is refused (error + done + close, like scope).
        org = crud.get_org(db, workspace.org_id)
        allowed, reason = billing.check_quota(db, org, "scan")
        if not allowed:
            crud.audit(
                db, workspace.org_id, user.id if user else None,
                "quota-denied", f"scan: {reason}",
            )
            db.commit()
            await reject(f"⛔ {reason}")
            return

        # --- Delegate execution to the shared core -------------------------- #
        # execution.stream owns netguard, the concurrency cap, the threaded
        # scanner pump, and the start/saved/done handshake — this router only
        # forwards events and wires the stop action to the job's cancel handle.
        job = execution.Job(
            tool=tool_id,
            target=target,
            options=options,
            workspace_id=workspace.id,
            created_by=user.id if user else None,
        )

        def on_persist(record: dict):
            """Persist the finished scan (called once by execution.stream)."""
            scan = crud.save_scan(db, record)
            crud.audit(
                db, workspace.org_id, user.id if user else None,
                "scan", f"{tool_id} {target} ({record.get('status')})",
            )
            db.commit()
            return scan

        async def receiver():
            """Turn a browser ``{"action":"stop"}`` into a cancel signal."""
            try:
                while True:
                    message = await websocket.receive_json()
                    if message.get("action") == "stop":
                        job.cancel.set()
                        return
            except Exception:  # noqa: BLE001 - disconnect/garbled frame -> stop
                job.cancel.set()

        receiver_task = asyncio.create_task(receiver())
        try:
            async for event in execution.stream(job, on_persist=on_persist):
                try:
                    await websocket.send_json(event)
                except (WebSocketDisconnect, RuntimeError):
                    job.cancel.set()
                    break
        finally:
            job.cancel.set()
            receiver_task.cancel()
            try:
                await websocket.close()
            except RuntimeError:
                pass
    finally:
        db.close()

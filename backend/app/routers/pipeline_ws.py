"""WebSocket endpoint for the automated end-to-end pentesting pipeline.

``WS /ws/pipeline`` authenticates identically to ``/ws/scan`` (query-param
``?token=`` or ``?key=``). The first JSON message is:

    {
        "target":       "example.com",
        "workspace_id": 1,
        "config": {                          // optional overrides
            "nmap_profile":       "service",
            "nuclei_severity":    "low,medium,high,critical",
            "max_http_targets":   50,
            "max_nmap_targets":   10,
            "max_nuclei_targets": 20,
            "max_dirbust_targets": 5,
            "dns_zone_transfer":  true
        }
    }

The server streams pipeline events until completion, then closes the socket.
Sending ``{"action": "stop"}`` cancels the run gracefully.
"""

import asyncio
import threading

import jwt
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from .. import billing, correlate, crud, netguard, pipeline, ratelimit, risk, scope, security, validate
from ..config import settings
from ..database import SessionLocal
from ..pipeline import PipelineConfig
from .ws import _ws_credentials  # shared: WS credential via Sec-WebSocket-Protocol

router = APIRouter()


def _extract_auth(raw) -> dict | None:
    """Sanitize the operator-supplied authenticated-session config.

    Keeps only known session fields and drops empties, returning ``None`` when
    nothing usable was supplied. The result is passed to the pipeline TRANSIENTLY
    and is never persisted. Credentials are used solely to drive the operator's
    own authenticated scanning — never stored, logged, or echoed.

    The kept keys are exactly the option names the downstream scanners READ:
      * ``auth_crawl`` reads ``cookie``/``auth_header``/``username``/``password``/
        ``login_url`` and the login-form selectors ``user_sel``/``pass_sel``/
        ``submit_sel`` (NOT ``*_selector`` — a prior mismatch dropped custom
        selectors so the crawler always fell back to its defaults);
      * ``jwt_audit`` reads ``token`` (a standalone JWT the operator wants
        statically analysed) — previously stripped here, so the JWT/API stage
        never received an operator-supplied token.
    """
    if not isinstance(raw, dict):
        return None
    allowed = ("cookie", "auth_header", "username", "password", "token", "login_url",
               "user_sel", "pass_sel", "submit_sel")
    out = {}
    for k in allowed:
        v = raw.get(k)
        if isinstance(v, str) and v.strip():
            out[k] = v.strip()
    return out or None


def _extract_identities(raw) -> list | None:
    """Sanitize the optional list of authorized test identities for IDOR.

    Each identity keeps only a label + session material (cookie / auth_header),
    dropping empties. TRANSIENT — never persisted; used solely to compare access
    between operator-authorized accounts. Returns ``None`` when fewer than two
    usable identities are supplied.
    """
    if not isinstance(raw, list):
        return None
    out = []
    for n, item in enumerate(raw):
        if not isinstance(item, dict):
            continue
        ident = {}
        label = item.get("label")
        if isinstance(label, str) and label.strip():
            ident["label"] = label.strip()
        else:
            ident["label"] = chr(ord("A") + n)
        for k in ("cookie", "auth_header"):
            v = item.get(k)
            if isinstance(v, str) and v.strip():
                ident[k] = v.strip()
        # Optional privilege rank (higher = more privileged) for the role-matrix
        # authorization scan; IDOR ignores it. Defaults to list order downstream.
        p = item.get("privilege")
        if isinstance(p, int) and not isinstance(p, bool) and p >= 0:
            ident["privilege"] = p
        if ident.get("cookie") or ident.get("auth_header"):
            out.append(ident)
    return out if len(out) >= 2 else None


def _authenticate(db, token: str | None, key: str | None):
    """Identical to ws.py — resolve caller from ?token= or ?key=."""
    if key:
        api_key = crud.resolve_api_key(db, key.strip())
        db.commit()
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
        if (
            user and user.is_active
            and not security.is_token_revoked(claims.get("ver"), user.token_version)
        ):
            return user, None
    return None, None


def _resolve_workspace(db, user, api_key, ws_id: int):
    """Resolve + authorize the target workspace."""
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


@router.websocket("/ws/pipeline")
async def ws_pipeline(websocket: WebSocket):
    """Authenticate, run the full auto-pentest pipeline, stream events, persist."""
    token, key, _subproto = _ws_credentials(websocket)
    await websocket.accept(subprotocol=_subproto)

    # P1-H2: rate-limit pipeline WS connections by client IP (scan bucket) BEFORE
    # auth so an attacker cannot open unlimited pipeline sockets.
    if settings.RATE_LIMIT_ENABLED:
        _ip = ratelimit.resolve_client_ip(
            websocket.client.host if websocket.client else None,
            websocket.headers.get("x-forwarded-for"),
            settings.rate_limit_trusted_proxies,
        )
        if not ratelimit.limiter().check(ratelimit.SCAN, _ip)[0].allowed:
            await websocket.send_json(
                {"type": "pipeline_log", "stage": 0,
                 "data": "Rate limit exceeded. Try again shortly."}
            )
            await websocket.close()
            return

    db = SessionLocal()
    try:
        # Credential from the Sec-WebSocket-Protocol header (read above); the
        # deprecated ?token=/?key= query string is handled as a fallback there.
        user, api_key = _authenticate(db, token, key)

        async def reject(msg: str) -> None:
            await websocket.send_json({"type": "pipeline_log", "stage": 0, "data": msg})
            await websocket.send_json({"type": "pipeline_done", "risk_score": 0, "summary": {}})
            await websocket.close()

        if user is None and api_key is None:
            await reject("Authentication failed.")
            return

        try:
            request = await websocket.receive_json()
        except Exception:
            await websocket.close()
            return

        target = (request.get("target") or "").strip()
        ws_id = request.get("workspace_id") or 0
        raw_config = request.get("config") or {}

        if not target:
            await reject("A target is required.")
            return

        workspace = _resolve_workspace(db, user, api_key, ws_id)
        if workspace is None:
            await reject("Workspace not found or insufficient permissions.")
            return

        # Scope check against the root domain
        allowed, reason = scope.check(target, workspace.scope)
        if not allowed:
            crud.audit(
                db, workspace.org_id, user.id if user else None,
                "scope-denied", f"pipeline {target}: {reason}",
            )
            db.commit()
            await reject(f"⛔ {reason}")
            return

        # SSRF / egress safety on the root target (mirrors every other scan path;
        # netguard runs regardless of scope so an empty/"*" scope can never point
        # the pipeline at loopback / RFC-1918 / link-local / cloud-metadata).
        safe, nreason = netguard.validate_target(target)
        if not safe:
            crud.audit(
                db, workspace.org_id, user.id if user else None,
                "pipeline-target-blocked", f"pipeline {target}: {nreason}",
            )
            db.commit()
            await reject(f"⛔ {nreason}")
            return

        # Billing quota
        org = crud.get_org(db, workspace.org_id)
        allowed, reason = billing.check_quota(db, org, "scan")
        if not allowed:
            await reject(f"⛔ {reason}")
            return

        # Build config from request overrides. NOTE: ``auth`` is TRANSIENT — it is
        # carried only in-memory for this run and is never written to the DB (the
        # PentestRun stores only the target; per-tool records store options={};
        # the process blob stores stage logs/results, and auth_crawl's result
        # exposes only login_method/auth_note, never the credentials).
        cfg = PipelineConfig(
            nmap_profile=raw_config.get("nmap_profile", "service"),
            nuclei_severity=raw_config.get("nuclei_severity", "low,medium,high,critical"),
            max_http_targets=int(raw_config.get("max_http_targets", 50)),
            max_nmap_targets=int(raw_config.get("max_nmap_targets", 10)),
            max_nuclei_targets=int(raw_config.get("max_nuclei_targets", 20)),
            max_dirbust_targets=int(raw_config.get("max_dirbust_targets", 5)),
            dns_zone_transfer=bool(raw_config.get("dns_zone_transfer", True)),
            max_takeover_targets=int(raw_config.get("max_takeover_targets", 25)),
            max_injection_targets=int(raw_config.get("max_injection_targets", 10)),
            max_ssrf_targets=int(raw_config.get("max_ssrf_targets", 5)),
            auth=_extract_auth(raw_config.get("auth")),
            auth_identities=_extract_identities(raw_config.get("auth_identities")),
        )

        cancel = threading.Event()

        # Record this auto-pentest as a first-class PentestRun envelope so its
        # aggregate risk lives alongside the manual scan history.
        run = crud.create_pentest_run(
            db, workspace.id, user.id if user else None, target
        )
        db.commit()
        run_finished = False
        crashed = False  # set when the pipeline emits its typed terminal error

        # Capture identifiers as plain values so the worker-thread persistence
        # callback never has to touch a coroutine-bound ORM object (which would be
        # a second kind of cross-thread sharing).
        ws_pk = workspace.id
        created_by = user.id if user else None

        def _persist(rec: dict) -> None:
            """Persist one per-tool pipeline result (also derives Findings).

            Runs on the pipeline's WORKER THREAD: ``run_pipeline`` executes its
            whole stage body inside ``loop.run_in_executor`` and calls this
            synchronously from there. SQLAlchemy Sessions are NOT thread-safe, so
            this owns a SHORT-LIVED Session of its own — never the event loop's
            ``db`` — created, committed/rolled-back, and closed entirely on this
            thread. A failed save therefore rolls back only its own small
            transaction (it can never corrupt the coroutine's session) and is
            swallowed so the run keeps streaming. The session is always closed.
            """
            s = SessionLocal()
            try:
                crud.save_scan(
                    s,
                    {**rec, "workspace_id": ws_pk, "created_by": created_by},
                )
                s.commit()
            except Exception:
                s.rollback()
            finally:
                s.close()

        async def receiver():
            try:
                while True:
                    msg = await websocket.receive_json()
                    if msg.get("action") == "stop":
                        cancel.set()
                        return
            except Exception:
                cancel.set()

        # Accumulate the full stage-by-stage process so the run can be replayed
        # from history. Logs are tail-capped per stage (nuclei streams thousands
        # of progress lines) — the trailing ✔ summary line is what we keep.
        process: dict = {"stages": {}, "summary": {}}

        def _save_process() -> None:
            try:
                run.process = {
                    "stages": {k: dict(v) for k, v in process["stages"].items()},
                    "summary": process["summary"],
                }
                db.add(run)
                db.commit()
            except Exception:
                db.rollback()

        def _accumulate(event: dict) -> None:
            et = event.get("type")
            sid = str(event.get("stage")) if event.get("stage") is not None else None
            if et == "pipeline_stage" and sid:
                st = process["stages"].setdefault(sid, {"logs": []})
                st["name"] = event.get("name", st.get("name", ""))
                st["status"] = event.get("status", "")
            elif et == "pipeline_log" and sid:
                st = process["stages"].setdefault(sid, {"logs": []})
                logs = st.setdefault("logs", [])
                logs.append(event.get("data", ""))
                if len(logs) > 80:
                    del logs[:-80]
            elif et == "pipeline_result" and sid:
                st = process["stages"].setdefault(sid, {"logs": []})
                st["result"] = event.get("data")
                st["name"] = event.get("name", st.get("name", ""))
            elif et == "pipeline_done":
                process["summary"] = event.get("summary", {})

        receiver_task = asyncio.create_task(receiver())
        try:
            async for event in pipeline.run_pipeline(
                target,
                cancel=cancel,
                config=cfg,
                workspace_id=workspace.id,
                created_by=user.id if user else None,
                scope_list=workspace.scope,
                persist=_persist,
            ):
                _accumulate(event)
                # A typed terminal error means the pipeline CRASHED (vs a user
                # Stop) — record it so the run is finalized "failed", not "stopped".
                if event.get("type") == "error":
                    crashed = True
                # Persist the process at each stage boundary so an interrupted
                # run still keeps everything completed up to that point.
                if event.get("type") == "pipeline_stage" and event.get("status") in (
                    "done", "error", "skipped", "stopped",
                ):
                    _save_process()
                # Finalize the PentestRun envelope from the summary event.
                if event.get("type") == "pipeline_done":
                    _save_process()
                    # P1a: safe Tier-2 validation — re-verify SIGNAL findings
                    # non-destructively (own session, off the event loop; every
                    # request is scope- + netguard-gated inside validate). Must
                    # never break run finalization.
                    try:
                        await asyncio.get_running_loop().run_in_executor(
                            None, validate.validate_workspace, workspace.id, workspace.scope
                        )
                        db.expire_all()  # see the validated tiers on our session
                    except Exception as exc:  # noqa: BLE001
                        await websocket.send_json({
                            "type": "pipeline_log", "stage": 0,
                            "data": f"⚠ validation step error: {exc}",
                        })
                    # P1b: cross-scanner correlation (pure DB, no network).
                    try:
                        correlate.correlate_workspace(db, workspace.id)
                        db.flush()
                    except Exception as exc:  # noqa: BLE001
                        db.rollback()
                        await websocket.send_json({
                            "type": "pipeline_log", "stage": 0,
                            "data": f"⚠ correlation step error: {exc}",
                        })
                    # Authoritative risk: recompute from the PERSISTED, validated,
                    # correlated, deduplicated findings using the same scorer the
                    # /risk endpoint uses, so a run's risk and the workspace risk
                    # are always consistent.
                    _db_findings = crud.list_findings(db, workspace.id)
                    _risk = risk.workspace_risk(_db_findings)
                    _summary = {
                        **(event.get("summary") or {}),
                        "risk_score": _risk["score"],
                        "risk_label": _risk["rating"],
                    }
                    crud.finish_pentest_run(
                        db, run, "done", _risk["score"], _risk["rating"], _summary,
                    )
                    db.commit()
                    run_finished = True
                try:
                    await websocket.send_json(event)
                except (WebSocketDisconnect, RuntimeError):
                    cancel.set()
                    break

            crud.audit(
                db, workspace.org_id, user.id if user else None,
                "pipeline", f"auto-pentest {target}",
            )
            db.commit()
        finally:
            cancel.set()
            receiver_task.cancel()
            # A run aborted before pipeline_done never got finalized — mark it
            # terminal so it doesn't linger "running". A crash (typed error) is
            # "failed"; a user Stop / disconnect is "stopped" — distinguishable
            # for monitoring and in the run history.
            if not run_finished:
                try:
                    _save_process()
                    _final_status = "failed" if crashed else "stopped"
                    crud.finish_pentest_run(
                        db, run, _final_status, run.risk_score, run.risk_label, run.summary
                    )
                    db.commit()
                except Exception:
                    db.rollback()
            try:
                await websocket.close()
            except RuntimeError:
                pass
    finally:
        db.close()

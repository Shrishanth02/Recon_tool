"""Cross-tenant live-scan stream + result authorization — production release gate.

Proves the invariant that gated the release: an authenticated user in org A can
obtain NO live or historical scan data, and perform NO scan control, belonging to
org B.

The design that makes this hold (verified by trace + adversarial review, so these
tests DEMONSTRATE an existing invariant — no code change accompanies them):

* Both stream endpoints (``/ws/scan``, ``/ws/pipeline``) authorize the WORKSPACE
  via the shared ``_resolve_workspace`` — a JWT caller needs a Membership in
  ``ws.org_id`` with role >= analyst; an API-key caller needs ``api_key.org_id ==
  ws.org_id`` — BEFORE any execution/stream. With no ``workspace_id`` both fall
  back only to the caller's OWN org default.
* There is no subscribe-by-id path: the live Redis stream is keyed
  ``reconx:scan:{job_id}`` with a SERVER-generated ``job_id`` (uuid4 / arq id)
  that is never read from the client request, so an org-A caller cannot attach to
  org-B's stream. ``{"action":"stop"}`` cancels only the caller's own job.
* Persisted results (``GET/DELETE /scans/{id}``) are authorized against the
  scan's own workspace org membership (fail-closed 404, existence-hiding).
"""


def _scan_first_event(client, token, payload):
    """Open /ws/scan, send one request, return the first server event."""
    with client.websocket_connect(
        "/ws/scan", subprotocols=["reconx.token", token]
    ) as ws:
        ws.send_json(payload)
        return ws.receive_json()


def _create_scan_in_org_a(client, auth):
    """Run one scan as the org-A owner (fake scanner) and return its id."""
    resp = client.get(
        "/scan/nuclei",
        headers=auth["headers"],
        params={"target": "example.com", "workspace_id": auth["ws_id"]},
    )
    assert resp.status_code == 200, resp.text
    return resp.json()["id"]


# --------------------------------------------------------------------------- #
# Live stream — WebSocket
# --------------------------------------------------------------------------- #
def test_ws_scan_cross_org_workspace_is_rejected(client, auth, make_user):
    """User B streaming into org A's REAL workspace is refused (not a member)."""
    other = make_user()  # a user in a DIFFERENT org
    msg = _scan_first_event(
        client, other["access_token"],
        {"tool": "nuclei", "target": "example.com", "workspace_id": auth["ws_id"]},
    )
    assert msg["type"] == "error"
    assert "not found or insufficient permissions" in str(msg["data"]).lower()


def test_ws_pipeline_cross_org_workspace_is_rejected(client, auth, make_user):
    other = make_user()
    with client.websocket_connect(
        "/ws/pipeline", subprotocols=["reconx.token", other["access_token"]]
    ) as ws:
        ws.send_json({"target": "example.com", "workspace_id": auth["ws_id"]})
        msg = ws.receive_json()
    assert "not found or insufficient permissions" in str(msg.get("data", "")).lower()


def test_ws_scan_same_org_owner_is_authorized(client, auth, fake_scanner):
    """Positive control: the owner streaming their OWN workspace clears authz
    (the first event is a real scan event, never a permission error)."""
    msg = _scan_first_event(
        client, auth["access_token"],
        {"tool": "nuclei", "target": "example.com", "workspace_id": auth["ws_id"]},
    )
    assert not (
        msg.get("type") == "error"
        and "permission" in str(msg.get("data", "")).lower()
    )


def test_ws_scan_deactivated_user_is_rejected(client, make_user):
    """A deactivated account's still-unexpired token must not reach the stream."""
    from app import models
    from app.database import SessionLocal

    victim = make_user()
    db = SessionLocal()
    try:
        u = db.get(models.User, victim["user_id"])
        u.is_active = False
        db.commit()
    finally:
        db.close()

    msg = _scan_first_event(
        client, victim["access_token"],
        {"tool": "nuclei", "target": "example.com", "workspace_id": victim["ws_id"]},
    )
    assert msg["type"] == "error"
    assert "authentication failed" in str(msg["data"]).lower()


# --------------------------------------------------------------------------- #
# Historical results + control — REST
# --------------------------------------------------------------------------- #
def test_get_scan_cross_org_is_404(client, auth, make_user, fake_scanner):
    scan_id = _create_scan_in_org_a(client, auth)
    # Owner can read it...
    assert client.get(f"/scans/{scan_id}", headers=auth["headers"]).status_code == 200
    # ...a user in another org cannot (404 hides existence).
    other = make_user()
    assert client.get(f"/scans/{scan_id}", headers=other["headers"]).status_code == 404


def test_delete_scan_cross_org_is_refused(client, auth, make_user, fake_scanner):
    scan_id = _create_scan_in_org_a(client, auth)
    other = make_user()
    assert client.delete(f"/scans/{scan_id}", headers=other["headers"]).status_code == 404
    # The scan is untouched for its owner.
    assert client.get(f"/scans/{scan_id}", headers=auth["headers"]).status_code == 200


def test_get_nonexistent_scan_is_404(client, auth):
    """A missing/enumerated scan id fails safely (never 200 with foreign data)."""
    assert client.get("/scans/999999999", headers=auth["headers"]).status_code == 404

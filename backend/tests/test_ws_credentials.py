"""STEP 3 — WebSocket credential handling: token via Sec-WebSocket-Protocol.

Credentials must NOT ride in the URL query string (reverse-proxy/gunicorn access
logs + browser history capture it). They are carried in the subprotocol header
instead; a deprecated ?token=/?key= fallback is retained for legacy clients.
These tests prove auth works WITHOUT a URL token, and that STEP 2's fail-closed
revocation still applies on the WS path.
"""


# --------------------------------------------------------------------------- #
# Unit: the credential extractor prefers the header, never needs the URL.
# --------------------------------------------------------------------------- #
class _FakeWS:
    def __init__(self, subproto_header="", query=None):
        self.headers = {"sec-websocket-protocol": subproto_header}
        self.query_params = query or {}


def test_ws_credentials_reads_subprotocol_header():
    from app.routers.ws import _ws_credentials
    t, k, sp = _ws_credentials(_FakeWS("reconx.token, ABC.jwt.value"))
    assert t == "ABC.jwt.value" and k is None and sp == "reconx.token"
    t, k, sp = _ws_credentials(_FakeWS("reconx.key, rcx_key_value"))
    assert k == "rcx_key_value" and t is None and sp == "reconx.key"


def test_ws_credentials_query_fallback_still_supported():
    from app.routers.ws import _ws_credentials
    t, k, sp = _ws_credentials(_FakeWS("", {"token": "QP.jwt"}))
    assert t == "QP.jwt" and sp is None  # no subprotocol echoed for the legacy path
    t, k, sp = _ws_credentials(_FakeWS(""))
    assert t is None and k is None and sp is None


# --------------------------------------------------------------------------- #
# Integration: /ws/scan authenticates via the subprotocol (no URL token).
# --------------------------------------------------------------------------- #
def test_ws_auth_via_subprotocol_no_url_token(client, auth):
    tok = auth["access_token"]
    # NOTE: the URL is the bare endpoint — the token is in the subprotocol header.
    with client.websocket_connect("/ws/scan", subprotocols=["reconx.token", tok]) as ws:
        ws.send_json({"tool": "__no_such_tool__", "target": "example.com"})
        msg = ws.receive_json()
    # Got PAST auth into the request handler -> not an auth failure.
    assert msg["type"] == "error" and "Unknown tool" in msg["data"]


def test_ws_no_credentials_rejected(client):
    with client.websocket_connect("/ws/scan") as ws:
        msg = ws.receive_json()
    assert msg["type"] == "error" and "authentication" in msg["data"].lower()


def test_ws_revoked_token_via_subprotocol_rejected(client, auth):
    tok = auth["access_token"]
    client.post("/auth/logout-all", headers=auth["headers"])  # bump token_version
    with client.websocket_connect("/ws/scan", subprotocols=["reconx.token", tok]) as ws:
        msg = ws.receive_json()
    assert msg["type"] == "error" and "authentication" in msg["data"].lower()


def test_ws_deprecated_query_fallback_still_authenticates(client, auth):
    tok = auth["access_token"]
    with client.websocket_connect(f"/ws/scan?token={tok}") as ws:
        ws.send_json({"tool": "__no_such_tool__", "target": "example.com"})
        msg = ws.receive_json()
    assert msg["type"] == "error" and "Unknown tool" in msg["data"]


def test_pipeline_ws_auth_via_subprotocol(client, auth):
    tok = auth["access_token"]
    with client.websocket_connect("/ws/pipeline", subprotocols=["reconx.token", tok]) as ws:
        # authenticated -> the pipeline waits for a config message; send junk to
        # get a deterministic non-auth response, then stop.
        ws.send_json({"workspace_id": 999999, "target": "example.com"})
        msg = ws.receive_json()
    # Any pipeline_* message (not an "Authentication failed." error) proves auth passed.
    assert not (msg.get("type") == "pipeline_log" and "authentication failed" in str(msg.get("data", "")).lower())

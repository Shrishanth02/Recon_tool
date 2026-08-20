"""Purple-Team P2 tests — SAFE ATT&CK emulation (unit + integration).

Everything here is fully hermetic: the ``requests`` module and ``socket`` used
inside :mod:`app.emulation.techniques` are monkeypatched so NO packet ever
leaves the box, and the router's netguard gate is stubbed. The tests also assert
the emulation is *non-destructive*: only benign GET/POST traffic carrying the
``X-RECONX-EMULATION`` marker is ever issued (no mutating verbs, no real data).
"""

import socket as real_socket

import pytest
import requests as real_requests

from app import emulation
from app.emulation import techniques as tq


# --------------------------------------------------------------------------- #
# Fakes: a recording stand-in for `requests`, and a stub `socket` module.
# --------------------------------------------------------------------------- #
class FakeResponse:
    """Minimal stand-in for a :class:`requests.Response`."""

    def __init__(self, status_code=200, reason="OK"):
        self.status_code = status_code
        self.reason = reason


class RecordingRequests:
    """Stand-in for the ``requests`` module used inside techniques.

    Records every call so a test can assert the run only issued benign GET/POST
    traffic. Can be configured to return a fixed status or to raise.
    """

    # Techniques catch ``requests.RequestException`` specifically, so expose the
    # real class here.
    RequestException = real_requests.RequestException

    def __init__(self, status_code=200, reason="OK", raise_with=None):
        self.status_code = status_code
        self.reason = reason
        self.raise_with = raise_with
        self.calls = []

    def _call(self, method, url, **kwargs):
        self.calls.append({"method": method, "url": url, "kwargs": kwargs})
        if self.raise_with is not None:
            raise self.raise_with
        return FakeResponse(self.status_code, self.reason)

    def get(self, url, **kwargs):
        return self._call("GET", url, **kwargs)

    def post(self, url, **kwargs):
        return self._call("POST", url, **kwargs)


class _FakeSocket:
    """A socket that never touches the network: connect_ex returns a canned code."""

    def __init__(self, connect_result):
        self._connect_result = connect_result
        self.data_sent = False

    def settimeout(self, _t):
        pass

    def connect_ex(self, _addr):
        return self._connect_result

    def send(self, *_a, **_k):  # pragma: no cover - guards against a data-sending regression
        self.data_sent = True

    def sendall(self, *_a, **_k):  # pragma: no cover
        self.data_sent = True

    def close(self):
        pass


class FakeSocketModule:
    """Stub of the ``socket`` module exposing just what E4 uses."""

    AF_INET = real_socket.AF_INET
    SOCK_STREAM = real_socket.SOCK_STREAM

    def __init__(self, connect_result=1):
        # 0 == "port open"; anything else == "closed/filtered".
        self.connect_result = connect_result
        self.created = []

    def socket(self, *_a, **_k):
        s = _FakeSocket(self.connect_result)
        self.created.append(s)
        return s


def _patch_transport(monkeypatch, requests_fake, socket_fake):
    """Redirect the technique module's HTTP + TCP transports to the fakes."""
    monkeypatch.setattr(tq, "requests", requests_fake)
    monkeypatch.setattr(tq, "socket", socket_fake)


# --------------------------------------------------------------------------- #
# Unit tests — the engine (app.emulation.run_emulation).
# --------------------------------------------------------------------------- #
def test_run_emulation_all_techniques_executed(monkeypatch):
    """A 200 for HTTP + closed ports -> every technique reports 'executed'."""
    reqs = RecordingRequests(status_code=200, reason="OK")
    sock = FakeSocketModule(connect_result=1)  # all ports closed
    _patch_transport(monkeypatch, reqs, sock)

    out = emulation.run_emulation("example.com")

    assert out["target"] == "example.com"
    # The whole registry ran (5 SAFE techniques) and each produced a result.
    assert len(out["results"]) == len(tq.TECHNIQUES) == 5
    statuses = {r["id"]: r["status"] for r in out["results"]}
    assert statuses == {"E1": "executed", "E2": "executed", "E3": "executed",
                        "E4": "executed", "E5": "executed"}
    assert out["executed"] == 5
    assert out["blocked"] == 0
    assert out["failed"] == 0

    # Every result carries the full technique metadata for persistence.
    for r in out["results"]:
        assert r["technique_id"] and r["name"] and r["tactic"]


def test_run_emulation_403_is_blocked(monkeypatch):
    """An HTTP 403 (WAF/target refusal) is reported as a positive 'blocked'."""
    reqs = RecordingRequests(status_code=403, reason="Forbidden")
    sock = FakeSocketModule(connect_result=1)
    _patch_transport(monkeypatch, reqs, sock)

    out = emulation.run_emulation("example.com", ["E1"])

    assert len(out["results"]) == 1
    result = out["results"][0]
    assert result["id"] == "E1"
    assert result["status"] == "blocked"
    assert "403" in result["evidence"]
    assert out["blocked"] == 1
    assert out["executed"] == 0
    assert out["failed"] == 0


def test_run_emulation_request_error_is_failed_not_crash(monkeypatch):
    """A technique whose request raises is recorded 'failed' — never a crash."""
    reqs = RecordingRequests(
        raise_with=real_requests.ConnectionError("boom")  # subclass of RequestException
    )
    sock = FakeSocketModule(connect_result=1)
    _patch_transport(monkeypatch, reqs, sock)

    out = emulation.run_emulation("example.com", ["E1"])

    assert len(out["results"]) == 1
    assert out["results"][0]["status"] == "failed"
    assert out["failed"] == 1
    assert out["executed"] == 0
    assert out["blocked"] == 0


def test_run_emulation_unexpected_exception_is_contained(monkeypatch):
    """Even a non-RequestException from the transport can't abort the run.

    Exercises the engine's defensive ``except Exception`` wrapper: a technique
    that raises something it does not itself catch is still recorded 'failed'.
    """
    reqs = RecordingRequests(raise_with=ValueError("unexpected"))
    sock = FakeSocketModule(connect_result=1)
    _patch_transport(monkeypatch, reqs, sock)

    # E1 (HTTP) hits the ValueError; E4 (socket) still runs and succeeds.
    out = emulation.run_emulation("example.com", ["E1", "E4"])

    statuses = {r["id"]: r["status"] for r in out["results"]}
    assert statuses["E1"] == "failed"
    assert statuses["E4"] == "executed"
    assert out["failed"] == 1
    assert out["executed"] == 1


def test_run_emulation_cancel_skips_remaining(monkeypatch):
    """A truthy cancel predicate marks every technique 'skipped' and stops."""
    reqs = RecordingRequests(status_code=200)
    sock = FakeSocketModule(connect_result=1)
    _patch_transport(monkeypatch, reqs, sock)

    out = emulation.run_emulation("example.com", cancel=lambda: True)

    assert all(r["status"] == "skipped" for r in out["results"])
    # Skipped results are present but not counted in the tallies.
    assert out["executed"] == out["blocked"] == out["failed"] == 0
    # And no HTTP traffic was ever issued.
    assert reqs.calls == []


def test_run_emulation_selects_only_requested_techniques(monkeypatch):
    """technique_ids restricts the run; unknown ids are silently ignored."""
    reqs = RecordingRequests(status_code=200)
    sock = FakeSocketModule(connect_result=1)
    _patch_transport(monkeypatch, reqs, sock)

    out = emulation.run_emulation("example.com", ["E2", "E9-does-not-exist"])

    assert [r["id"] for r in out["results"]] == ["E2"]


def test_emulation_is_non_destructive(monkeypatch):
    """The full run only issues benign GET/POST marker traffic — no exceptions.

    Asserts the safety contract end to end: only GET/POST verbs, every request
    aimed at the normalized target base URL, each stamped with the
    ``X-RECONX-EMULATION`` marker header, the exfil body carries only a synthetic
    no-real-data marker, and the port sweep never sends bytes.
    """
    reqs = RecordingRequests(status_code=200)
    sock = FakeSocketModule(connect_result=1)
    _patch_transport(monkeypatch, reqs, sock)

    emulation.run_emulation("example.com")

    assert reqs.calls, "expected the HTTP techniques to have issued traffic"
    for call in reqs.calls:
        # Only read-only-shaped verbs; no PUT/DELETE/PATCH exist on the fake.
        assert call["method"] in {"GET", "POST"}
        # Never wanders off the authorized target base URL.
        assert call["url"].startswith("http://example.com")
        # Every emulated request is attributable via the marker header.
        headers = call["kwargs"].get("headers", {})
        assert tq.MARKER_HEADER in headers

    # The exfil technique (E5) moves a fixed synthetic marker, never real data.
    post_bodies = [c["kwargs"].get("data", {}) for c in reqs.calls if c["method"] == "POST"]
    exfil_bodies = [b for b in post_bodies if isinstance(b, dict) and "exfil" in b]
    assert exfil_bodies and exfil_bodies[0]["exfil"] == "RECONX-EMULATION-NO-REAL-DATA"

    # The port sweep opened sockets but sent no bytes down any of them.
    assert sock.created
    assert all(s.data_sent is False for s in sock.created)


def test_e4_reports_open_ports(monkeypatch):
    """The TCP-connect sweep surfaces the open port set (connect_ex == 0)."""
    reqs = RecordingRequests(status_code=200)
    sock = FakeSocketModule(connect_result=0)  # every probed port "open"
    _patch_transport(monkeypatch, reqs, sock)

    out = emulation.run_emulation("example.com", ["E4"])

    result = out["results"][0]
    assert result["status"] == "executed"
    assert "open" in result["evidence"]


# --------------------------------------------------------------------------- #
# Integration tests — POST /workspaces/{id}/emulate and the read routes.
# --------------------------------------------------------------------------- #
def _set_scope(client, auth, scope_list):
    resp = client.put(
        f"/workspaces/{auth['ws_id']}/scope",
        headers=auth["headers"],
        json={"scope": scope_list},
    )
    assert resp.status_code == 200, resp.text


@pytest.fixture()
def safe_transport(monkeypatch):
    """Neutralize netguard + wire the technique transports to the fakes.

    Returns the RecordingRequests instance so a test can inspect the traffic the
    route caused.
    """
    from app import netguard

    monkeypatch.setattr(netguard, "validate_target", lambda target: (True, "ok"))
    reqs = RecordingRequests(status_code=200, reason="OK")
    sock = FakeSocketModule(connect_result=1)
    _patch_transport(monkeypatch, reqs, sock)
    return reqs


def test_emulate_in_scope_persists_run_and_results(client, auth, safe_transport):
    """A POST /emulate against an in-scope target persists a run + its results."""
    _set_scope(client, auth, ["example.com"])

    resp = client.post(
        f"/workspaces/{auth['ws_id']}/emulate",
        headers=auth["headers"],
        json={"target": "example.com"},
    )
    assert resp.status_code == 200, resp.text
    run = resp.json()
    assert run["target"] == "example.com"
    assert run["status"] == "done"
    assert run["executed"] == 5
    assert run["blocked"] == 0
    assert run["failed"] == 0
    assert len(run["technique_results"]) == 5
    # Results carry ATT&CK metadata and are ordered E1..E5.
    assert [r["technique_id"] for r in run["technique_results"]] == [
        "T1595.002", "T1190", "T1071.001", "T1046", "T1048"
    ]
    for r in run["technique_results"]:
        assert r["status"] in {"executed", "blocked", "failed", "skipped"}

    # And the route only caused benign GET/POST marker traffic.
    assert safe_transport.calls
    for call in safe_transport.calls:
        assert call["method"] in {"GET", "POST"}
        assert call["url"].startswith("http://example.com")


def test_emulate_out_of_scope_is_refused(client, auth, safe_transport):
    """An out-of-scope target is refused 403 and nothing is persisted."""
    _set_scope(client, auth, ["example.com"])

    resp = client.post(
        f"/workspaces/{auth['ws_id']}/emulate",
        headers=auth["headers"],
        json={"target": "attacker.net"},
    )
    assert resp.status_code == 403, resp.text

    # No run was created, and no emulation traffic left the box.
    listing = client.get(
        f"/workspaces/{auth['ws_id']}/emulations", headers=auth["headers"]
    )
    assert listing.status_code == 200
    assert listing.json() == []
    assert safe_transport.calls == []


def test_emulate_lists_and_fetches_run(client, auth, safe_transport):
    """The persisted run appears in the workspace listing and fetches by id."""
    _set_scope(client, auth, ["example.com"])

    created = client.post(
        f"/workspaces/{auth['ws_id']}/emulate",
        headers=auth["headers"],
        json={"target": "example.com"},
    )
    assert created.status_code == 200, created.text
    run_id = created.json()["id"]

    listing = client.get(
        f"/workspaces/{auth['ws_id']}/emulations", headers=auth["headers"]
    )
    assert listing.status_code == 200
    ids = [r["id"] for r in listing.json()]
    assert run_id in ids

    fetched = client.get(f"/emulations/{run_id}", headers=auth["headers"])
    assert fetched.status_code == 200
    body = fetched.json()
    assert body["id"] == run_id
    assert len(body["technique_results"]) == 5


def test_emulate_requires_authentication(client, auth, safe_transport):
    """The launch route rejects unauthenticated callers."""
    _set_scope(client, auth, ["example.com"])
    resp = client.post(
        f"/workspaces/{auth['ws_id']}/emulate",
        json={"target": "example.com"},
    )
    assert resp.status_code == 401, resp.text


def test_get_emulation_hidden_from_non_member(client, auth, make_user, safe_transport):
    """A non-member of the run's workspace gets 404 (existence hidden)."""
    _set_scope(client, auth, ["example.com"])
    created = client.post(
        f"/workspaces/{auth['ws_id']}/emulate",
        headers=auth["headers"],
        json={"target": "example.com"},
    )
    assert created.status_code == 200, created.text
    run_id = created.json()["id"]

    outsider = make_user()
    resp = client.get(f"/emulations/{run_id}", headers=outsider["headers"])
    assert resp.status_code == 404, resp.text

    # The outsider also can't reach the run through the other workspace's list.
    listing = client.get(
        f"/workspaces/{auth['ws_id']}/emulations", headers=outsider["headers"]
    )
    assert listing.status_code == 404, listing.text

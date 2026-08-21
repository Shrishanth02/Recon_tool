"""Purple-Team P3 tests — detection validation / SIEM connectors (unit + integration).

Fully hermetic: the :class:`~app.connectors.mock.MockConnector` is deterministic
by construction, the :class:`~app.connectors.http.HttpConnector`'s ``requests``
transport is monkeypatched (no packet ever leaves the box), and the integration
tests drive the real emulate route with the same fake transports P2 uses. Nothing
here touches a real network or SIEM.

Coverage:

* MockConnector: deterministic detect/miss driven by ``coverage`` and
  ``detect_technique_ids`` (verified against the connector's own SHA-256 bucket).
* HttpConnector: detected when the SIEM hit count > 0, not detected on 0 hits,
  and — the layer's hard rule — *never raises* on a network error (degrades to
  ``detected=False`` with the error in ``evidence``).
* detection.validate_emulation: coverage computed over a run with mixed technique
  statuses (only ``executed``/``blocked`` count; ``skipped``/``failed`` excluded).
* Routes: create a connector (admin), run a real emulation, validate it (persists
  DetectionResults + returns the summary), list the detections, secret masking on
  DetectionConnectorOut, non-member -> 404, viewer cannot create -> 403.
"""

import hashlib

import pytest
import requests as real_requests

from app import detection
from app.connectors import DEFAULT_MARKER, get_connector
from app.connectors.http import HttpConnector
from app.connectors.mock import MockConnector

# Reuse the P2 emulation fakes verbatim so the integration path is hermetic.
from tests.test_emulation import (
    _set_scope,
    safe_transport,  # noqa: F401  (pytest fixture, imported for use)
)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _bucket(technique_id: str) -> int:
    """Recompute MockConnector's stable 0..99 bucket independently of the class."""
    digest = hashlib.sha256((technique_id or "").encode("utf-8")).hexdigest()
    return int(digest[:8], 16) % 100


class _StubTR:
    """A stand-in TechniqueResult: validate_emulation only reads these attrs."""

    def __init__(self, technique_id, status, technique_name="", tactic=""):
        self.technique_id = technique_id
        self.status = status
        self.technique_name = technique_name
        self.tactic = tactic


class _StubRun:
    """A stand-in EmulationRun (persistence-free; getattr-driven)."""

    def __init__(self, technique_results, target="example.com", started_at="2026-08-13T00:00:00+00:00"):
        self.technique_results = technique_results
        self.target = target
        self.started_at = started_at


class _FakeHttpResponse:
    """Minimal requests.Response stand-in with a JSON body and status code."""

    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code

    def json(self):
        return self._payload


# =========================================================================== #
# Unit — MockConnector determinism
# =========================================================================== #
def test_mock_connector_detects_explicit_allowlist():
    """A technique in ``detect_technique_ids`` is always detected (count 1)."""
    conn = MockConnector({"detect_technique_ids": ["T1046", "T1071.001"]})
    out = conn.query_detections("T1046", DEFAULT_MARKER, "2026-01-01T00:00:00Z", "t")
    assert out == {
        "detected": True,
        "count": 1,
        "evidence": out["evidence"],
        "source": "mock",
    }
    assert out["detected"] is True and out["count"] == 1
    # A different id, not in the allow-list and with no coverage, is missed.
    miss = conn.query_detections("T1190", DEFAULT_MARKER, "2026-01-01T00:00:00Z", "t")
    assert miss["detected"] is False and miss["count"] == 0


def test_mock_connector_no_config_detects_nothing():
    """With no coverage and an empty allow-list the connector detects nothing."""
    conn = MockConnector({})
    for tid in ("T1046", "T1190", "T1071.001", "T1595.002", "T1048"):
        assert conn.query_detections(tid, DEFAULT_MARKER, "s", "t")["detected"] is False


def test_mock_connector_coverage_zero_and_one():
    """coverage=0.0 detects nothing; coverage=1.0 detects every technique."""
    none = MockConnector({"coverage": 0.0})
    full = MockConnector({"coverage": 1.0})
    for tid in ("T1046", "T1190", "T1071.001", "T1595.002", "T1048"):
        assert none.query_detections(tid, DEFAULT_MARKER, "s", "t")["detected"] is False
        assert full.query_detections(tid, DEFAULT_MARKER, "s", "t")["detected"] is True


def test_mock_connector_coverage_gate_matches_sha_bucket():
    """The coverage gate is exactly ``bucket(tid) < coverage*100`` and stable."""
    # Pick a technique and set coverage straddling its bucket both ways.
    tid = "T1046"
    b = _bucket(tid)
    assert 0 <= b <= 99
    # coverage just above the bucket -> detected; just at/below -> missed.
    hi = MockConnector({"coverage": (b + 1) / 100})
    lo = MockConnector({"coverage": b / 100})
    assert hi.query_detections(tid, DEFAULT_MARKER, "s", "t")["detected"] is True
    assert lo.query_detections(tid, DEFAULT_MARKER, "s", "t")["detected"] is False


def test_mock_connector_deterministic_across_instances():
    """Same config + id -> identical verdict every time (no per-process salt)."""
    cfg = {"coverage": 0.5}
    a = MockConnector(cfg)
    b = MockConnector(dict(cfg))
    for tid in ("T1046", "T1190", "T1071.001", "T1595.002", "T1048", "T1234"):
        va = a.query_detections(tid, DEFAULT_MARKER, "s", "t")["detected"]
        vb = b.query_detections(tid, DEFAULT_MARKER, "s", "t")["detected"]
        assert va == vb
        # And matches the independent bucket computation.
        assert va == (_bucket(tid) < 50)


# =========================================================================== #
# Unit — HttpConnector (monkeypatched requests)
# =========================================================================== #
def _http_conn():
    return HttpConnector(
        {
            "search_url": "https://siem.example/api/search",
            "method": "POST",
            "count_path": "total",
        }
    )


def test_http_connector_detected_when_hits(monkeypatch):
    """A JSON body whose count path is > 0 yields ``detected=True``."""
    captured = {}

    def fake_post(url, **kwargs):
        captured["url"] = url
        captured["kwargs"] = kwargs
        return _FakeHttpResponse({"total": 3}, status_code=200)

    monkeypatch.setattr(real_requests, "post", fake_post)
    out = _http_conn().query_detections("T1046", DEFAULT_MARKER, "2026-01-01T00:00:00Z", "example.com")

    assert out["detected"] is True
    assert out["count"] == 3
    assert out["source"] == "http"
    assert captured["url"] == "https://siem.example/api/search"


def test_http_connector_zero_hits_not_detected(monkeypatch):
    """A zero hit count is a clean miss (``detected=False``), not an error."""
    monkeypatch.setattr(
        real_requests, "post", lambda url, **kw: _FakeHttpResponse({"total": 0})
    )
    out = _http_conn().query_detections("T1046", DEFAULT_MARKER, "s", "t")
    assert out["detected"] is False
    assert out["count"] == 0
    assert "0 hits" in out["evidence"]


def test_http_connector_never_raises_on_network_error(monkeypatch):
    """The hard rule: a raising transport degrades to ``detected=False``."""

    def boom(url, **kwargs):
        raise real_requests.ConnectionError("connection refused")

    monkeypatch.setattr(real_requests, "post", boom)
    # Must NOT propagate — the connector swallows it into a miss with evidence.
    out = _http_conn().query_detections("T1046", DEFAULT_MARKER, "s", "t")
    assert out["detected"] is False
    assert out["count"] == 0
    assert "request failed" in out["evidence"]
    assert "connection refused" in out["evidence"]


def test_http_connector_http_error_status_not_detected(monkeypatch):
    """A 4xx/5xx search response is a miss with the status in the evidence."""
    monkeypatch.setattr(
        real_requests, "post", lambda url, **kw: _FakeHttpResponse({}, status_code=503)
    )
    out = _http_conn().query_detections("T1046", DEFAULT_MARKER, "s", "t")
    assert out["detected"] is False
    assert "503" in out["evidence"]


def test_http_connector_no_search_url_is_a_miss():
    """A connector with no ``search_url`` never touches the network — miss."""
    out = HttpConnector({}).query_detections("T1046", DEFAULT_MARKER, "s", "t")
    assert out["detected"] is False
    assert "no search_url" in out["evidence"]


def test_get_connector_unknown_type_raises():
    """The factory raises ValueError on an unknown ctype (a config error)."""
    with pytest.raises(ValueError):
        get_connector("does-not-exist", {})


# =========================================================================== #
# Unit — detection.validate_emulation coverage over mixed statuses
# =========================================================================== #
def test_validate_emulation_counts_only_executed_and_blocked():
    """Only executed/blocked techniques score; skipped/failed are excluded."""
    run = _StubRun(
        [
            _StubTR("T1046", "executed", "Network Service Discovery", "discovery"),
            _StubTR("T1190", "blocked", "Exploit Public-Facing App", "initial-access"),
            _StubTR("T1071.001", "skipped"),   # excluded from scoring
            _StubTR("T1595.002", "failed"),    # excluded from scoring
            _StubTR("T1048", "executed"),
        ]
    )
    # Detect exactly one of the three counted techniques (T1046).
    connector = MockConnector({"detect_technique_ids": ["T1046"]})
    results, summary = detection.validate_emulation(None, run, connector)

    # Three counted techniques (2 executed + 1 blocked), skipped/failed dropped.
    assert summary["total"] == 3
    assert {r["technique_id"] for r in results} == {"T1046", "T1190", "T1048"}
    assert summary["detected"] == 1
    assert summary["missed"] == 2
    assert summary["coverage_pct"] == round(100 * 1 / 3)  # 33
    assert summary["source"] == "mock"
    assert summary["window_seconds"] == 600
    # The detected row carries the verdict + evidence; excluded ids are absent.
    detected_ids = {r["technique_id"] for r in results if r["detected"]}
    assert detected_ids == {"T1046"}


def test_validate_emulation_full_and_zero_coverage():
    """coverage 100% -> coverage_pct 100; an all-skipped run -> 0 (no div-by-zero)."""
    counted = _StubRun(
        [_StubTR("T1046", "executed"), _StubTR("T1190", "blocked")]
    )
    _, full = detection.validate_emulation(None, counted, MockConnector({"coverage": 1.0}))
    assert full["total"] == 2 and full["detected"] == 2 and full["coverage_pct"] == 100

    empty = _StubRun([_StubTR("T1046", "skipped"), _StubTR("T1190", "failed")])
    results, summ = detection.validate_emulation(None, empty, MockConnector({"coverage": 1.0}))
    assert results == []
    assert summ["total"] == 0 and summ["detected"] == 0 and summ["coverage_pct"] == 0


# =========================================================================== #
# Integration — connector CRUD + validate + list routes
# =========================================================================== #
def _create_connector(client, auth, headers=None, **overrides):
    body = {
        "name": overrides.get("name", "Primary SIEM"),
        "ctype": overrides.get("ctype", "mock"),
        "config": overrides.get("config", {"coverage": 1.0}),
        "enabled": overrides.get("enabled", True),
    }
    return client.post(
        f"/orgs/{auth['org_id']}/detection-connectors",
        headers=headers or auth["headers"],
        json=body,
    )


def _emulate(client, auth):
    _set_scope(client, auth, ["example.com"])
    resp = client.post(
        f"/workspaces/{auth['ws_id']}/emulate",
        headers=auth["headers"],
        json={"target": "example.com"},
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


def test_create_connector_admin_ok_and_masks_secrets(client, auth):
    """An admin/owner creates a connector; the response never echoes secrets."""
    resp = _create_connector(
        client,
        auth,
        ctype="http",
        config={
            "search_url": "https://siem.example/api/search",
            "token": "super-secret-token",
            "api_key": "AKIA-not-shown",
            "headers": {"Authorization": "Bearer leak-me"},
        },
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    # Non-secret key is visible; secret-bearing keys are masked to "***".
    assert body["config"]["search_url"] == "https://siem.example/api/search"
    assert body["config"]["token"] == "***"
    assert body["config"]["api_key"] == "***"
    assert body["config"]["headers"] == "***"
    # config_keys advertises what's set without leaking values.
    assert set(body["config_keys"]) == {"search_url", "token", "api_key", "headers"}
    # The raw secrets appear nowhere in the serialized response.
    assert "super-secret-token" not in resp.text
    assert "AKIA-not-shown" not in resp.text
    assert "leak-me" not in resp.text


def test_viewer_cannot_create_connector(client, auth, make_user):
    """A viewer member lacks admin+ and is refused connector creation (403)."""
    viewer = make_user()
    client.post(
        f"/orgs/{auth['org_id']}/members",
        headers=auth["headers"],
        json={"email": viewer["email"], "role": "viewer"},
    )
    resp = _create_connector(client, auth, headers=viewer["headers"])
    assert resp.status_code == 403, resp.text


def test_validate_saves_results_and_returns_summary(client, auth, safe_transport):
    """POST /validate persists a DetectionResult per technique and returns the summary."""
    run = _emulate(client, auth)
    run_id = run["id"]
    # A full-coverage mock detects every emulated technique.
    conn = _create_connector(client, auth, config={"coverage": 1.0}).json()

    resp = client.post(
        f"/emulations/{run_id}/validate",
        headers=auth["headers"],
        params={"connector_id": conn["id"]},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    summary = body["summary"]
    # All 5 emulated techniques were executed and (coverage 1.0) detected.
    assert summary["total"] == 5
    assert summary["detected"] == 5
    assert summary["missed"] == 0
    assert summary["coverage_pct"] == 100
    assert summary["source"] == "mock"
    assert len(body["results"]) == 5
    assert all(r["detected"] is True for r in body["results"])
    assert all(r["emulation_run_id"] == run_id for r in body["results"])

    # And the persisted rows are listable via the read route.
    listing = client.get(
        f"/emulations/{run_id}/detections", headers=auth["headers"]
    )
    assert listing.status_code == 200
    rows = listing.json()
    assert len(rows) == 5
    assert {r["technique_id"] for r in rows} == {
        "T1595.002", "T1190", "T1071.001", "T1046", "T1048"
    }
    assert all(r["source"] == "mock" for r in rows)


def test_validate_partial_coverage_scores_correctly(client, auth, safe_transport):
    """A mock that only detects a subset yields a partial, correct coverage_pct."""
    run = _emulate(client, auth)
    run_id = run["id"]
    # Detect exactly two of the five emulated techniques by explicit allow-list.
    conn = _create_connector(
        client, auth, config={"detect_technique_ids": ["T1046", "T1190"]}
    ).json()

    resp = client.post(
        f"/emulations/{run_id}/validate",
        headers=auth["headers"],
        params={"connector_id": conn["id"]},
    )
    assert resp.status_code == 200, resp.text
    summary = resp.json()["summary"]
    assert summary["total"] == 5
    assert summary["detected"] == 2
    assert summary["missed"] == 3
    assert summary["coverage_pct"] == 40


def test_validate_non_member_gets_404(client, auth, make_user, safe_transport):
    """A non-member of the run's org cannot validate it -> 404 (existence hidden)."""
    run = _emulate(client, auth)
    run_id = run["id"]
    conn = _create_connector(client, auth).json()

    outsider = make_user()
    resp = client.post(
        f"/emulations/{run_id}/validate",
        headers=outsider["headers"],
        params={"connector_id": conn["id"]},
    )
    assert resp.status_code == 404, resp.text
    # The detections read route is equally hidden.
    listing = client.get(
        f"/emulations/{run_id}/detections", headers=outsider["headers"]
    )
    assert listing.status_code == 404, listing.text


def test_list_connectors_masks_secrets(client, auth):
    """GET /detection-connectors returns masked configs for members."""
    _create_connector(
        client,
        auth,
        ctype="splunk",
        config={"base_url": "https://splunk.example", "token": "hunter2"},
    )
    resp = client.get(
        f"/orgs/{auth['org_id']}/detection-connectors", headers=auth["headers"]
    )
    assert resp.status_code == 200, resp.text
    rows = resp.json()
    assert len(rows) == 1
    assert rows[0]["config"]["token"] == "***"
    assert rows[0]["config"]["base_url"] == "https://splunk.example"
    assert "hunter2" not in resp.text

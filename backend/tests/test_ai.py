"""Tests for the AI-triage endpoint (:mod:`app.ai` + intel router).

The real ``anthropic`` SDK is never required: we inject a stub module into
``sys.modules`` for the presence check and monkeypatch ``ai._client`` to a fake
client whose ``messages.parse`` returns a typed ``TriageOut``. We also assert the
graceful degrade path when no API key is configured.
"""

import sys
import types

import pytest

from app import ai


def _install_fake_anthropic(monkeypatch):
    """Satisfy the `import anthropic` presence check without the real SDK."""
    monkeypatch.setitem(sys.modules, "anthropic", types.ModuleType("anthropic"))


class _FakeResponse:
    """Mimics a messages.parse() response with typed structured output."""

    def __init__(self, parsed, stop_reason="end_turn"):
        self.parsed_output = parsed
        self.stop_reason = stop_reason


class _FakeMessages:
    def __init__(self, parsed):
        self._parsed = parsed
        self.calls = []

    def parse(self, **kwargs):
        self.calls.append(kwargs)
        return _FakeResponse(self._parsed)


class _FakeClient:
    def __init__(self, parsed):
        self.messages = _FakeMessages(parsed)


@pytest.fixture()
def enable_ai(monkeypatch):
    """Enable AI: real key present (via settings), fake SDK + fake client."""
    monkeypatch.setattr(ai.settings, "ANTHROPIC_API_KEY", "test-key-123")
    _install_fake_anthropic(monkeypatch)

    parsed = ai.TriageOut(
        summary="Two criticals require immediate patching.",
        risk_narrative="Elevated business risk from exposed RCE.",
        items=[
            ai.TriagedFinding(
                finding_id=1,
                verdict="real",
                suggested_severity="critical",
                remediation="Patch now.",
                rationale="Confirmed exploit path.",
            )
        ],
        dedup_groups=[[1]],
    )
    monkeypatch.setattr(ai, "_client", lambda: _FakeClient(parsed))
    return parsed


def test_triage_enabled_persists_and_is_retrievable(client, auth, enable_ai):
    ws_id = auth["ws_id"]

    resp = client.post(f"/workspaces/{ws_id}/triage", headers=auth["headers"])
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["enabled"] is True
    assert body["model"] == ai.settings.AI_MODEL
    assert body["result"]["summary"] == "Two criticals require immediate patching."
    assert body["result"]["items"][0]["verdict"] == "real"

    # It was persisted: GET returns the stored triage.
    got = client.get(f"/workspaces/{ws_id}/triage", headers=auth["headers"])
    assert got.status_code == 200, got.text
    stored = got.json()
    assert stored["enabled"] is True
    assert stored["summary"] == "Two criticals require immediate patching."
    assert stored["risk_narrative"] == "Elevated business risk from exposed RCE."
    assert stored["result"]["items"][0]["finding_id"] == 1


def test_triage_disabled_without_api_key_does_not_crash(client, auth, monkeypatch):
    # Empty key -> settings.ai_enabled is False -> graceful, no persistence.
    monkeypatch.setattr(ai.settings, "ANTHROPIC_API_KEY", "")

    resp = client.post(f"/workspaces/{auth['ws_id']}/triage", headers=auth["headers"])
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["enabled"] is False
    assert "reason" in body

    # Nothing was persisted.
    got = client.get(f"/workspaces/{auth['ws_id']}/triage", headers=auth["headers"])
    assert got.status_code == 200
    assert got.json()["enabled"] is False


def test_triage_findings_returns_disabled_when_key_empty(monkeypatch):
    """The pure entrypoint degrades without raising when AI is off."""
    monkeypatch.setattr(ai.settings, "ANTHROPIC_API_KEY", "")
    out = ai.triage_findings([{"id": 1, "severity": "high", "name": "X"}])
    assert out == {"enabled": False, "reason": "ANTHROPIC_API_KEY not configured"}


def test_triage_findings_handles_model_refusal(monkeypatch):
    """A stop_reason == 'refusal' is surfaced gracefully, not persisted."""
    monkeypatch.setattr(ai.settings, "ANTHROPIC_API_KEY", "test-key-123")
    _install_fake_anthropic(monkeypatch)

    class _RefusingMessages:
        def parse(self, **kwargs):
            return _FakeResponse(parsed=None, stop_reason="refusal")

    class _RefusingClient:
        messages = _RefusingMessages()

    monkeypatch.setattr(ai, "_client", lambda: _RefusingClient())
    out = ai.triage_findings([{"id": 1, "severity": "high", "name": "X"}])
    assert out["enabled"] is True
    assert out.get("refused") is True
    assert "result" not in out


def test_triage_requires_analyst_role(client, auth, make_user, enable_ai):
    """A viewer member cannot run triage (analyst+ gate)."""
    viewer = make_user()
    added = client.post(
        f"/orgs/{auth['org_id']}/members",
        headers=auth["headers"],
        json={"email": viewer["email"], "role": "viewer"},
    )
    assert added.status_code == 201, added.text

    denied = client.post(
        f"/workspaces/{auth['ws_id']}/triage", headers=viewer["headers"]
    )
    assert denied.status_code == 403, denied.text

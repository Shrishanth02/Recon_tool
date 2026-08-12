"""Tests for :mod:`app.notify` — the failure-safe alert dispatcher.

Network and SMTP are never touched: ``notify.requests.post`` and
``notify._send_email`` are monkeypatched. We verify subscription matching,
webhook/slack POST delivery, email delivery, and that a failing transport is
caught and reported as ``ok=False`` rather than raised.
"""

from app import notify


class _FakeResponse:
    def __init__(self, status_code):
        self.status_code = status_code


# --------------------------------------------------------------------------- #
# should_notify
# --------------------------------------------------------------------------- #
def test_should_notify_honors_explicit_event():
    ch = {"events": ["new_finding", "scan_done"]}
    assert notify.should_notify(ch, "new_finding") is True
    assert notify.should_notify(ch, "scan_done") is True
    assert notify.should_notify(ch, "other") is False


def test_should_notify_wildcard_matches_anything():
    ch = {"events": ["*"]}
    assert notify.should_notify(ch, "new_finding") is True
    assert notify.should_notify(ch, "literally_anything") is True


def test_should_notify_no_events_subscribes_to_nothing():
    assert notify.should_notify({}, "new_finding") is False
    assert notify.should_notify({"events": []}, "new_finding") is False


# --------------------------------------------------------------------------- #
# webhook / slack dispatch
# --------------------------------------------------------------------------- #
def test_dispatch_webhook_posts_to_url_and_returns_ok(monkeypatch):
    calls = {}

    def fake_post(url, json=None, timeout=None):
        calls["url"] = url
        calls["json"] = json
        calls["timeout"] = timeout
        return _FakeResponse(200)

    monkeypatch.setattr(notify.requests, "post", fake_post)

    channel = {
        "ctype": "webhook",
        "config": {"url": "https://hooks.example/abc"},
        "events": ["new_finding"],
    }
    event = {"type": "new_finding", "message": "found something"}
    out = notify.dispatch(channel, event)

    assert out["ok"] is True
    assert calls["url"] == "https://hooks.example/abc"
    assert calls["json"] == {"event": event}
    assert calls["timeout"] == notify._HTTP_TIMEOUT


def test_dispatch_slack_includes_text_summary(monkeypatch):
    captured = {}

    def fake_post(url, json=None, timeout=None):
        captured["url"] = url
        captured["json"] = json
        return _FakeResponse(204)

    monkeypatch.setattr(notify.requests, "post", fake_post)

    channel = {
        "ctype": "slack",
        "config": {"url": "https://slack.example/hook"},
        "events": ["*"],
    }
    event = {"type": "new_finding", "message": "SQLi on /login"}
    out = notify.dispatch(channel, event)

    assert out["ok"] is True  # 204 is in the 2xx success range
    assert captured["url"] == "https://slack.example/hook"
    # Slack bodies carry a human-readable text line plus the raw event.
    assert "SQLi on /login" in captured["json"]["text"]
    assert captured["json"]["event"] == event


def test_dispatch_webhook_non_2xx_is_not_ok(monkeypatch):
    monkeypatch.setattr(notify.requests, "post", lambda *a, **k: _FakeResponse(500))
    channel = {"ctype": "webhook", "config": {"url": "https://x/y"}, "events": ["*"]}
    out = notify.dispatch(channel, {"type": "new_finding"})
    assert out["ok"] is False
    assert "500" in out["detail"]


def test_dispatch_webhook_failure_is_caught_not_raised(monkeypatch):
    def boom(*a, **k):
        raise ConnectionError("network down")

    monkeypatch.setattr(notify.requests, "post", boom)

    channel = {"ctype": "webhook", "config": {"url": "https://x/y"}, "events": ["*"]}
    # Must not raise.
    out = notify.dispatch(channel, {"type": "new_finding"})
    assert out["ok"] is False
    assert "POST failed" in out["detail"]


def test_dispatch_webhook_missing_url(monkeypatch):
    # No URL configured -> reported, not raised. requests.post never called.
    monkeypatch.setattr(
        notify.requests, "post", lambda *a, **k: pytest_fail_if_called()
    )
    out = notify.dispatch({"ctype": "webhook", "config": {}, "events": ["*"]}, {})
    assert out["ok"] is False
    assert "missing config.url" in out["detail"]


def pytest_fail_if_called():  # pragma: no cover - only hit on regression
    raise AssertionError("requests.post should not be called when url is missing")


# --------------------------------------------------------------------------- #
# email dispatch
# --------------------------------------------------------------------------- #
def test_dispatch_email_uses_send_email_helper(monkeypatch):
    monkeypatch.setattr(notify.settings, "SMTP_HOST", "smtp.example")
    sent = {}

    def fake_send_email(to_addr, subject, body):
        sent["to"] = to_addr
        sent["subject"] = subject
        sent["body"] = body
        return {"ok": True, "detail": f"emailed {to_addr}"}

    monkeypatch.setattr(notify, "_send_email", fake_send_email)

    channel = {
        "ctype": "email",
        "config": {"email": "soc@example.com"},
        "events": ["new_finding"],
    }
    event = {"type": "new_finding", "message": "alert"}
    out = notify.dispatch(channel, event)

    assert out["ok"] is True
    assert sent["to"] == "soc@example.com"
    assert "new_finding" in sent["subject"]


def test_dispatch_email_without_smtp_host_is_not_ok(monkeypatch):
    monkeypatch.setattr(notify.settings, "SMTP_HOST", "")
    # _send_email should never be reached when SMTP is unconfigured.
    monkeypatch.setattr(
        notify, "_send_email", lambda *a, **k: pytest_fail_if_called()
    )
    out = notify.dispatch(
        {"ctype": "email", "config": {"email": "a@b.com"}, "events": ["*"]},
        {"type": "new_finding"},
    )
    assert out["ok"] is False
    assert "SMTP not configured" in out["detail"]


def test_dispatch_unknown_channel_type(monkeypatch):
    out = notify.dispatch({"ctype": "carrier-pigeon", "config": {}}, {})
    assert out["ok"] is False
    assert "unknown channel type" in out["detail"]

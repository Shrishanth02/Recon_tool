"""dirbuster (ffuf content discovery) regression: auto-calibration.

Empirically found validating against OWASP Juice Shop (an Angular SPA that serves
HTTP 200 + the same index.html for EVERY path — a soft-404 / catch-all): without
ffuf auto-calibration the scanner reported 4,638 "discovered path" findings, almost
all false positives (every wordlist entry "matched" the catch-all). ffuf's ``-ac``
probes random non-existent paths first and filters responses matching that
baseline, so a SPA / custom-404 site no longer floods false positives while a
normal 404-ing site is unaffected.
"""
from app.scanners import dirbuster


def test_dirbuster_ffuf_uses_autocalibration(monkeypatch):
    monkeypatch.setattr(dirbuster, "reachable", lambda u: True)
    captured = {}

    def fake_stream_command(cmd, **k):
        captured["cmd"] = cmd
        yield {"type": "returncode", "data": 0}

    monkeypatch.setattr(dirbuster, "stream_command", fake_stream_command)
    list(dirbuster.stream("http://target.test"))

    cmd = captured.get("cmd") or []
    assert "ffuf" in cmd
    assert "-ac" in cmd, "ffuf must auto-calibrate to avoid SPA/soft-404 false positives"
    # The status-code match set is still applied (real discovery still works).
    assert "-mc" in cmd

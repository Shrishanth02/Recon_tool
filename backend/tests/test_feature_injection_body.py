"""Feature (POST/JSON injection) tests: body-request support in the injection
scanner. sqlmap/dalfox are not run — stream_command is monkeypatched to capture
the built command. Verifies --data / content-type / method wiring, that no
destructive flags are ever added, and that findings are annotated with the
request method + body kind.
"""

from app.scanners import injection


def test_sqlmap_cmd_includes_data_ctype_method(monkeypatch):
    captured = {}
    monkeypatch.setattr(injection, "stream_command",
                        lambda cmd, **k: (captured.__setitem__("cmd", cmd), iter([]))[1])
    list(injection._run_sqlmap(["sqlmap"], "https://x/a", None,
                               data="id=1", ctype="application/json", method="PUT"))
    cmd = captured["cmd"]
    assert "--data" in cmd and "id=1" in cmd
    assert "-H" in cmd and any("application/json" in c for c in cmd)
    assert "--method" in cmd and "PUT" in cmd
    # Safety: read-only flags preserved, never destructive.
    assert "--risk=1" in cmd
    for bad in ("--dump", "--os-shell", "--file-write", "--file-read"):
        assert bad not in cmd


def test_sqlmap_cmd_no_data_stays_get(monkeypatch):
    captured = {}
    monkeypatch.setattr(injection, "stream_command",
                        lambda cmd, **k: (captured.__setitem__("cmd", cmd), iter([]))[1])
    list(injection._run_sqlmap(["sqlmap"], "https://x/a?id=1", None))
    assert "--data" not in captured["cmd"]


def test_sqlmap_cmd_does_not_use_smart_heuristic_skip(monkeypatch):
    """--smart makes sqlmap run only its quick basic heuristic and SKIP any
    parameter it doesn't immediately flag — which silently drops real error-free
    SQLi (boolean/UNION/time-based) whose payloads emit no DB error (e.g. a
    string-interpolated LIKE clause). Empirically verified against the VulnShop
    testbed: with --smart sqlmap reported the injectable ``q`` param as "not
    injectable" and skipped it; without --smart it confirmed a UNION-based SQLi.
    The scanner must test every supplied parameter for real, so --smart must NOT
    be present. (sqlmap still runs its own false-positive confirmation, so
    dropping --smart does not cost precision.)
    """
    captured = {}
    monkeypatch.setattr(injection, "stream_command",
                        lambda cmd, **k: (captured.__setitem__("cmd", cmd), iter([]))[1])
    list(injection._run_sqlmap(["sqlmap"], "https://x/a?id=1", None))
    cmd = captured["cmd"]
    assert "--smart" not in cmd, "sqlmap --smart skips real, error-free SQLi params"
    # The thorough, read-only detection flags remain.
    assert "--batch" in cmd and "--level=2" in cmd and "--risk=1" in cmd


def _sqlmap_logs(monkeypatch, returncode):
    """Run _run_sqlmap with a stubbed sqlmap that emits ONLY the given exit code
    (no injection output) and return its log lines."""
    from app.scanners import injection

    def fake_stream_command(cmd, **k):
        yield {"type": "returncode", "data": returncode}

    monkeypatch.setattr(injection, "stream_command", fake_stream_command)
    return [ev["data"] for ev in injection._run_sqlmap(["sqlmap"], "http://t/a?id=1", None)
            if ev.get("type") == "log"]


def test_sqlmap_nonzero_exit_is_reported_not_tested_not_clean(monkeypatch):
    """A crashed / killed / never-ran sqlmap (non-zero exit, no output) must NOT
    be reported as 'no SQL injection confirmed' — that false-clean would tell an
    operator the URL is SQLi-free when the capability never actually ran."""
    joined = " ".join(str(x) for x in _sqlmap_logs(monkeypatch, 1)).lower()
    assert "did not complete" in joined and "not tested" in joined
    assert "no sql injection confirmed" not in joined


def test_sqlmap_clean_exit_still_reports_no_injection(monkeypatch):
    """Regression guard: a genuine clean run (exit 0, nothing found) still gets
    the honest 'no SQL injection confirmed' message."""
    joined = " ".join(str(x) for x in _sqlmap_logs(monkeypatch, 0)).lower()
    assert "no sql injection confirmed" in joined
    assert "did not complete" not in joined


def test_dalfox_nonzero_exit_is_reported_not_tested(monkeypatch):
    from app.scanners import injection

    def fake_stream_command(cmd, **k):
        yield {"type": "returncode", "data": 1}

    monkeypatch.setattr(injection, "stream_command", fake_stream_command)
    logs = [ev["data"] for ev in injection._run_dalfox(["dalfox"], "http://t/a?id=1", None)
            if ev.get("type") == "log"]
    joined = " ".join(str(x) for x in logs).lower()
    assert "did not complete" in joined and "not tested" in joined
    assert "no xss confirmed" not in joined


def test_dalfox_cmd_includes_data(monkeypatch):
    captured = {}
    monkeypatch.setattr(injection, "stream_command",
                        lambda cmd, **k: (captured.__setitem__("cmd", cmd), iter([]))[1])
    list(injection._run_dalfox(["dalfox"], "https://x/a", None, data="q=1"))
    assert "--data" in captured["cmd"] and "q=1" in captured["cmd"]


def test_stream_annotates_body_method_and_ctype(monkeypatch):
    monkeypatch.setattr(injection, "_sqlmap_cmd", lambda: ["sqlmap"])
    monkeypatch.setattr(injection, "_dalfox_cmd", lambda: None)

    def fake_sqlmap(sqlmap, url, cancel, data=None, ctype=None, method=None):
        # Confirm the body options reached the runner.
        assert data == "id=1" and ctype == "application/json" and method == "POST"
        yield {"type": "_sqli", "data": [{
            "param": "id", "place": "POST", "types": ["boolean-based blind"],
            "payloads": ["id=1 AND 1=1"], "dbms": "MySQL", "url": url,
        }]}

    monkeypatch.setattr(injection, "_run_sqlmap", fake_sqlmap)
    events = list(injection.stream("https://x/a", method="POST", data="id=1", content_type="json"))
    res = next(e["data"] for e in events if e["type"] == "result")
    f = res["findings"][0]
    assert f["evidence"]["http_method"] == "POST"
    assert f["evidence"]["content_type"] == "application/json"
    assert f["evidence"]["body_tested"] is True
    assert f["evidence"]["parameter"] == "id"      # P1 evidence preserved

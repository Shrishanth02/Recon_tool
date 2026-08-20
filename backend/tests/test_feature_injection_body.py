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

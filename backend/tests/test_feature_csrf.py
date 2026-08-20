"""Feature (CSRF) tests. HTTP monkeypatched — no network, nothing destructive."""

from app import crud
from app.scanners import csrf

TARGET = "https://app.example.com/transfer"


def _run(monkeypatch, http, inputs=(), method="POST"):
    monkeypatch.setattr(csrf, "_http", http)
    events = list(csrf.stream(TARGET, method=method, inputs=list(inputs), content_type="form"))
    return next(e["data"] for e in events if e["type"] == "result")


def test_missing_token_and_samesite_is_signal(monkeypatch):
    def http(method, url, headers, data=None, ctype=None):
        if method == "GET":
            return (200, "<form></form>", "session=abc; Path=/")
        return (403, "forbidden", "")

    res = _run(monkeypatch, http)
    assert any("Possible CSRF" in f["name"] and f["detection_tier"] == "signal"
               for f in res["findings"])


def test_token_field_present_no_missing_signal(monkeypatch):
    def http(method, url, headers, data=None, ctype=None):
        return (200, "<form></form>", "session=abc") if method == "GET" else (403, "forbidden", "")

    res = _run(monkeypatch, http, inputs=["csrf_token", "amount"])
    assert not any("Possible CSRF: no token" in f["name"] for f in res["findings"])


def test_samesite_cookie_suppresses_missing_signal(monkeypatch):
    def http(method, url, headers, data=None, ctype=None):
        return (200, "<form></form>", "session=abc; SameSite=Lax") if method == "GET" else (403, "x", "")

    res = _run(monkeypatch, http)
    assert not any("no token or SameSite" in f["name"] for f in res["findings"])


def test_static_token_is_signal(monkeypatch):
    html = '<form><input name="csrf_token" value="STATIC123"></form>'

    def http(method, url, headers, data=None, ctype=None):
        return (200, html, "session=abc; SameSite=Lax") if method == "GET" else (403, "x", "")

    res = _run(monkeypatch, http)
    assert any("static" in f["name"].lower() for f in res["findings"])
    assert not any("no token or SameSite" in f["name"] for f in res["findings"])


def test_rotating_token_no_static_signal(monkeypatch):
    calls = {"n": 0}

    def http(method, url, headers, data=None, ctype=None):
        if method == "GET":
            calls["n"] += 1
            return (200, f'<input name="csrf_token" value="TOK{calls["n"]}">', "session=abc; SameSite=Lax")
        return (403, "x", "")

    res = _run(monkeypatch, http)
    assert not any("static" in f["name"].lower() for f in res["findings"])


def test_csrf_not_enforced_is_validated(monkeypatch):
    def http(method, url, headers, data=None, ctype=None):
        if method == "GET":
            return (200, "<form></form>", "session=abc")
        return (400, "invalid data", "")     # invalid-token probe reached the handler

    res = _run(monkeypatch, http)
    v = [f for f in res["findings"] if f["detection_tier"] == "validated"]
    assert v and v[0]["cwe"] == ["CWE-352"]
    assert v[0]["evidence"]["validation_result"] == "not_enforced"
    assert v[0]["evidence"]["probe_status"] == 400


def test_csrf_enforced_403_is_negative(monkeypatch):
    def http(method, url, headers, data=None, ctype=None):
        return (200, "<form></form>", "session=abc; SameSite=Lax") if method == "GET" else (403, "forbidden", "")

    res = _run(monkeypatch, http)
    assert not any(f["detection_tier"] == "validated" for f in res["findings"])


def test_csrf_error_text_is_negative(monkeypatch):
    def http(method, url, headers, data=None, ctype=None):
        if method == "GET":
            return (200, "<form></form>", "session=abc; SameSite=Lax")
        return (200, "CSRF token missing or incorrect", "")   # 200 but CSRF error -> enforced

    res = _run(monkeypatch, http)
    assert not any(f["detection_tier"] == "validated" for f in res["findings"])


def test_get_method_no_csrf_test(monkeypatch):
    monkeypatch.setattr(csrf, "_http", lambda *a, **k: (200, "", ""))
    events = list(csrf.stream(TARGET, method="GET"))
    res = next(e["data"] for e in events if e["type"] == "result")
    assert res["findings"] == []


def test_malformed_target_errors():
    events = list(csrf.stream("-oX", method="POST"))
    assert any(e["type"] == "error" for e in events)


def test_no_cookie_values_in_evidence(monkeypatch):
    def http(method, url, headers, data=None, ctype=None):
        if method == "GET":
            return (200, "<form></form>", "session=SUPERSECRETVALUE; Path=/")
        return (400, "bad", "")

    res = _run(monkeypatch, http)
    assert "SUPERSECRETVALUE" not in str(res["findings"])   # cookie value never stored


def test_derive_csrf_per_finding_tier():
    result = {"findings": [
        {"severity": "high", "name": "CSRF not enforced", "location": "u", "cwe": ["CWE-352"],
         "detection_tier": "validated", "confidence": 80, "evidence": {"endpoint": "u"}},
        {"severity": "medium", "name": "Possible CSRF", "location": "u", "cwe": ["CWE-352"],
         "detection_tier": "signal", "confidence": 40, "evidence": {"endpoint": "u"}},
    ]}
    out = crud.derive_findings("csrf", result)
    assert out[0]["detection_tier"] == "validated" and out[1]["detection_tier"] == "signal"
    assert out[0]["kind"] == "vuln"

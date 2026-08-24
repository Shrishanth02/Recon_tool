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
    """A forged-token, foreign-Origin state-changing request that SUCCEEDS is the
    vulnerability itself — the server accepted a request no legitimate same-site
    form could have produced.

    (Previously this case asserted a shared HTTP 400 was `validated`. That was
    incorrect: a 400 is equally consistent with the body validator rejecting the
    junk probe before any CSRF check ran, so it is not evidence. That scenario is
    now covered as a negative by test_csrf_shared_4xx_is_signal_not_validated.)
    """
    def http(method, url, headers, data=None, ctype=None):
        if method == "GET":
            return (200, "<form></form>", "session=abc")
        return (200, "transfer queued", "")   # forged request actually succeeded

    res = _run(monkeypatch, http)
    v = [f for f in res["findings"] if f["detection_tier"] == "validated"]
    assert v and v[0]["cwe"] == ["CWE-352"]
    assert v[0]["evidence"]["validation_result"] == "not_enforced"
    assert v[0]["evidence"]["probe_status"] == 200
    assert v[0]["evidence"]["control_status"] == 200


def test_csrf_shared_4xx_is_signal_not_validated(monkeypatch):
    """REGRESSION: the forged probe and the same-origin control both returning
    HTTP 400 is INCONCLUSIVE — both may have failed at input validation before
    any CSRF check ran. It must still be surfaced, but never as `validated`."""
    def http(method, url, headers, data=None, ctype=None):
        if method == "GET":
            return (200, "<form></form>", "session=abc")
        return (400, "invalid data", "")

    res = _run(monkeypatch, http)
    assert not [f for f in res["findings"] if f["detection_tier"] == "validated"],         "a shared 400 is not evidence that CSRF is unenforced"
    sig = [f for f in res["findings"] if "control had no effect" in f["name"]]
    assert sig and sig[0]["detection_tier"] == "signal"
    assert sig[0]["evidence"]["validation_result"] == "inconclusive"


def test_csrf_origin_check_is_negative(monkeypatch):
    """REGRESSION: an endpoint with no token that defends via Origin checking is
    NOT vulnerable. The single-probe check could not see this — it sent no Origin
    at all, got a 200, and reported a false positive. The differential catches it
    because only the foreign-Origin half is rejected."""
    def http(method, url, headers, data=None, ctype=None):
        if method == "GET":
            return (200, "<form></form>", "session=abc")
        if "csrf-probe.invalid" in (headers.get("Origin") or ""):
            return (403, "cross-origin request blocked", "")
        return (200, "ok", "")

    res = _run(monkeypatch, http)
    assert not [f for f in res["findings"] if f["detection_tier"] == "validated"]


def test_csrf_token_is_actually_validated_is_negative(monkeypatch):
    """An endpoint that rejects the forged token but accepts the harvested one is
    enforcing CSRF — no validated finding."""
    html = '<form><input name="csrf_token" value="GOODTOKEN"></form>'

    def http(method, url, headers, data=None, ctype=None):
        if method == "GET":
            return (200, html, "session=abc; SameSite=Lax")
        return (200, "ok", "") if "GOODTOKEN" in (data or "") else (403, "bad csrf", "")

    res = _run(monkeypatch, http)
    assert not [f for f in res["findings"] if f["detection_tier"] == "validated"]


def test_csrf_differential_probes_differ_only_in_control(monkeypatch):
    """The two probes must be identical except for the CSRF control, otherwise a
    difference in outcome could not be attributed to the control."""
    seen = []

    def http(method, url, headers, data=None, ctype=None):
        if method == "GET":
            return (200, '<form><input name="csrf_token" value="TOK"></form>', "s=1")
        seen.append({"method": method, "url": url, "ctype": ctype,
                     "origin": headers.get("Origin"), "data": data})
        return (200, "ok", "")

    _run(monkeypatch, http)
    assert len(seen) == 2, "expected a control probe and a forged probe"
    control, forged = seen
    assert control["method"] == forged["method"] == "POST"
    assert control["url"] == forged["url"]
    assert control["ctype"] == forged["ctype"]
    assert control["origin"] != forged["origin"], "Origin must be the varied control"
    assert "csrf-probe.invalid" in forged["origin"]
    # body differs only in the token value; the junk payload is held constant
    assert control["data"].endswith("&redopsx_probe=1")
    assert forged["data"].endswith("&redopsx_probe=1")
    assert "TOK" in control["data"] and "TOK" not in forged["data"]


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

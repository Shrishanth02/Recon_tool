"""Feature (API depth) tests: OPTIONS method discovery, method-level
authorization via non-destructive probes, DELETE-never-sent, and GraphQL
introspection. HTTP monkeypatched — no network, nothing destructive.
"""

from app.scanners import jwt_audit


def test_discover_methods_parses_allow(monkeypatch):
    monkeypatch.setattr(jwt_audit, "_http",
                        lambda m, u, h, data=None, ctype=None: (200, "", {"Allow": "GET, POST, OPTIONS"}))
    assert jwt_audit._discover_methods("https://x/o", {}) == ["GET", "POST", "OPTIONS"]


def test_missing_method_authz_is_validated(monkeypatch):
    def fake(method, url, headers, data=None, ctype=None):
        if method == "OPTIONS":
            return (200, "", {"Allow": "GET, POST, PUT, OPTIONS"})
        # invalid-body probe reaches the handler (400) with OR without a session.
        return (400, "bad request", {})

    monkeypatch.setattr(jwt_audit, "_http", fake)
    res = jwt_audit._check_method_authz("https://api.example.com/orders", {"Cookie": "s=1"})
    names = [f["name"] for f in res]
    assert any("POST" in n for n in names) and any("PUT" in n for n in names)
    for f in res:
        if "Missing method-level" in f["name"]:
            assert f["detection_tier"] == "validated" and f["cwe"] == ["CWE-285"]


def test_method_authz_enforced_is_negative(monkeypatch):
    def fake(method, url, headers, data=None, ctype=None):
        if method == "OPTIONS":
            return (200, "", {"Allow": "GET, POST"})
        if method == "POST":
            return (400, "bad", {}) if headers.get("Cookie") else (401, "unauth", {})
        return (200, "", {})

    monkeypatch.setattr(jwt_audit, "_http", fake)
    res = jwt_audit._check_method_authz("https://api.example.com/orders", {"Cookie": "s=1"})
    assert not any("Missing method-level" in f["name"] for f in res)


def test_unadvertised_method_not_probed(monkeypatch):
    called = []

    def fake(method, url, headers, data=None, ctype=None):
        called.append(method)
        if method == "OPTIONS":
            return (200, "", {"Allow": "GET, OPTIONS"})  # no state methods
        return (400, "", {})

    monkeypatch.setattr(jwt_audit, "_http", fake)
    jwt_audit._check_method_authz("https://x/o", {"Cookie": "s"})
    assert "POST" not in called and "PUT" not in called and "PATCH" not in called


def test_delete_is_reported_but_never_sent(monkeypatch):
    called = []

    def fake(method, url, headers, data=None, ctype=None):
        called.append(method)
        if method == "OPTIONS":
            return (200, "", {"Allow": "GET, DELETE, OPTIONS"})
        return (200, "", {})

    monkeypatch.setattr(jwt_audit, "_http", fake)
    res = jwt_audit._check_method_authz("https://x/item/1", {"Cookie": "s"})
    assert "DELETE" not in called                     # never actively sent
    assert any(f["name"].startswith("DELETE method advertised") for f in res)
    assert all(f["detection_tier"] == "signal" for f in res if "DELETE" in f["name"])


def test_graphql_introspection_enabled_is_validated(monkeypatch):
    monkeypatch.setattr(jwt_audit, "_http",
                        lambda m, u, h, data=None, ctype=None: (200, '{"data":{"__schema":{"types":[{"name":"Query"}]}}}', {}))
    res = jwt_audit._graphql_check("https://api.example.com/graphql", {})
    assert res and res[0]["detection_tier"] == "validated"
    assert res[0]["evidence"]["introspection"] is True


def test_graphql_only_checks_graphql_paths(monkeypatch):
    monkeypatch.setattr(jwt_audit, "_http",
                        lambda m, u, h, data=None, ctype=None: (200, '{"data":{"__schema":{}}}', {}))
    assert jwt_audit._graphql_check("https://api.example.com/orders", {}) == []


def test_graphql_introspection_disabled_no_finding(monkeypatch):
    monkeypatch.setattr(jwt_audit, "_http",
                        lambda m, u, h, data=None, ctype=None: (200, '{"errors":["introspection is disabled"]}', {}))
    assert jwt_audit._graphql_check("https://api.example.com/graphql", {}) == []


def test_stream_includes_method_and_graphql_findings(monkeypatch):
    def fake(method, url, headers, data=None, ctype=None):
        if "graphql" in url:
            return (200, '{"data":{"__schema":{"types":[]}}}', {})
        if method == "OPTIONS":
            return (200, "", {"Allow": "GET, POST"})
        if method == "GET":
            return (200, "data", {})
        return (400, "bad", {})              # POST reaches handler unauth

    monkeypatch.setattr(jwt_audit, "_http", fake)
    events = list(jwt_audit.stream(
        "", api_endpoints=["https://api.example.com/orders", "https://api.example.com/graphql"],
        identity={"cookie": "s=1"},
    ))
    res = next(e["data"] for e in events if e["type"] == "result")
    names = [f["name"] for f in res["findings"]]
    assert any("Missing method-level" in n for n in names)
    assert any("GraphQL introspection" in n for n in names)

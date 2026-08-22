"""Feature (IDOR) tests: cross-identity authorization comparison (read-only).

HTTP monkeypatched. Covers object-id detection, validated cross-user access,
the public-resource control (no false positive), authz-enforced negative,
single-identity suspected, non-id URLs, header building, no-secret evidence, and
per-finding tier in derivation.
"""

from app import crud
from app.scanners import idor

_TWO = [{"label": "A", "cookie": "sa"}, {"label": "B", "cookie": "sb"}]


def _stream(monkeypatch, fake, target, identities):
    monkeypatch.setattr(idor, "_http_get", fake)
    events = list(idor.stream(target, identities=identities))
    return next(e["data"] for e in events if e["type"] == "result")


def test_object_id_detection():
    assert idor._object_id("https://x/account/123") == "123"
    assert idor._object_id("https://x/api/user?id=5") == "5"
    assert idor._object_id("https://x/about") is None
    assert idor._object_id("https://x/p?name=bob") is None


def test_identity_headers():
    assert idor._identity_headers({"cookie": "s=1"}) == {"Cookie": "s=1"}
    assert idor._identity_headers({"auth_header": "Authorization: Bearer x"}) == {"Authorization": "Bearer x"}
    assert idor._identity_headers({"auth_header": "tokenval"}) == {"Authorization": "tokenval"}
    assert idor._identity_headers({}) == {}


def test_validated_cross_user_access(monkeypatch):
    body_a = "profile owner a@user.com XYZTOKEN1234567890"

    def fake(url, headers):
        ck = headers.get("Cookie")
        if ck == "sa":
            return (200, body_a)
        if ck == "sb":
            return (200, body_a)          # B (different user) sees A's resource
        return (403, "denied")            # anon denied

    res = _stream(monkeypatch, fake, "https://app.example.com/account/123", _TWO)
    v = [f for f in res["findings"] if f["detection_tier"] == "validated"]
    assert len(v) == 1
    ev = v[0]["evidence"]
    assert v[0]["cwe"] == ["CWE-639"]
    assert ev["identity_a"] == "A" and ev["identity_b"] == "B"
    assert ev["object_id"] == "123"
    assert ev["anon_denied"] is True
    # No session secret is ever stored in the evidence.
    assert "sa" not in str(ev) and "sb" not in str(ev)


def test_public_resource_is_not_idor(monkeypatch):
    def fake(url, headers):
        return (200, "public page TOKEN_PUBLIC_1234567890")   # A, B, anon all see it

    res = _stream(monkeypatch, fake, "https://app.example.com/doc/5", _TWO)
    assert res["findings"] == []          # anon control rules out a false positive


def test_authorization_enforced_is_negative(monkeypatch):
    def fake(url, headers):
        ck = headers.get("Cookie")
        if ck == "sa":
            return (200, "A private XYZTOKEN1234567890")
        return (403, "forbidden")         # B and anon denied

    res = _stream(monkeypatch, fake, "https://app.example.com/account/9", _TWO)
    assert res["findings"] == []


def test_single_identity_is_suspected(monkeypatch):
    res = _stream(monkeypatch, lambda u, h: (200, "x"),
                  "https://app.example.com/user/5", [{"label": "A", "cookie": "sa"}])
    sig = [f for f in res["findings"] if f["detection_tier"] == "signal"]
    assert sig and sig[0]["confidence"] == 35
    assert sig[0]["evidence"]["object_id"] == "5"


def test_non_id_url_not_tested(monkeypatch):
    res = _stream(monkeypatch, lambda u, h: (200, ""), "https://app.example.com/about", _TWO)
    assert res["findings"] == [] and res["tested"] == []


def test_malformed_target_errors():
    events = list(idor.stream("-oX", identities=_TWO))
    assert any(e["type"] == "error" for e in events)


def test_derive_idor_respects_per_finding_tier():
    result = {"findings": [
        {"severity": "high", "name": "IDOR: cross-user (123)", "location": "u",
         "cwe": ["CWE-639"], "detection_tier": "validated", "confidence": 85,
         "evidence": {"object_id": "123", "identity_a": "A"}},
    ]}
    out = crud.derive_findings("idor", result)
    assert out[0]["detection_tier"] == "validated"
    assert out[0]["kind"] == "vuln"
    assert out[0]["confidence"] == 85


# --------------------------------------------------------------------------- #
# Deeper IDOR: JSON / form body object IDs + method/body replay
# --------------------------------------------------------------------------- #
def test_body_object_id_detection():
    assert idor._object_id_from_body('{"user_id": 5}', "application/json") == "5"
    assert idor._object_id_from_body('{"data":{"account":"9"}}', "json") == "9"
    assert idor._object_id_from_body('{"name":"bob"}', "json") is None
    assert idor._object_id_from_body("id=7&q=1", "form") == "7"
    assert idor._object_id_from_body("{bad json", "json") is None
    assert idor._object_id_from_body(None, "json") is None


def test_json_body_idor_validated(monkeypatch):
    body = '{"user_id":5}'

    def fake(method, url, headers, data=None, ctype=None):
        assert method == "POST" and data == body and ctype == "application/json"
        return (200, "owner XYZTOKEN1234567890") if headers.get("Cookie") else (403, "denied")

    monkeypatch.setattr(idor, "_request", fake)
    events = list(idor.stream("https://api.example.com/account", identities=_TWO,
                              method="POST", data=body, content_type="json"))
    res = next(e["data"] for e in events if e["type"] == "result")
    v = [f for f in res["findings"] if f["detection_tier"] == "validated"]
    assert v and v[0]["evidence"]["object_id"] == "5"
    assert v[0]["evidence"]["method"] == "POST"
    assert v[0]["evidence"]["content_type"] == "application/json"
    assert v[0]["evidence"]["body_tested"] is True


def test_form_body_id_single_identity_suspected(monkeypatch):
    monkeypatch.setattr(idor, "_request", lambda *a, **k: (200, "x"))
    events = list(idor.stream("https://api.example.com/update",
                              identities=[{"label": "A", "cookie": "sa"}],
                              method="POST", data="id=9", content_type="form"))
    res = next(e["data"] for e in events if e["type"] == "result")
    sig = [f for f in res["findings"] if f["detection_tier"] == "signal"]
    assert sig and sig[0]["evidence"]["object_id"] == "9"
    assert sig[0]["evidence"]["method"] == "POST"


# --------------------------------------------------------------------------- #
# Unauthenticated enumerable-object access — broken access control with NO
# session (the case the cross-identity comparison alone drops as "public").
# --------------------------------------------------------------------------- #
def test_unauthenticated_enumerable_object_flagged(monkeypatch):
    """VulnShop-style /order/<id>: readable with NO session and adjacent ids
    return DISTINCT records -> unauthenticated broken-access-control finding."""
    orders = {
        "/order/5": (200, "Order 5 customer alice@shop.test total 42 WIDGETSKU0000000005"),
        "/order/4": (200, "Order 4 customer bob@shop.test total 99 GADGETSKU0000000004"),
        "/order/6": (200, "Order 6 customer carol@shop.test total 17 GIZMOSKU00000000006"),
    }

    def fake(url, headers):
        for path, resp in orders.items():
            if url.endswith(path):
                return resp
        return (404, "not found")

    res = _stream(monkeypatch, fake, "https://shop.test/order/5", [])  # no identities
    unauth = [f for f in res["findings"] if f["name"].startswith("Unauthenticated object access")]
    assert len(unauth) == 1
    f = unauth[0]
    assert f["detection_tier"] == "validated" and f["severity"] == "high"
    assert f["evidence"]["object_id"] == "5" and f["evidence"]["anonymous"] is True
    assert "CWE-639" in f["cwe"] and "CWE-284" in f["cwe"]
    # The validated unauth finding supersedes the unconfirmed "Possible IDOR" signal.
    assert not [x for x in res["findings"] if x["name"].startswith("Possible IDOR")]


def test_public_catalogue_object_not_flagged(monkeypatch):
    """A genuinely public catalogue object (/product/<id>) is enumerable but NOT a
    sensitive object type -> no unauthenticated-access false positive, and no
    low-confidence signal either."""
    prods = {
        "/product/5": (200, "Product 5 Blue Widget CATALOGSKU0000000005"),
        "/product/4": (200, "Product 4 Red Gadget CATALOGSKU0000000004"),
        "/product/6": (200, "Product 6 Green Gizmo CATALOGSKU0000000006"),
    }

    def fake(url, headers):
        for path, resp in prods.items():
            if url.endswith(path):
                return resp
        return (404, "x")

    res = _stream(monkeypatch, fake, "https://shop.test/product/5", [])
    assert res["findings"] == []   # public object type -> nothing flagged


def test_sensitive_but_not_enumerable_not_flagged(monkeypatch):
    """A sensitive-looking path where every id returns the SAME page is a single
    shared resource, not per-object records -> not enumerable -> not flagged."""
    def fake(url, headers):
        return (200, "Account help centre contact support SHAREDHELPPAGEZZZ")  # identical for all ids

    res = _stream(monkeypatch, fake, "https://shop.test/account/5", [])
    assert not [f for f in res["findings"] if f["name"].startswith("Unauthenticated object access")]


def test_unauth_object_requires_anonymous_read(monkeypatch):
    """If the object is NOT anonymously readable (403), the unauthenticated check
    does not fire — that path is for the two-identity cross-user comparison."""
    res = _stream(monkeypatch, lambda u, h: (403, "forbidden"), "https://shop.test/order/5", [])
    assert not [f for f in res["findings"] if f["name"].startswith("Unauthenticated object access")]


def test_sensitive_object_type_classification():
    assert idor._object_type("https://x/order/5", "5") == "order"
    assert idor._object_type("https://x/product/9", "9") == "product"
    assert idor._object_type("https://x/api/user?id=7", "7") == "user"
    assert idor._sensitive("https://x/order/5", "5", "") is True
    assert idor._sensitive("https://x/product/5", "5", "") is False
    assert idor._sensitive("https://x/x/5", "5", "contact a@b.co") is True   # unknown + PII
    assert idor._sensitive("https://x/x/5", "5", "no pii here") is False


def test_with_id_and_distinct_record_helpers():
    assert idor._with_id("https://x/order/5", "5", "6") == "https://x/order/6"
    assert idor._with_id("https://x/api?id=5", "5", "6") == "https://x/api?id=6"
    assert idor._distinct_record("alice@a.com XYZTOKEN1234567890", "bob@b.com QRSTOKEN0987654321")
    assert not idor._distinct_record("same body content here", "same body content here")


def test_derive_unauth_object_finding_is_vuln():
    result = {"findings": [idor._unauth_finding("https://x/order/5", "5", (200, ""))]}
    out = crud.derive_findings("idor", result)
    assert out[0]["detection_tier"] == "validated"
    assert out[0]["kind"] == "vuln"
    assert out[0]["confidence"] == 80
    assert "CWE-639" in out[0]["cwe"]

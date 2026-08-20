"""Feature (business-logic foundation) tests: workflow model + signal-only
analysis. Pure functions — no network. Confirms signals never inflate risk.
"""

from app import bizlogic, crud, risk


# --------------------------------------------------------------------------- #
# Workflow model
# --------------------------------------------------------------------------- #
def test_build_model_from_mixed_sources():
    auth = {
        "authenticated": True,
        "forms": [{"action": "https://x/checkout", "method": "POST", "inputs": ["price", "qty", "csrf"]}],
        "parameterized_urls": [{"url": "https://x/search?q=1", "params": ["q"]}],
        "api_endpoints": ["https://x/api/orders?user_id=5"],
    }
    crawl = {"authenticated": False, "parameterized_urls": [{"url": "https://x/item?id=1", "params": ["id"]}]}
    m = bizlogic.build_model([auth, crawl])
    keys = {(e["path"], e["method"], e["authenticated"]) for e in m["endpoints"]}
    assert ("/checkout", "POST", True) in keys
    assert ("/api/orders", "GET", True) in keys
    assert ("/item", "GET", False) in keys
    assert any(r["node"] == "/checkout" for r in m["relationships"])   # workflow step modelled


def test_build_model_dedup_and_id_normalization():
    src = {"authenticated": True, "endpoints": [
        {"url": "https://x/order/1", "method": "GET", "params": []},
        {"url": "https://x/order/2", "method": "GET", "params": []},   # same node after {id}
    ]}
    m = bizlogic.build_model([src])
    assert len([e for e in m["endpoints"] if e["path"] == "/order/{id}"]) == 1


# --------------------------------------------------------------------------- #
# Signal analysis
# --------------------------------------------------------------------------- #
def _model(**e):
    e.setdefault("url", "https://x" + e.get("path", "/x"))
    e.setdefault("params", [])
    e.setdefault("authenticated", True)
    e.setdefault("source", "form")
    e.setdefault("method", "POST")
    return {"endpoints": [e]}


def test_client_controlled_price_signal():
    fs = bizlogic.analyze(_model(path="/buy", params=["price", "qty"]))
    price = [f for f in fs if "price/quantity" in f["name"]]
    assert price and price[0]["detection_tier"] == "signal" and price[0]["kind"] == "info"
    assert "price" in price[0]["evidence"]["sensitive_parameters"]


def test_privilege_param_signal():
    fs = bizlogic.analyze(_model(path="/user/update", params=["role", "name"]))
    assert any("privilege/state" in f["name"] for f in fs)


def test_inconsistent_authorization_signal():
    m = {"endpoints": [
        {"url": "https://x/admin/1", "path": "/admin/{id}", "method": "GET", "params": [], "authenticated": True, "source": "api"},
        {"url": "https://x/admin/2", "path": "/admin/{id}", "method": "GET", "params": [], "authenticated": False, "source": "api"},
    ]}
    assert any("reachable authenticated and unauthenticated" in f["name"] for f in bizlogic.analyze(m))


def test_state_changing_workflow_step_signal():
    fs = bizlogic.analyze(_model(path="/checkout", method="POST"))
    assert any("State-changing workflow step" in f["name"] for f in fs)


def test_benign_endpoint_no_signal():
    m = {"endpoints": [{"url": "https://x/about", "path": "/about", "method": "GET",
                        "params": ["lang"], "authenticated": False, "source": "param_url"}]}
    assert bizlogic.analyze(m) == []


# --------------------------------------------------------------------------- #
# Risk + derive integration
# --------------------------------------------------------------------------- #
def test_signals_do_not_inflate_risk():
    fs = bizlogic.analyze(_model(path="/buy", params=["price"]))
    assert fs
    assert all(f["kind"] == "info" and f["detection_tier"] == "signal" for f in fs)
    assert risk.workspace_risk(fs)["score"] == 0        # info kind never scores


def test_derive_bizlogic_keeps_info_kind_and_signal():
    fs = bizlogic.analyze(_model(path="/checkout", method="POST", params=["price", "role"]))
    out = crud.derive_findings("bizlogic", {"findings": fs})
    assert out and all(o["kind"] == "info" and o["detection_tier"] == "signal" for o in out)
    assert risk.workspace_risk(out)["score"] == 0

"""Phase 5: security-headers middleware + infra endpoints.

With ``SECURITY_HEADERS`` on (the default) every response carries the hardening
headers, ``/health`` still works, and the headers coexist with CORS (they only
``setdefault``, so the CORS ``Access-Control-*`` set is never clobbered).
Also smoke-tests the ``/metrics`` and ``/ready`` infra endpoints.
"""

_ORIGIN = "http://localhost:5173"


def test_security_headers_present_on_normal_response(client):
    resp = client.get("/health")
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"status": "ok"}
    assert resp.headers.get("X-Content-Type-Options") == "nosniff"
    assert resp.headers.get("X-Frame-Options") == "DENY"
    assert "default-src" in resp.headers.get("Content-Security-Policy", "")
    assert resp.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"


def test_security_headers_coexist_with_cors(client):
    resp = client.get("/health", headers={"Origin": _ORIGIN})
    assert resp.status_code == 200, resp.text
    # CORS still applied...
    assert resp.headers.get("Access-Control-Allow-Origin") == _ORIGIN
    # ...and the security headers are present alongside it (setdefault, no clobber).
    assert resp.headers.get("X-Content-Type-Options") == "nosniff"
    assert resp.headers.get("X-Frame-Options") == "DENY"


def test_cors_preflight_still_works(client):
    resp = client.options(
        "/health",
        headers={
            "Origin": _ORIGIN,
            "Access-Control-Request-Method": "GET",
        },
    )
    assert resp.status_code in (200, 204), resp.text
    assert resp.headers.get("Access-Control-Allow-Origin") == _ORIGIN


def test_request_id_header_echoed(client):
    resp = client.get("/health")
    assert resp.headers.get("X-Request-ID")


def test_metrics_endpoint_returns_text(client):
    """/metrics returns 200 text (real prometheus exposition or the stub)."""
    resp = client.get("/metrics")
    assert resp.status_code == 200, resp.text
    assert resp.text  # non-empty body either way
    assert resp.headers["content-type"].startswith("text/plain")


def test_ready_endpoint_ok(client):
    resp = client.get("/ready")
    assert resp.status_code == 200, resp.text
    assert resp.json()["status"] == "ready"

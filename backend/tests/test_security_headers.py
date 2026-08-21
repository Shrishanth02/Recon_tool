"""Phase 5: security-headers middleware + infra endpoints.

With ``SECURITY_HEADERS`` on (the default) every response carries the hardening
headers, ``/health`` still works, and the headers coexist with CORS (they only
``setdefault``, so the CORS ``Access-Control-*`` set is never clobbered).
Also smoke-tests the ``/metrics`` and ``/ready`` infra endpoints.
"""

from app.config import settings as app_settings

_ORIGIN = "http://localhost:5173"


def test_security_headers_present_on_normal_response(client):
    resp = client.get("/health")
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"status": "ok"}
    assert resp.headers.get("X-Content-Type-Options") == "nosniff"
    assert resp.headers.get("X-Frame-Options") == "DENY"
    assert resp.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"
    # CSP is strict and carries the hardening directives (STEP 4).
    csp = resp.headers.get("Content-Security-Policy", "")
    assert "default-src 'self'" in csp
    assert "frame-ancestors 'none'" in csp
    assert "base-uri 'none'" in csp
    assert "object-src 'none'" in csp
    assert "form-action 'none'" in csp


def test_hsts_absent_on_plain_http(client):
    # No TLS, no forwarded-proto -> HSTS must not be asserted.
    resp = client.get("/health")
    assert "Strict-Transport-Security" not in resp.headers


def test_hsts_emitted_behind_tls_terminating_proxy(client):
    # Plain-http ASGI scheme but X-Forwarded-Proto: https (TLS proxy) -> emit HSTS.
    resp = client.get("/health", headers={"X-Forwarded-Proto": "https"})
    assert resp.status_code == 200
    hsts = resp.headers.get("Strict-Transport-Security", "")
    assert "max-age=31536000" in hsts and "includeSubDomains" in hsts


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


def test_metrics_disabled_by_default(client):
    """Secure-by-default (STEP 4): /metrics is OFF unless explicitly enabled."""
    resp = client.get("/metrics")
    assert resp.status_code == 404


def test_metrics_returns_text_when_enabled(client, monkeypatch):
    """When enabled with no token, /metrics returns 200 text (exposition or stub)."""
    monkeypatch.setattr(app_settings, "METRICS_ENABLED", True)
    resp = client.get("/metrics")
    assert resp.status_code == 200, resp.text
    assert resp.text  # non-empty body either way
    assert resp.headers["content-type"].startswith("text/plain")


def test_metrics_requires_token_when_configured(client, monkeypatch):
    """With METRICS_TOKEN set, /metrics demands a matching bearer token."""
    monkeypatch.setattr(app_settings, "METRICS_ENABLED", True)
    monkeypatch.setattr(app_settings, "METRICS_TOKEN", "scrape-secret-123")
    assert client.get("/metrics").status_code == 401  # no token
    assert (
        client.get("/metrics", headers={"Authorization": "Bearer nope"}).status_code
        == 401
    )  # wrong token
    ok = client.get("/metrics", headers={"Authorization": "Bearer scrape-secret-123"})
    assert ok.status_code == 200, ok.text
    assert ok.text


def test_ready_endpoint_ok(client):
    resp = client.get("/ready")
    assert resp.status_code == 200, resp.text
    assert resp.json()["status"] == "ready"

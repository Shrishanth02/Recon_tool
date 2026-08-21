"""STEP 4: frontend serving headers + CSP + inline-script removal (regression).

The SPA origin runs the app's JavaScript, holds the access token, and renders
scan-derived report HTML. These content assertions lock in the production CSP /
security headers (in ``frontend/nginx.conf``) and the removal of the inline theme
``<script>`` from ``index.html`` (extracted to ``/theme-init.js`` so ``script-src``
can stay strict ``'self'`` with no ``'unsafe-inline'``). They read the committed
files, so a regression is caught without needing nginx or a browser.
"""

import re
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]
_NGINX = _REPO / "frontend" / "nginx.conf"
_INDEX = _REPO / "frontend" / "index.html"


def test_nginx_serves_csp_and_security_headers():
    conf = _NGINX.read_text(encoding="utf-8")
    assert "Content-Security-Policy" in conf
    assert "default-src 'self'" in conf
    # script-src is strict 'self' — NOT weakened with 'unsafe-inline'/'unsafe-eval'.
    assert "script-src 'self';" in conf
    assert "script-src 'self' 'unsafe-inline'" not in conf
    assert "'unsafe-eval'" not in conf
    assert "frame-ancestors 'none'" in conf
    assert "object-src 'none'" in conf
    assert "base-uri 'self'" in conf
    # Framing + MIME-sniffing + referrer hardening headers.
    assert "X-Frame-Options" in conf and "DENY" in conf
    assert "nosniff" in conf
    assert "Referrer-Policy" in conf


def test_index_html_has_no_inline_script_body():
    html = _INDEX.read_text(encoding="utf-8")
    # The theme init moved to an external file so script-src can stay strict.
    assert "/theme-init.js" in html
    # No <script> without a src= that carries an inline body.
    inline = re.findall(r"<script(?![^>]*\bsrc=)[^>]*>\s*\S", html)
    assert inline == [], f"unexpected inline <script> body in index.html: {inline}"

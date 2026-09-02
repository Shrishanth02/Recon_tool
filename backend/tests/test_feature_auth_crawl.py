"""auth_crawl regression: same-site scoping must be port-agnostic.

Empirically found during detection validation against a controlled target on a
non-standard port (127.0.0.1:8201): the authenticated deep-crawler collapsed to a
single page because ``_same_site`` compared the URL's bare hostname against a
``clean_target`` domain that still carried the port, so every same-host link was
rejected and never enqueued. That silently breaks the "deep crawl behind login"
for any target on a non-standard port (dev/staging/internal apps, custom API
ports) — a common pentest scenario.
"""
from app.scanners import auth_crawl


def test_same_site_is_port_agnostic():
    # The bug case: link and domain share the host, domain carries the port.
    assert auth_crawl._same_site("http://127.0.0.1:8201/dashboard", "127.0.0.1:8201")
    assert auth_crawl._same_site("http://app.internal:8080/admin", "app.internal:8080")
    # A link whose URL also carries the port matches a port-less domain, and v.v.
    assert auth_crawl._same_site("http://example.com:3000/x", "example.com")
    assert auth_crawl._same_site("https://example.com/x", "example.com:443")


def test_same_site_still_scopes_correctly():
    # Standard-port behaviour is unchanged...
    assert auth_crawl._same_site("https://example.com/x", "example.com")
    # ...subdomains of the target are in-scope...
    assert auth_crawl._same_site("https://app.example.com/x", "example.com")
    # ...and a genuinely different host is still rejected (no over-broadening).
    assert not auth_crawl._same_site("https://evil.com/x", "example.com")
    assert not auth_crawl._same_site("https://notexample.com/x", "example.com")
    assert not auth_crawl._same_site("https://example.com.evil.com/x", "example.com")

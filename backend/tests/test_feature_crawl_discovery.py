"""Tier-3 tests: passive, same-origin form + API-endpoint discovery in crawl.

The unauthenticated crawl now parses ``<form>`` elements and picks API-shaped
URLs out of the data it already collected, so the CSRF and JWT/API+GraphQL
stages have a surface to work on without operator credentials. Parsing only —
no script execution, no extra fetching, same-origin, non-destructive.
"""

from app.scanners import crawl


class _Resp:
    def __init__(self, url, text, status=200):
        self.url = url
        self.text = text
        self.status_code = status


def _patch(monkeypatch, html):
    monkeypatch.setattr(crawl, "reachable", lambda u: True)
    monkeypatch.setattr(crawl, "_which", lambda name: None)  # skip katana/gau/arjun

    def fake_request(method, url, **_k):
        # The page fetch returns our HTML; there are no <script src> so no JS GET.
        return _Resp("https://app.example.com/", html)

    monkeypatch.setattr(crawl.safe_http, "safe_request", fake_request)


def _result(target="https://app.example.com"):
    for ev in crawl.stream(target):
        if ev.get("type") == "result":
            return ev["data"]
    return None


_HTML = """<html><body>
  <a href="/api/v1/users">users</a>
  <a href="/graphql">gql</a>
  <a href="/about">about</a>
  <form action="/transfer" method="post">
    <input name="amount"><input name="to"><button name="go">Send</button>
  </form>
  <form action="https://evil.example/steal" method="post"><input name="x"></form>
  <form action="/search"><input name="q"></form>
</body></html>"""


def test_crawl_discovers_same_origin_forms(monkeypatch):
    _patch(monkeypatch, _HTML)
    data = _result()
    actions = {(f["action"], f["method"]) for f in data["forms"]}
    # Same-origin POST form is discovered with its input names.
    assert ("https://app.example.com/transfer", "POST") in actions
    transfer = next(f for f in data["forms"] if f["action"].endswith("/transfer"))
    assert transfer["inputs"] == ["amount", "to", "go"]
    # The same-origin GET form is discovered too (CSRF will skip non-state methods).
    assert ("https://app.example.com/search", "GET") in actions


def test_crawl_excludes_cross_origin_forms(monkeypatch):
    _patch(monkeypatch, _HTML)
    data = _result()
    assert all("evil.example" not in f["action"] for f in data["forms"])


def test_crawl_discovers_same_origin_api_endpoints(monkeypatch):
    _patch(monkeypatch, _HTML)
    data = _result()
    eps = set(data["api_endpoints"])
    assert "https://app.example.com/api/v1/users" in eps
    assert "https://app.example.com/graphql" in eps
    # A plain page is not an API endpoint.
    assert "https://app.example.com/about" not in eps


def test_crawl_form_and_api_counts_present(monkeypatch):
    _patch(monkeypatch, _HTML)
    data = _result()
    assert data["counts"]["forms"] == len(data["forms"]) >= 2
    assert data["counts"]["api_endpoints"] == len(data["api_endpoints"]) >= 2


def test_crawl_forms_are_bounded(monkeypatch):
    many = "<html><body>" + "".join(
        f'<form action="/f{i}" method="post"><input name="a"></form>'
        for i in range(crawl.FORM_CAP + 15)
    ) + "</body></html>"
    _patch(monkeypatch, many)
    data = _result()
    assert len(data["forms"]) == crawl.FORM_CAP


# --------------------------------------------------------------------------- #
# arjun fail-closed isolation gate
#
# arjun runs via a direct subprocess.run (not base.stream_command), so it is the
# one scanner that would otherwise execute on the HOST even under container
# isolation. It is not container-wrapped yet, so it must SKIP (never run
# unisolated) when the active policy is CONTAINER or UNAVAILABLE, and run only
# under NONE/PROCESS.
# --------------------------------------------------------------------------- #
def test_arjun_fail_closed_under_container_and_unavailable(monkeypatch):
    from app import sandbox

    monkeypatch.setattr(crawl, "_which", lambda name: "/usr/bin/arjun")
    calls = []

    def spy_run(*a, **k):
        calls.append(a)
        raise AssertionError("arjun executed on the host despite the isolation policy")

    monkeypatch.setattr(crawl.subprocess, "run", spy_run)

    for mode in (sandbox.ISOLATION_CONTAINER, sandbox.ISOLATION_UNAVAILABLE):
        calls.clear()
        monkeypatch.setattr(
            sandbox, "effective_isolation", lambda m=mode: (m, "docker unavailable")
        )
        events = list(crawl._run_arjun(["http://t/x"], None, set()))
        assert not calls, f"arjun ran on the host under {mode}"
        assert any("skipped" in str(e.get("data", "")).lower() for e in events), mode


def test_arjun_runs_under_process_isolation(monkeypatch):
    from app import sandbox

    monkeypatch.setattr(crawl, "_which", lambda name: "/usr/bin/arjun")
    calls = []

    class _CP:
        returncode = 0

    def spy_run(cmd, *a, **k):
        calls.append(cmd)
        return _CP()

    monkeypatch.setattr(crawl.subprocess, "run", spy_run)
    monkeypatch.setattr(
        sandbox, "effective_isolation", lambda: (sandbox.ISOLATION_PROCESS, "")
    )
    list(crawl._run_arjun(["http://t/x"], None, set()))
    assert calls, "arjun did not run under process isolation"
    # It runs the arjun binary directly on the host (NOT a docker wrapper).
    assert calls[0][0] == "/usr/bin/arjun"

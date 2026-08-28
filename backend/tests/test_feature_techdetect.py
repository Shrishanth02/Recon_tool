"""Techdetect SSRF-safety: ``builtwith`` must parse the HTML we ALREADY fetched
through the netguard-pinned safe client, never do its own (unpinned,
redirect-following, off-thread) urllib fetch that could reach a private/metadata
IP. HTTP is monkeypatched — no network.
"""

from app.scanners import techdetect


class _Resp:
    status_code = 200
    reason = "OK"
    headers = {"Server": "nginx", "Content-Type": "text/html"}
    text = "<html><body>hi</body></html>"


def _result(events):
    return next(e["data"] for e in events if e["type"] == "result")


def test_techdetect_feeds_builtwith_safe_html_not_a_self_fetch(monkeypatch):
    monkeypatch.setattr(techdetect.safe_http, "safe_request", lambda *a, **k: _Resp())
    seen = {}

    def _fake_builtwith(url, headers=None, html=None, **k):
        seen["url"] = url
        seen["html"] = html
        seen["headers"] = headers
        return {"web-servers": ["Nginx"]}

    monkeypatch.setattr(techdetect, "builtwith", _fake_builtwith)
    res = _result(list(techdetect.stream("http://site.test")))
    # builtwith got the safe-fetched HTML + headers -> it never fetched on its own.
    assert seen["html"] == "<html><body>hi</body></html>"
    assert (seen["headers"] or {}).get("Server") == "nginx"
    assert res["detected_tech"] == {"web-servers": ["Nginx"]}


def test_techdetect_uses_safe_get_so_body_is_pinned(monkeypatch):
    calls = {}

    def _sr(method, url, **k):
        calls["method"] = method
        return _Resp()

    monkeypatch.setattr(techdetect.safe_http, "safe_request", _sr)
    monkeypatch.setattr(techdetect, "builtwith", lambda *a, **k: {})
    _result(list(techdetect.stream("http://site.test")))
    # A GET (not HEAD) so the body is captured via the netguard-pinned client and
    # can be handed to builtwith — closing builtwith's independent fetch.
    assert calls["method"] == "GET"

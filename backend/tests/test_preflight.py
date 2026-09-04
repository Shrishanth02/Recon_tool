"""P0-6 regression tests — scanner preflight + missing-binary behavior.

The auto-pentest pipeline must not silently degrade when a REQUIRED scanner
binary is absent. These tests cover the preflight classification/inventory, the
``/preflight`` endpoint, and the clear error a scanner emits when its binary is
missing.
"""

import app.preflight as preflight
from app.scanners import base

REQUIRED = {"nmap", "subfinder", "httpx", "nuclei", "ffuf"}
OPTIONAL_EXPECTED = {"whois", "sqlmap", "dalfox", "katana", "gau", "arjun"}


def _patch_which(monkeypatch, present: set):
    monkeypatch.setattr(
        preflight.shutil, "which",
        lambda name: f"/usr/bin/{name}" if name in present else None,
    )
    # preflight's sqlmap/arjun availability also defers to the scanners' own
    # discovery (which finds pip-installed, off-PATH tools). For these which-based
    # tests to fully control availability, gate those fallbacks on `present` too —
    # otherwise a real local sqlmap/arjun install would leak into the result.
    monkeypatch.setattr(
        "app.scanners.injection._sqlmap_cmd",
        lambda: ["sqlmap"] if "sqlmap" in present else None,
    )
    monkeypatch.setattr(
        "app.scanners.crawl._which",
        lambda name: f"/x/{name}" if name in present else None,
    )


# --------------------------------------------------------------------------- #
# Classification
# --------------------------------------------------------------------------- #
def test_required_set_is_exactly_the_core_binaries():
    assert set(preflight.REQUIRED_TOOLS) == REQUIRED


def test_optional_set_covers_graceful_tools_and_is_disjoint():
    assert OPTIONAL_EXPECTED <= set(preflight.OPTIONAL_TOOLS)
    assert not (set(preflight.REQUIRED_TOOLS) & set(preflight.OPTIONAL_TOOLS))


def test_check_tools_shape():
    s = preflight.check_tools()
    assert set(s) == {"required", "optional", "missing_required",
                      "missing_optional", "ok"}
    assert set(s["required"]) == REQUIRED
    assert set(s["optional"]) == set(preflight.OPTIONAL_TOOLS)
    assert isinstance(s["ok"], bool)


# --------------------------------------------------------------------------- #
# Required vs optional semantics
# --------------------------------------------------------------------------- #
def test_all_required_present_is_ok_even_if_optional_missing(monkeypatch):
    _patch_which(monkeypatch, set(REQUIRED))  # optionals absent
    s = preflight.check_tools()
    assert s["ok"] is True
    assert s["missing_required"] == []
    # Optional absence never affects ok.
    assert set(s["missing_optional"]) == set(preflight.OPTIONAL_TOOLS)


def test_missing_required_is_flagged_and_not_ok(monkeypatch):
    _patch_which(monkeypatch, (REQUIRED - {"nuclei"}) | set(preflight.OPTIONAL_TOOLS))
    s = preflight.check_tools()
    assert s["ok"] is False
    assert s["missing_required"] == ["nuclei"]
    assert s["missing_optional"] == []


def test_log_startup_report_never_raises_when_all_missing(monkeypatch):
    _patch_which(monkeypatch, set())
    status = preflight.log_startup_report()  # must not raise / must not exit
    assert status["ok"] is False
    assert set(status["missing_required"]) == REQUIRED


# --------------------------------------------------------------------------- #
# Endpoint
# --------------------------------------------------------------------------- #
def test_preflight_endpoint_returns_inventory(client):
    r = client.get("/preflight")
    assert r.status_code == 200
    body = r.json()
    assert set(body["required"]) == REQUIRED
    assert "ok" in body and "missing_required" in body


# --------------------------------------------------------------------------- #
# Missing-binary behavior — a clear error, never a silent empty result
# --------------------------------------------------------------------------- #
def test_missing_binary_yields_clear_error_event():
    events = list(base.stream_command(["reconx-nonexistent-binary-zzz"]))
    assert any(
        e.get("type") == "error" and "not found" in str(e.get("data", "")).lower()
        for e in events
    ), events
    assert any(e.get("type") == "returncode" and e.get("data") == 127 for e in events)


# --------------------------------------------------------------------------- #
# preflight must AGREE with the scanners' actual tool discovery. sqlmap and arjun
# install via pip with a console script that lands in a Scripts dir off PATH (and
# sqlmap's package has no __main__), so shutil.which alone misses them — but the
# injection/crawl scanners find and RUN them. If preflight disagreed, the report's
# coverage matrix would mark e.g. "SQL Injection: NOT TESTED / tool unavailable"
# for a scan that actually ran sqlmap and produced a Confirmed finding.
# --------------------------------------------------------------------------- #
def test_preflight_agrees_with_scanner_tool_discovery():
    """Environment-independent invariant: preflight's sqlmap/arjun availability
    equals what the scanners can actually run (both False in CI, both True on a
    box with the pip packages installed off-PATH)."""
    from app.scanners import crawl
    from app.scanners.injection import _sqlmap_cmd

    opt = preflight.check_tools()["optional"]
    assert opt["sqlmap"] == (_sqlmap_cmd() is not None)
    assert opt["arjun"] == (crawl._which("arjun") is not None)


def test_preflight_reports_pip_tool_when_scanner_can_run_it(monkeypatch):
    """shutil.which sees nothing on PATH, but the scanners' own discovery says
    sqlmap and arjun are runnable -> preflight MUST report them available, while a
    tool nothing can run stays unavailable."""
    monkeypatch.setattr(preflight.shutil, "which", lambda *_a, **_k: None)
    monkeypatch.setattr(
        "app.scanners.injection._sqlmap_cmd",
        lambda: ["python", "/x/sqlmap/sqlmap.py"],
    )
    monkeypatch.setattr(
        "app.scanners.crawl._which",
        lambda name: "/x/Scripts/arjun.exe" if name == "arjun" else None,
    )
    status = preflight.check_tools()
    assert status["optional"]["sqlmap"] is True
    assert status["optional"]["arjun"] is True
    assert status["optional"]["whois"] is False        # nothing can run it
    assert status["required"]["nmap"] is False          # a required binary off PATH
    assert "sqlmap" not in status["missing_optional"]
    assert "arjun" not in status["missing_optional"]

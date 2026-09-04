"""Regression: the sqlmap availability probe must not treat a broken/placeholder
`sqlmap` package (importable but NOT runnable via `python -m sqlmap`) as usable.

A squatted or partial `sqlmap` pip package ships an importable ``sqlmap/__init__.py``
with no ``__main__``. The old probe returned ``[python, -m, sqlmap]`` for it, so the
scan reported ``tools.sqlmap = True`` while the command actually fails at runtime —
a scan-level false-clean ("sqlmap ran, found no SQLi" when it never ran). The probe
must require ``sqlmap.__main__`` (present in a real install) so such a package reads
as ABSENT, consistent with ``preflight.check_tools`` (which only trusts the binary).
"""
import importlib.util

from app.scanners import injection


def test_placeholder_sqlmap_package_without_main_is_absent(monkeypatch):
    """Importable `sqlmap` with NO `__main__` -> _sqlmap_cmd() returns None."""
    monkeypatch.setattr(injection.shutil, "which", lambda *_a, **_k: None)
    real = importlib.util.find_spec

    def fake(name, *a, **k):
        if name == "sqlmap":
            return real("os")          # truthy spec: "importable"
        if name == "sqlmap.__main__":
            return None                # NOT runnable via python -m
        return real(name, *a, **k)

    monkeypatch.setattr(importlib.util, "find_spec", fake)
    assert injection._sqlmap_cmd() is None


def test_runnable_sqlmap_package_with_main_is_used(monkeypatch):
    """Importable `sqlmap` WITH `__main__` -> used via `python -m sqlmap`."""
    monkeypatch.setattr(injection.shutil, "which", lambda *_a, **_k: None)
    real = importlib.util.find_spec

    def fake(name, *a, **k):
        if name in ("sqlmap", "sqlmap.__main__"):
            return real("os")          # both truthy
        return real(name, *a, **k)

    monkeypatch.setattr(importlib.util, "find_spec", fake)
    cmd = injection._sqlmap_cmd()
    assert cmd is not None and cmd[-2:] == ["-m", "sqlmap"]


def test_sqlmap_binary_on_path_is_preferred(monkeypatch):
    """A real sqlmap console script on PATH is used directly (no package probe)."""
    monkeypatch.setattr(
        injection.shutil, "which",
        lambda exe, *_a, **_k: "/usr/bin/sqlmap" if exe == "sqlmap" else None,
    )
    assert injection._sqlmap_cmd() == ["/usr/bin/sqlmap"]

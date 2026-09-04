"""Regression: sqlmap availability probe (app.scanners.injection._sqlmap_cmd).

The probe must find a RUNNABLE sqlmap and reject a non-runnable one:
  * a console script / sqlmap.py on PATH        -> use it;
  * an importable package with __main__         -> `python -m sqlmap`;
  * the OFFICIAL PyPI package (sqlmap/sqlmap.py, thin __init__, no __main__,
    console script often off-PATH) -> run its bundled sqlmap.py directly;
  * a bare/placeholder package (just __init__.py, no sqlmap.py, no __main__)
    -> ABSENT, so the scan never reports tools.sqlmap=True for a tool that
       cannot run (which would be a scan-level false-clean).
"""
import importlib.util
import sys
import types

from app.scanners import injection


def _spec_for_dir(path):
    """A minimal ModuleSpec-like object pointing at a package directory."""
    s = types.SimpleNamespace()
    s.origin = str(path / "__init__.py")
    s.submodule_search_locations = [str(path)]
    return s


def _patch_probe(monkeypatch, *, which=None, pkg_dir=None, has_main=False):
    monkeypatch.setattr(injection.shutil, "which", which or (lambda *_a, **_k: None))
    real = importlib.util.find_spec

    def fake(name, *a, **k):
        if name == "sqlmap":
            return _spec_for_dir(pkg_dir) if pkg_dir is not None else None
        if name == "sqlmap.__main__":
            return object() if has_main else None
        return real(name, *a, **k)

    monkeypatch.setattr(importlib.util, "find_spec", fake)


def test_bare_placeholder_package_is_absent(monkeypatch, tmp_path):
    """Package with only __init__.py (no sqlmap.py, no __main__) -> None."""
    (tmp_path / "__init__.py").write_text("# placeholder\n")
    _patch_probe(monkeypatch, pkg_dir=tmp_path, has_main=False)
    assert injection._sqlmap_cmd() is None


def test_official_pypi_package_runs_bundled_sqlmap_py(monkeypatch, tmp_path):
    """Official shape: sqlmap/sqlmap.py present, no __main__ -> run sqlmap.py."""
    (tmp_path / "__init__.py").write_text("# thin init\n")
    (tmp_path / "sqlmap.py").write_text("# entry\n")
    _patch_probe(monkeypatch, pkg_dir=tmp_path, has_main=False)
    cmd = injection._sqlmap_cmd()
    assert cmd is not None
    assert cmd[0] == sys.executable
    assert cmd[-1].endswith("sqlmap.py")


def test_package_with_dunder_main_uses_module_form(monkeypatch, tmp_path):
    """A package exposing __main__ is run as `python -m sqlmap`."""
    (tmp_path / "__init__.py").write_text("# init\n")
    (tmp_path / "__main__.py").write_text("# main\n")
    _patch_probe(monkeypatch, pkg_dir=tmp_path, has_main=True)
    assert injection._sqlmap_cmd() == [sys.executable, "-m", "sqlmap"]


def test_binary_on_path_is_preferred(monkeypatch):
    """A real sqlmap console script on PATH wins over the package probe."""
    monkeypatch.setattr(
        injection.shutil, "which",
        lambda exe, *_a, **_k: "/usr/bin/sqlmap" if exe == "sqlmap" else None,
    )
    assert injection._sqlmap_cmd() == ["/usr/bin/sqlmap"]

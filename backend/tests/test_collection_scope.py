"""Regression guard: pytest collection is pinned to tests/, and no application
module is ever collected as a test.

History: ``app/scanners/waf_test.py`` is a *production* scanner module whose name
matches pytest's default ``*_test.py`` discovery pattern. If pytest is allowed to
recurse application code during collection, it imports that module OUTSIDE the
tests/ tree — where ``tests/conftest.py`` has not established the test security
env (JWT_SECRET, DATABASE_URL) — which trips ``app.config``'s fail-closed boot
guard and aborts collection (pytest exit code 2). This was observed when running
a bare ``pytest`` from the repository root.

``backend/pytest.ini`` prevents this at two levels, and these tests lock both in:

* ``testpaths = tests`` — a bare ``pytest`` (exactly how CI runs it from backend/)
  collects only the tests/ tree, so application code is never even visited.
* ``python_files = test_*.py`` — the ``*_test.py`` suffix is NOT a test pattern
  here, so a production module named like ``waf_test.py`` can never be collected
  as a test even if pytest is pointed directly at app/ code.

If either guard is weakened, the corresponding test below fails.
"""

import subprocess
import sys
from fnmatch import fnmatch
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]


def test_testpaths_pins_collection_to_tests_dir(pytestconfig):
    """Bare collection must be restricted to the tests/ directory."""
    assert pytestconfig.getini("testpaths") == ["tests"], (
        "pytest.ini must pin `testpaths = tests` so a bare `pytest` never recurses "
        "application code during collection."
    )


def test_star_test_suffix_is_not_a_collection_pattern(pytestconfig):
    """`*_test.py` must not be a test-file pattern (production modules use it)."""
    patterns = pytestconfig.getini("python_files")
    assert "test_*.py" in patterns, patterns
    assert "*_test.py" not in patterns, (
        "`*_test.py` must be dropped from python_files so production modules named "
        f"that way are never collected as tests; got {patterns}."
    )


def test_no_application_module_matches_a_test_pattern(pytestconfig):
    """No file under app/ may match the active test-file patterns.

    Dynamic + future-proof: scans the whole application package, so re-introducing
    a `*_test.py` collection pattern (which would make app/scanners/waf_test.py
    collectable again) is caught immediately, as is any newly added app module
    that happens to be named like a test.
    """
    patterns = pytestconfig.getini("python_files")
    app_dir = BACKEND / "app"
    offenders = sorted(
        str(p.relative_to(BACKEND)).replace("\\", "/")
        for p in app_dir.rglob("*.py")
        if any(fnmatch(p.name, pat) for pat in patterns)
    )
    assert offenders == [], (
        "application modules match a python_files test pattern and could be "
        f"collected as tests: {offenders}"
    )


def test_bare_pytest_collection_is_restricted_to_tests(tmp_path):
    """End-to-end: a bare `pytest --collect-only` from backend/ (CI's invocation)
    succeeds and collects only tests/ node ids — never app/ scanner modules."""
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q"],
        cwd=str(BACKEND),
        capture_output=True,
        text=True,
    )
    combined = (proc.stdout + proc.stderr).replace("\\", "/")
    assert proc.returncode == 0, f"bare collection failed (exit {proc.returncode}):\n{combined}"
    # No application scanner module surfaced in the collection.
    assert "app/scanners" not in combined, combined
    assert "waf_test" not in combined, combined
    # Every collected node id is under tests/.
    node_ids = [ln.strip() for ln in proc.stdout.splitlines() if "::" in ln]
    assert node_ids, f"expected collected tests, got none:\n{combined}"
    stray = [n for n in node_ids if not n.replace("\\", "/").startswith("tests/")]
    assert stray == [], f"collected node ids outside tests/: {stray}"

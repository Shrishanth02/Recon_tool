"""Regression guard for the CI Ruff lint policy.

The backend CI job runs ``ruff check .`` BEFORE pytest — if that step is red the
tests never run. Two things must stay true so the gate is meaningful and can't
silently regress:

1. The enforced rule set is EXPLICIT in ruff.toml. It used to be implicit (no
   ``select``), so a Ruff version bump silently widened the default to hundreds of
   style rules and reddened CI. Pinning ``select`` makes the policy version-stable.
2. The tree stays clean under that policy (so the backend job reaches pytest).
"""

import subprocess
import sys
from pathlib import Path

import pytest

try:  # tomllib is stdlib on the py311 target (and the local runner)
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    tomllib = None

BACKEND = Path(__file__).resolve().parents[1]


def _ruff_available() -> bool:
    try:
        return (
            subprocess.run(
                [sys.executable, "-m", "ruff", "--version"],
                capture_output=True,
            ).returncode
            == 0
        )
    except OSError:  # pragma: no cover
        return False


def test_ruff_config_pins_an_explicit_select():
    assert tomllib is not None, "tomllib unavailable (need py311+)"
    cfg = tomllib.loads((BACKEND / "ruff.toml").read_text(encoding="utf-8"))
    select = cfg.get("lint", {}).get("select")
    # Must be explicit so a Ruff upgrade can't silently change the enforced set.
    assert select, "ruff.toml must pin an explicit [lint] select"
    # The intended baseline: pyflakes (real bugs) + pycodestyle error classes.
    assert "F" in select and "E9" in select, f"unexpected select: {select}"


def test_ruff_check_is_clean():
    """The exact CI lint command must pass, so the backend job reaches pytest."""
    if not _ruff_available():  # pragma: no cover
        pytest.skip("ruff not installed in this environment")
    proc = subprocess.run(
        [sys.executable, "-m", "ruff", "check", "."],
        cwd=str(BACKEND),
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, (
        "`ruff check .` is not clean — the backend CI job would fail before "
        f"pytest:\n{proc.stdout}\n{proc.stderr}"
    )

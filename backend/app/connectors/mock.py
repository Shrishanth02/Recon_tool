"""The mock detection connector (Purple-Team P3).

:class:`MockConnector` is a fully deterministic, dependency-free stand-in for a
real SIEM. It exists so the purple-team correlation flow can be demoed and
tested end-to-end without any external system: given the same config and the
same technique id it always returns the same detected/missed verdict.

Config
------
``{"coverage": 0..1, "detect_technique_ids": ["T1046", ...]}``

A technique is reported *detected* when **either**:

* its id appears in ``detect_technique_ids`` (an explicit allow-list), **or**
* ``hash(technique_id) % 100 < coverage * 100`` — a stable pseudo-random gate
  that models a SIEM with ``coverage`` fractional detection breadth.

Both inputs are optional: with no config the connector detects nothing
(``coverage`` defaults to ``0.0``, empty allow-list).
"""

from __future__ import annotations

import hashlib
from typing import Any

from .base import Connector


class MockConnector(Connector):
    """A deterministic, offline SIEM stand-in for demos and tests."""

    ctype = "mock"

    def _coverage(self) -> float:
        """Return the configured coverage clamped to the ``[0.0, 1.0]`` range."""
        try:
            cov = float(self.config.get("coverage", 0.0) or 0.0)
        except (TypeError, ValueError):
            return 0.0
        return max(0.0, min(1.0, cov))

    def _detect_ids(self) -> set[str]:
        """Return the explicit detect allow-list as a set of stripped ids."""
        raw = self.config.get("detect_technique_ids") or []
        if isinstance(raw, str):  # tolerate a single id passed as a bare string
            raw = [raw]
        return {str(t).strip() for t in raw if str(t).strip()}

    @staticmethod
    def _stable_bucket(technique_id: str) -> int:
        """Map a technique id to a stable ``0..99`` bucket.

        Python's builtin :func:`hash` is salted per-process, so it cannot back a
        *deterministic* verdict across runs. We use a SHA-256 digest instead so
        the same id always lands in the same bucket everywhere.
        """
        digest = hashlib.sha256((technique_id or "").encode("utf-8")).hexdigest()
        return int(digest[:8], 16) % 100

    def query_detections(
        self,
        technique_id: str,
        marker: str,
        since_iso: str,
        target: str,
    ) -> dict[str, Any]:
        """Deterministically decide whether ``technique_id`` is "detected"."""
        tid = str(technique_id or "").strip()
        coverage = self._coverage()
        allow = self._detect_ids()

        if tid in allow:
            return self._result(
                True,
                count=1,
                evidence=f"mock: {tid} in detect_technique_ids allow-list",
            )

        bucket = self._stable_bucket(tid)
        if bucket < coverage * 100:
            return self._result(
                True,
                count=1,
                evidence=(
                    f"mock: {tid} within simulated coverage "
                    f"(bucket {bucket} < {int(coverage * 100)})"
                ),
            )
        return self._result(
            False,
            count=0,
            evidence=(
                f"mock: {tid} not detected "
                f"(bucket {bucket} >= {int(coverage * 100)})"
            ),
        )

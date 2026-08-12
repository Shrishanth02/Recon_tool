"""Workspace risk scoring — pure, stdlib-only logic (Phase 4).

Turns a flat list of finding dicts into a single 0–100 risk score and a
human-readable rating. This is deliberately dependency-free so it can be called
from routers, the scheduler worker, tests, or the report layer without any
database or network access.

The scoring is a simple weighted count of findings by severity, capped at 100::

    critical = 40   high = 18   medium = 7   low = 2   info = 0

so a single critical finding already puts a workspace in the "Medium" band and
two criticals reach "High". Weights favour breadth-insensitive escalation: many
low findings never outrank a genuine critical.
"""

from typing import Any

# Points contributed by a single finding of each severity.
SEVERITY_WEIGHTS: dict[str, int] = {
    "critical": 40,
    "high": 18,
    "medium": 7,
    "low": 2,
    "info": 0,
}

# Canonical severity buckets, worst first.
_SEVERITIES = ("critical", "high", "medium", "low", "info")


def finding_severity(f: Any) -> str:
    """Return a finding's normalized severity, tolerant of missing keys.

    Accepts a mapping (``dict``) or any object exposing a ``severity``
    attribute. Unknown, empty, or non-string values collapse to ``"info"`` so
    callers never have to pre-clean their data.
    """
    if isinstance(f, dict):
        value = f.get("severity")
    else:
        value = getattr(f, "severity", None)
    sev = str(value or "info").strip().lower()
    return sev if sev in SEVERITY_WEIGHTS else "info"


def workspace_risk(findings: list[dict]) -> dict:
    """Compute a workspace risk score from a list of findings.

    Args:
        findings: An iterable of finding dicts (or objects with a ``severity``
            attribute). Missing/unknown severities are treated as ``"info"``.

    Returns:
        A dict ``{"score": int, "rating": str, "counts": {sev: n}, "total": int}``
        where ``score`` is ``min(100, sum(weight * count))`` and ``rating`` is
        one of ``Critical`` (>=75), ``High`` (>=50), ``Medium`` (>=25),
        ``Low`` (>0), or ``Informational`` (0).
    """
    counts: dict[str, int] = {sev: 0 for sev in _SEVERITIES}
    for f in findings or []:
        counts[finding_severity(f)] += 1

    raw = sum(SEVERITY_WEIGHTS[sev] * n for sev, n in counts.items())
    score = min(100, raw)

    if score >= 75:
        rating = "Critical"
    elif score >= 50:
        rating = "High"
    elif score >= 25:
        rating = "Medium"
    elif score > 0:
        rating = "Low"
    else:
        rating = "Informational"

    return {
        "score": score,
        "rating": rating,
        "counts": counts,
        "total": sum(counts.values()),
    }

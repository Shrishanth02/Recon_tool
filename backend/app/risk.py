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

from .severity import normalize_severity

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
    # Single, shared normalization strategy (see app.severity) so risk scoring,
    # the schema, the write path, the report and triage all agree on what an
    # out-of-vocabulary severity becomes.
    return normalize_severity(value)


def finding_kind(f: Any) -> str:
    """Return a finding's ``kind`` (vuln | hardening | recon | info).

    Tolerant of dicts, ORM objects, and legacy rows: anything without a ``kind``
    is treated as ``"vuln"`` so pre-P0 findings keep their original weight.
    """
    if isinstance(f, dict):
        value = f.get("kind")
    else:
        value = getattr(f, "kind", None)
    return str(value).strip().lower() if value else "vuln"


def finding_confidence(f: Any) -> int:
    """Return a finding's 0-100 confidence.

    Missing/invalid confidence collapses to ``100`` so legacy findings (which
    have no confidence) keep full weight and the pre-P0 score is preserved.
    """
    if isinstance(f, dict):
        value = f.get("confidence")
    else:
        value = getattr(f, "confidence", None)
    if value is None:
        return 100
    try:
        c = int(value)
    except (TypeError, ValueError):
        return 100
    return max(0, min(100, c))


def workspace_risk(findings: list[dict]) -> dict:
    """Compute a workspace risk score from a list of findings.

    This is THE single risk calculation used by both the ``/risk`` endpoint and
    the Auto-Pentest pipeline (there is no longer a second, conflicting scorer).

    Args:
        findings: An iterable of finding dicts (or ORM objects). Missing/unknown
            severities are treated as ``"info"``; missing ``kind`` as ``"vuln"``;
            missing ``confidence`` as ``100``.

    Scoring:
        Only findings with ``kind == "vuln"`` contribute to the score; recon /
        informational / hardening signal is tallied in ``counts`` but never
        inflates risk. Each contributing finding is weighted by its severity AND
        its confidence (``weight * confidence / 100``), so a low-confidence
        SIGNAL counts for less than a high-confidence VALIDATED finding of the
        same severity.

    Returns:
        ``{"score": int, "rating": str, "counts": {sev: n}, "total": int}`` where
        ``rating`` is ``Critical`` (>=75), ``High`` (>=50), ``Medium`` (>=25),
        ``Low`` (>0), or ``Informational`` (0).
    """
    counts: dict[str, int] = {sev: 0 for sev in _SEVERITIES}
    raw = 0
    for f in findings or []:
        sev = finding_severity(f)
        counts[sev] += 1
        if finding_kind(f) != "vuln":
            continue
        raw += int(round(SEVERITY_WEIGHTS[sev] * finding_confidence(f) / 100))
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

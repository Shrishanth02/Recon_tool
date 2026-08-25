"""Canonical severity vocabulary and the single severity-normalization strategy.

Every surface that reads a finding's severity — the write path
(:func:`app.crud.save_scan`), the API schema (:class:`app.schemas.FindingOut`),
risk scoring (:mod:`app.risk`), the report and AI triage — funnels its input
through :func:`normalize_severity`. That guarantees a malformed scanner value
(``"unknown"``, ``""``, ``None``, ``"CRITICAL"``, garbage) can never reach a
strict consumer and 500 an entire workspace's findings/risk/report/triage.

Design rules:

* The five canonical severities are the single source of truth.
* Recognized values (in ANY case) are preserved exactly (lowercased) — a
  ``"Critical"`` is never weakened.
* A small, unambiguous synonym set is mapped (e.g. ``"informational" -> "info"``).
* Anything else is *not guessed*: it collapses to a conservative, visible
  fallback (``"info"`` — scored at 0 by risk, so it never inflates severity),
  and callers preserve the ORIGINAL value in evidence/metadata for auditability.
"""

import math
from typing import Any

#: The five supported severities, worst-first. Single source of truth.
SEVERITIES: tuple[str, ...] = ("critical", "high", "medium", "low", "info")
_SEVERITY_SET = frozenset(SEVERITIES)

#: Conservative fallback for an untrusted / unrecognized value. "info" is visible
#: but never risk-inflating; we never guess an unknown value UP toward critical.
FALLBACK_SEVERITY = "info"

#: Recognized non-canonical spellings whose meaning is unambiguous. Kept small on
#: purpose: only synonyms we are certain about. Anything not here and not
#: canonical falls back (with the raw value preserved by the caller) rather than
#: being guessed at.
_SEVERITY_ALIASES: dict[str, str] = {
    "informational": "info",
    "information": "info",
    "none": "info",
    "unknown": "info",
    "undefined": "info",
    "null": "info",
    "": "info",
}


def is_known_severity(value: Any) -> bool:
    """Return ``True`` iff ``value`` is one of the five canonical severities.

    Case-insensitive; aliases (``"informational"`` etc.) are deliberately NOT
    "known" here, so callers preserve their raw form in evidence.
    """
    if not isinstance(value, str):
        return False
    return value.strip().lower() in _SEVERITY_SET


def normalize_severity(value: Any, *, default: str = FALLBACK_SEVERITY) -> str:
    """Return a guaranteed-valid canonical severity for any input. Never raises.

    - A canonical value (any case) is returned lowercased, unchanged in meaning.
    - A recognized synonym is mapped to its canonical value.
    - Everything else (``None``, empty, ``"unknown"``, numbers, garbage) collapses
      to ``default`` (``"info"``). The caller is responsible for preserving the
      original value in evidence/metadata.
    """
    if value is None:
        return default
    token = str(value).strip().lower()
    if token in _SEVERITY_SET:
        return token
    if token in _SEVERITY_ALIASES:
        return _SEVERITY_ALIASES[token]
    return default


def coerce_cvss(value: Any) -> float | None:
    """Return a valid CVSS base score as a float, or ``None``. Never raises.

    The nuclei ``cvss-score`` (and the CVE-lookup path) are template/data
    controlled, so ``Finding.cvss`` — a nullable ``Float`` — can be handed a bare
    string (``"7.5"`` or ``"high"``), a bool, ``NaN``/``inf``, a list, or ``None``.
    Two failure modes follow if that reaches the column verbatim:

    * ``save_scan``'s dedup merge does ``max(existing.cvss, f["cvss"])`` — a
      ``str`` vs ``float`` raises ``TypeError`` mid-scan, losing the whole scan;
    * a non-numeric value that persisted (SQLite is permissive) then fails the
      strict ``float`` on :class:`app.schemas.FindingOut` and 500s the ENTIRE
      findings/report/risk/triage surface — the same blast radius the severity
      guard closed.

    So: a finite number (or a numeric string) in the valid CVSS range 0-10 is
    returned as a float unchanged; everything else — ``None``, bools, non-numeric
    or out-of-range values, ``NaN``/``inf`` — collapses to ``None`` (unscored),
    never a guess. Booleans are rejected (a score of ``True`` is nonsense) even
    though ``bool`` is an ``int`` subclass.
    """
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        num = float(value)
    elif isinstance(value, str):
        try:
            num = float(value.strip())
        except (TypeError, ValueError):
            return None
    else:
        return None
    if not math.isfinite(num) or not (0.0 <= num <= 10.0):
        return None
    return num

"""Finding diffing — pure, stdlib-only logic (Phase 4).

Compares two point-in-time snapshots of findings (e.g. the two most recent
scans of the same target) and classifies each finding as *new*, *resolved*, or
*unchanged*. Identity is a coarse ``(severity, name, location)`` key rather than
a database id, so it survives re-scans that mint fresh finding rows.

Like :mod:`app.risk`, this module has no database or network dependencies and is
safe to import anywhere.
"""

from typing import Any


def finding_key(f: Any) -> tuple[str, str, str]:
    """Return the stable identity key ``(severity, name, location)`` for ``f``.

    All three components are lower-cased and whitespace-stripped so trivially
    different renderings of the same finding collapse together. Accepts a
    mapping or any object exposing the matching attributes; missing values
    become empty strings.
    """
    def _get(key: str) -> str:
        if isinstance(f, dict):
            value = f.get(key)
        else:
            value = getattr(f, key, None)
        return str(value or "").strip().lower()

    return (_get("severity"), _get("name"), _get("location"))


def diff_findings(previous: list[dict], current: list[dict]) -> dict:
    """Diff two finding snapshots by identity key.

    Args:
        previous: The older snapshot (e.g. the prior scan's findings).
        current: The newer snapshot (e.g. the latest scan's findings).

    Returns:
        A dict with four keys:

        * ``new`` — findings present in ``current`` but not ``previous``.
        * ``resolved`` — findings present in ``previous`` but not ``current``.
        * ``unchanged`` — findings present in both (the ``current`` copy is kept).
        * ``counts`` — ``{"new": n, "resolved": n, "unchanged": n}``.

        Findings are compared by :func:`finding_key`; the returned lists hold the
        original finding objects (not the keys).
    """
    prev_list = list(previous or [])
    cur_list = list(current or [])
    prev_keys = {finding_key(f) for f in prev_list}
    cur_keys = {finding_key(f) for f in cur_list}

    new = [f for f in cur_list if finding_key(f) not in prev_keys]
    unchanged = [f for f in cur_list if finding_key(f) in prev_keys]
    resolved = [f for f in prev_list if finding_key(f) not in cur_keys]

    return {
        "new": new,
        "resolved": resolved,
        "unchanged": unchanged,
        "counts": {
            "new": len(new),
            "resolved": len(resolved),
            "unchanged": len(unchanged),
        },
    }

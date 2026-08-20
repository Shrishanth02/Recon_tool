"""SAFE ATT&CK emulation engine (Purple-Team P2).

This package runs the non-destructive, ATT&CK-mapped technique tests defined in
:mod:`app.emulation.techniques` against an *already-authorized* target (the
router enforces scope + SSRF/netguard + billing before calling in here) and
rolls their per-technique results up into a single run summary.

Public surface:

* :data:`TECHNIQUES` — the registry of safe technique tests (re-exported).
* :func:`run_emulation` — execute some/all techniques against one target.

Nothing in here talks to the database; persistence is the router's job. The
engine only performs benign HTTP/TCP probes and shapes the results.
"""

from __future__ import annotations

from typing import Any, Callable, Iterable

from .techniques import (
    TECHNIQUES,
    TECHNIQUES_BY_ID,
    host_from_base_url,
    normalize_base_url,
)

__all__ = ["TECHNIQUES", "run_emulation", "normalize_base_url"]


def _select_techniques(
    technique_ids: Iterable[str] | None,
) -> list[dict[str, Any]]:
    """Return the technique entries to run, preserving registry order.

    ``technique_ids`` is a list of emulation ids (``"E1"`` ...). ``None`` selects
    every technique. Unknown ids are silently ignored so a stale client id can
    never abort a run.
    """
    if technique_ids is None:
        return list(TECHNIQUES)
    wanted = {str(t).strip() for t in technique_ids if str(t).strip()}
    return [t for t in TECHNIQUES if t["id"] in wanted]


def run_emulation(
    target: str,
    technique_ids: list[str] | None = None,
    cancel: Callable[[], bool] | None = None,
) -> dict[str, Any]:
    """Run the selected SAFE emulation techniques against ``target``.

    Parameters
    ----------
    target:
        The authorized target host/URL. It is normalized to a
        ``scheme://host[:port]`` base URL internally; each technique controls its
        own request path.
    technique_ids:
        Emulation ids to run (``["E1", "E4"]``). ``None`` runs the whole
        registry.
    cancel:
        Optional zero-arg predicate polled before each technique; when it returns
        truthy the remaining techniques are recorded as ``"skipped"`` and the run
        stops early (used to honor a client disconnect / cancel).

    Returns
    -------
    dict
        ``{"target", "results": [...], "executed": int, "blocked": int,
        "failed": int}`` where each result is
        ``{"id","technique_id","name","tactic","status","evidence","detail"}``.
        (``"skipped"`` results are present in ``results`` but not counted in the
        three tallies.)
    """
    base_url = normalize_base_url(target)
    host = host_from_base_url(base_url)
    ctx: dict[str, Any] = {"target": target, "base_url": base_url, "host": host}

    selected = _select_techniques(technique_ids)
    results: list[dict[str, Any]] = []
    executed = blocked = failed = 0

    for tech in selected:
        if cancel is not None and cancel():
            outcome = {"status": "skipped", "evidence": "", "detail": "run canceled"}
        elif not base_url:
            outcome = {
                "status": "failed",
                "evidence": "",
                "detail": "could not normalize target to a base URL",
            }
        else:
            try:
                outcome = tech["run"](base_url, ctx)
            except Exception as exc:  # defensive: a technique must never abort the run
                outcome = {
                    "status": "failed",
                    "evidence": "",
                    "detail": f"technique raised: {exc}",
                }

        status = outcome.get("status", "failed")
        if status == "executed":
            executed += 1
        elif status == "blocked":
            blocked += 1
        elif status == "failed":
            failed += 1

        results.append(
            {
                "id": tech["id"],
                "technique_id": tech["technique_id"],
                "name": tech["name"],
                "tactic": tech["tactic"],
                "status": status,
                "evidence": outcome.get("evidence", ""),
                "detail": outcome.get("detail", ""),
            }
        )

    return {
        "target": target,
        "results": results,
        "executed": executed,
        "blocked": blocked,
        "failed": failed,
    }

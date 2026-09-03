"""Vulnerability scanning via nuclei — templated CVE / misconfig / exposure detection.

Streams each finding the moment nuclei reports it and accumulates a structured,
severity-ranked result set. This is detection-only (the industry-standard
approach); it does not exploit anything.
"""

import json
import re
import threading
from typing import Iterator, Optional

from .base import error, log, reachable, result, stream_command

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}

_SPLIT = re.compile(r"[\s,]+")


def _targets(raw: str):
    from .base import reject_optionlike

    out = []
    for t in _SPLIT.split(raw or ""):
        t = t.strip()
        if not t:
            continue
        host = t.split("://", 1)[-1].split("/")[0]
        reject_optionlike(host)  # refuse option-like targets (arg-injection guard)
        out.append(t)
    return out


def stream(
    target: str,
    severity: str = "low,medium,high,critical",
    cancel: Optional[threading.Event] = None,
    **_,
) -> Iterator[dict]:
    targets = _targets(target)
    if not targets:
        yield error("At least one target is required.")
        return

    # Pre-flight: skip hosts that don't answer at all. Without this, a dead or
    # firewalled target makes nuclei time out on every one of ~18k templates,
    # crawling at a few requests/second for hours and finding nothing.
    yield log("Checking target reachability ...")
    live, dead = [], []
    for t in targets:
        if cancel is not None and cancel.is_set():
            return
        (live if reachable(t) else dead).append(t)
    for d in dead:
        yield log(f"⚠ {d} did not respond (host down or blocking) — skipping.")
    if not live:
        yield error(
            "No target responded — the host(s) appear to be down or blocking "
            "connections, so there is nothing to scan."
        )
        return
    targets = live

    yield log(f"Running nuclei against {len(targets)} target(s) [severity: {severity}]")
    yield log("Loading templates and scanning — live progress streams below.")

    findings = []
    # Performance + live-feedback flags:
    #   -c / -rate-limit / -timeout  → run the ~10k templates much faster
    #                                  (typically ~30-60s instead of several minutes)
    #   -stats -stats-json -stats-interval → emit a JSON progress line every few
    #                                  seconds so the live terminal never looks frozen
    cmd = [
        "nuclei", "-jsonl", "-no-color",
        "-stats", "-stats-json", "-stats-interval", "5",
        # Parallelize template execution (safe: doesn't change per-request
        # behaviour, so it speeds the scan up without dropping detections).
        # Rate stays moderate to avoid tripping target rate-limits, and the
        # per-request timeout is left at nuclei's default so slow endpoints
        # aren't missed.
        "-c", "50",
        "-rate-limit", "300",
        "-retries", "1",
        "-max-host-error", "50",
    ]
    if severity and severity != "all":
        cmd += ["-severity", severity]
    for t in targets:
        cmd += ["-u", t]

    # stderr carries the progress stats, so merge it in and tell findings apart
    # from progress by shape (a finding has info/template-id; a stat has percent).
    rc = None
    for ev in stream_command(cmd, cancel=cancel, merge_stderr=True):
        if ev["type"] == "returncode":
            rc = ev.get("data")  # capture (do NOT discard) — see honesty note below
            continue
        if ev["type"] != "log":
            yield ev
            continue
        line = ev["data"]
        if line.startswith("$ "):
            yield ev
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            # Non-JSON: keep concise [INF]/[WRN] notes, drop the ASCII banner.
            s = line.strip()
            if s.startswith("[INF]") or s.startswith("[WRN]"):
                yield log(s)
            continue

        # A progress/stats line (from -stats-json) — surface it, don't count it.
        if "percent" in obj or ("requests" in obj and "total" in obj):
            yield log(
                f"⏳ {obj.get('percent', '?')}% · {obj.get('requests', 0)} requests"
                f" · {obj.get('matched', 0)} matched · {obj.get('rps', 0)} req/s"
            )
            continue

        # Otherwise it is a finding.
        info = obj.get("info", {})
        classification = info.get("classification") or {}
        finding = {
            "template_id": obj.get("template-id", ""),
            "name": info.get("name", obj.get("template-id", "")),
            "severity": (info.get("severity") or "unknown").lower(),
            "type": obj.get("type", ""),
            "matched_at": obj.get("matched-at", obj.get("host", "")),
            "tags": info.get("tags", []),
            "description": info.get("description", ""),
            "reference": info.get("reference", []),
            "cve": (classification.get("cve-id") or []),
            "cwe": (classification.get("cwe-id") or []),
            "cvss": classification.get("cvss-score"),
            "extracted": obj.get("extracted-results", []),
            # nuclei includes the raw request/response by default; keep a bounded
            # copy as real evidence for the matched detection (truncated so a
            # single large finding can't bloat the scan blob / DB).
            "request": (obj.get("request") or "")[:4000] or None,
            "response": (obj.get("response") or "")[:4000] or None,
        }
        findings.append(finding)
        yield log(
            f"[{finding['severity'].upper()}] {finding['name']} -> {finding['matched_at']}"
        )

    # Honesty on cancel / timeout / crash / missing-binary: nuclei can match a
    # template late in a long run, so a run that did not FINISH is not proof the
    # target is clean. base.stream_command SIGKILLs nuclei on a user cancel AND on
    # a wall-clock timeout, reporting the non-zero exit status via the returncode
    # event; a template-load error / panic also exits non-zero, and a missing
    # binary yields rc 127 (plus an error event already forwarded above). Deriving
    # `partial` from cancel ALONE (the old bug) let a timed-out or crashed run —
    # whose returncode was discarded — report complete:true / "0 findings", a
    # false-clean. Treat a non-zero exit as incomplete too (mirrors the sqlmap/
    # dalfox rc-based honesty in injection.py). A clean finish is rc 0.
    cancelled = cancel is not None and cancel.is_set()
    errored = rc is not None and rc != 0
    partial = cancelled or errored

    findings.sort(key=lambda f: SEVERITY_ORDER.get(f["severity"], 9))
    counts = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    if partial:
        reason = "cancelled/stopped" if cancelled else f"exited abnormally (code {rc})"
        yield log(
            f"⚠ nuclei did not complete ({reason}) — results are "
            f"PARTIAL: {len(findings)} finding(s) captured so far, more may exist. "
            f"This is NOT a clean result."
        )
    else:
        yield log(f"✔ {len(findings)} finding(s): "
                  + (", ".join(f"{k}:{v}" for k, v in counts.items()) or "none"))
    yield result({
        "targets": targets,
        "total": len(findings),
        "counts": counts,
        "findings": findings,
        "complete": not partial,
    })

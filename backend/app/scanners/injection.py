"""Active injection testing — SQL injection (sqlmap) + XSS (dalfox).

This is the "deep vuln scan" tier that catches what nuclei's template engine
misses: real, *confirmed* injection flaws found by actively fuzzing request
parameters. It orchestrates two best-in-class external tools and normalises
their very different output into one unified finding list:

    * SQL injection  → sqlmap   (Python pkg or standalone binary on PATH)
    * Reflected/DOM XSS → dalfox (Go binary on PATH)

Design goals mirror the other scanners in this package:

* **Generator contract** — ``stream()`` yields ``log`` / ``result`` / ``error``
  event dicts (see :mod:`app.scanners.base`) so the WebSocket layer forwards
  live progress the instant a line is produced.
* **Graceful degradation** — the module *imports* cleanly with neither tool
  installed, and ``stream()`` runs to completion, logging a clear "skipping"
  note and returning a valid (possibly empty) ``result`` instead of crashing.
* **Safe by construction** — targets are sanitised through ``ensure_url`` +
  ``reject_optionlike`` (argument-injection guard), commands are argv lists
  (never ``shell=True``), every run is time-bounded, and *only* read-only,
  non-destructive tool flags are ever used. sqlmap's ``--dump`` / ``--os-*`` /
  ``--file-*`` and any other data-exfil / RCE flags are never enabled.

The ``result`` payload shape::

    {
        "target": str,
        "sqli": [ {param, place, dbms, url, title}, ... ],
        "xss":  [ {type, param, url, evidence, poc}, ... ],
        "findings": [ {severity, name, location, description, cwe, tool}, ... ],
        "counts": {"sqli": int, "xss": int, "critical": int, "high": int,
                   "medium": int, "low": int, "total": int},
        "tools": {"sqlmap": bool, "dalfox": bool},   # whether each ran
    }
"""

import json
import re
import shutil
import threading
from typing import Iterator, List, Optional

from .base import error, ensure_url, log, reject_optionlike, result, stream_command

# ---------------------------------------------------------------------------
# Tuning knobs
# ---------------------------------------------------------------------------
# These tools are slow (they fuzz many payloads per parameter). Each is capped
# with its own wall-clock ceiling; the two ceilings together stay under the
# ~180s total budget requested for this module so a scan never runs away.
_SQLMAP_MAX_SECONDS = 120
_DALFOX_MAX_SECONDS = 90
# Per-request network timeout handed to the tools themselves.
_REQUEST_TIMEOUT = 15

# Cap how many raw findings we retain, to keep WebSocket payloads bounded.
_MAX_FINDINGS = 200


# ---------------------------------------------------------------------------
# Tool discovery
# ---------------------------------------------------------------------------
def _sqlmap_cmd() -> Optional[List[str]]:
    """Return the argv prefix that launches sqlmap, or None if unavailable.

    sqlmap ships in several shapes: a console script (``sqlmap``), a standalone
    ``sqlmap.py``, or an importable Python package runnable via
    ``python -m sqlmap``. We probe them in that order and return the first that
    exists so the rest of the module doesn't care how it was installed.
    """
    for exe in ("sqlmap", "sqlmap.py"):
        path = shutil.which(exe)
        if path:
            return [path]
    # Fall back to the importable package (`pip install sqlmap`).
    try:
        import importlib.util

        if importlib.util.find_spec("sqlmap") is not None:
            import sys

            return [sys.executable, "-m", "sqlmap"]
    except Exception:  # noqa: BLE001 — any import machinery hiccup ⇒ treat as absent
        pass
    return None


def _dalfox_cmd() -> Optional[List[str]]:
    """Return the argv prefix that launches dalfox, or None if unavailable."""
    path = shutil.which("dalfox")
    return [path] if path else None


# ---------------------------------------------------------------------------
# SQL injection (sqlmap)
# ---------------------------------------------------------------------------
# sqlmap announces a confirmed injection with lines like:
#   "Parameter: id (GET)"
#   "    Type: boolean-based blind"
#   "sqlmap identified the following injection point(s) ..."
#   "back-end DBMS: MySQL >= 5.0"
_RE_PARAM = re.compile(r"^\s*Parameter:\s*(?P<param>.+?)\s*\((?P<place>[A-Za-z]+)\)")
_RE_TYPE = re.compile(r"^\s*Type:\s*(?P<type>.+?)\s*$")
_RE_TITLE = re.compile(r"^\s*Title:\s*(?P<title>.+?)\s*$")
# The concrete confirmation sqlmap prints for each injection technique — the
# strongest piece of evidence a SQLi finding can carry. Captured (bounded) so the
# finding can show exactly what was sent; the scan itself is still read-only
# (--risk=1, no --dump/--os-*).
_RE_PAYLOAD = re.compile(r"^\s*Payload:\s*(?P<payload>.+?)\s*$")
_RE_DBMS = re.compile(r"back-end DBMS:\s*(?P<dbms>.+?)\s*$", re.IGNORECASE)
_RE_INJECTABLE = re.compile(
    r"(is vulnerable|appears to be .* injectable|"
    r"identified the following injection point)",
    re.IGNORECASE,
)


def _run_sqlmap(
    sqlmap: List[str], url: str, cancel: Optional[threading.Event],
    data: Optional[str] = None, ctype: Optional[str] = None,
    method: Optional[str] = None,
) -> Iterator[dict]:
    """Run sqlmap read-only against *url*, yielding log events and one internal
    ``{"type": "_sqli", "data": [...]}`` event carrying parsed findings.

    Bounded, non-interactive (``--batch``), and strictly detection-only — no
    ``--dump``/``--os-shell``/``--file-write`` ever. ``--crawl=0`` keeps it to
    the single supplied URL. When ``data`` is given the request becomes a body
    request (POST by default; ``method`` overrides for PUT/PATCH) so POST/JSON/
    form parameters are tested too; ``--risk=1`` still excludes data-modifying
    payloads.
    """
    cmd = sqlmap + [
        "-u", url,
        "--batch",             # never prompt — fully non-interactive
        "--level=2",
        "--risk=1",
        "--smart",             # only probe params that look promising
        "--crawl=0",           # do NOT spider; test just this URL
        f"--timeout={_REQUEST_TIMEOUT}",
        "--retries=1",
        "--disable-coloring",  # clean, parseable output
        "--flush-session",     # don't reuse stale state between runs
    ]
    if data:
        cmd += ["--data", data]
    if ctype:
        cmd += ["-H", f"Content-Type: {ctype}"]
    if method and method.upper() not in ("GET", "POST"):
        cmd += ["--method", method.upper()]

    findings: list[dict] = []
    current_param: Optional[dict] = None
    dbms: Optional[str] = None
    saw_injection = False

    def _flush():
        if current_param is not None:
            findings.append(current_param)

    for ev in stream_command(cmd, cancel=cancel, max_seconds=_SQLMAP_MAX_SECONDS):
        if ev["type"] == "returncode":
            continue
        if ev["type"] != "log":
            yield ev
            continue
        line = ev["data"]
        # Echo the command line and a filtered view of sqlmap's chatter.
        if line.startswith("$ "):
            yield log(line)
            continue

        m = _RE_DBMS.search(line)
        if m:
            dbms = m.group("dbms").strip()

        m = _RE_PARAM.match(line)
        if m:
            _flush()
            current_param = {
                "param": m.group("param").strip(),
                "place": m.group("place").strip(),
                "types": [],
                "payloads": [],
                "dbms": dbms,
                "url": url,
            }
            saw_injection = True
            yield log(f"🚨 [SQLi] injectable parameter: {m.group('param')} ({m.group('place')})")
            continue

        m = _RE_TYPE.match(line)
        if m and current_param is not None:
            current_param["types"].append(m.group("type").strip())
            continue

        m = _RE_PAYLOAD.match(line)
        if m and current_param is not None:
            # Keep a bounded list of the confirmed payloads as evidence.
            payload = m.group("payload").strip()[:300]
            if payload and payload not in current_param["payloads"]:
                current_param["payloads"].append(payload)
            continue

        if _RE_INJECTABLE.search(line):
            saw_injection = True

        # Surface concise sqlmap status notes; drop the ASCII banner / legalese.
        s = line.strip()
        if s.startswith("[") and ("INFO" in s or "WARNING" in s or "CRITICAL" in s or "ERROR" in s):
            yield log(s)

    _flush()
    # Backfill dbms discovered after the parameter block.
    for f in findings:
        if not f.get("dbms"):
            f["dbms"] = dbms
        f["title"] = "SQL injection in parameter '%s' (%s)" % (f["param"], f["place"])

    if not findings and not saw_injection:
        yield log("✔ sqlmap: no SQL injection confirmed on this URL.")
    yield {"type": "_sqli", "data": findings}


# ---------------------------------------------------------------------------
# XSS (dalfox)
# ---------------------------------------------------------------------------
def _run_dalfox(
    dalfox: List[str], url: str, cancel: Optional[threading.Event],
    data: Optional[str] = None,
) -> Iterator[dict]:
    """Run dalfox against *url*, yielding log events and one internal
    ``{"type": "_xss", "data": [...]}`` event with parsed findings.

    Uses ``--format json`` so each confirmed vuln is a machine-readable object.
    ``--skip-bav`` skips basic-auth/other-vuln probing to stay focused on XSS.
    When ``data`` is given the request body is tested (POST/form parameters).
    """
    cmd = dalfox + [
        "url", url,
        "--silence",       # suppress the noisy banner/spinner
        "--no-color",
        "--skip-bav",      # focus strictly on XSS
        "--format", "json",
        f"--timeout={_REQUEST_TIMEOUT}",
    ]
    if data:
        cmd += ["--data", data]

    findings: list[dict] = []

    def _ingest(obj: dict):
        # dalfox JSON POC objects carry: type, method, data(=url), param,
        # evidence, cwe, severity, message_str, etc. Field names have varied
        # across versions, so read defensively.
        entry = {
            "type": (obj.get("type") or obj.get("poc_type") or "XSS"),
            "param": obj.get("param", ""),
            "url": obj.get("data") or obj.get("url") or url,
            "evidence": obj.get("evidence") or obj.get("message_str") or "",
            "poc": obj.get("data") or obj.get("poc") or "",
            "cwe": obj.get("cwe", "CWE-79"),
            "severity": (obj.get("severity") or "").lower() or None,
        }
        findings.append(entry)
        yield log(f"🚨 [XSS] {entry['type']} on param '{entry['param']}' -> {entry['url']}")

    for ev in stream_command(cmd, cancel=cancel, max_seconds=_DALFOX_MAX_SECONDS):
        if ev["type"] == "returncode":
            continue
        if ev["type"] != "log":
            yield ev
            continue
        line = ev["data"]
        if line.startswith("$ "):
            yield log(line)
            continue

        s = line.strip()
        if not s:
            continue

        # dalfox --format json may emit either a single JSON array or one JSON
        # object per line ([POC] lines). Handle both.
        parsed = None
        if s.startswith("[") or s.startswith("{"):
            try:
                parsed = json.loads(s)
            except json.JSONDecodeError:
                parsed = None

        if isinstance(parsed, list):
            for obj in parsed:
                if isinstance(obj, dict):
                    yield from _ingest(obj)
            continue
        if isinstance(parsed, dict):
            yield from _ingest(parsed)
            continue

        # Non-JSON: dalfox's human "[POC]" grep lines are still useful evidence.
        if s.startswith("[POC]") or "[V]" in s or "triggered" in s.lower():
            findings.append({
                "type": "XSS",
                "param": "",
                "url": url,
                "evidence": s,
                "poc": s,
                "cwe": "CWE-79",
                "severity": None,
            })
            yield log(f"🚨 [XSS] {s}")

    if not findings:
        yield log("✔ dalfox: no XSS confirmed on this URL.")
    yield {"type": "_xss", "data": findings}


# ---------------------------------------------------------------------------
# Normalisation
# ---------------------------------------------------------------------------
def _normalise(sqli: List[dict], xss: List[dict]) -> List[dict]:
    """Fold both tools' raw findings into one unified, UI-friendly list."""
    out: list[dict] = []
    for f in sqli:
        types = ", ".join(f.get("types") or []) or "SQL injection"
        dbms = f.get("dbms")
        # Confirmed SQLi is high by default; stacked-query / out-of-band or a
        # known DBMS backing it bumps to critical (fuller compromise potential).
        sev = "high"
        blob = types.lower()
        if "stacked" in blob or "out-of-band" in blob or "os" in blob:
            sev = "critical"
        desc = "Confirmed SQL injection in parameter '%s' (%s) via %s." % (
            f.get("param", "?"), f.get("place", "?"), types,
        )
        if dbms:
            desc += " Back-end DBMS: %s." % dbms
        out.append({
            "severity": sev,
            "name": "SQL Injection: %s" % f.get("param", "?"),
            "location": f.get("url", ""),
            "description": desc,
            "cwe": "CWE-89",
            "tool": "sqlmap",
            # Structured confirmation evidence — the exact parameter, injection
            # techniques, back-end DBMS and the concrete payload(s) sqlmap used.
            "evidence": {
                k: v for k, v in {
                    "tool": "sqlmap",
                    "parameter": f.get("param"),
                    "place": f.get("place"),
                    "technique": f.get("types") or None,
                    "dbms": dbms,
                    "payloads": f.get("payloads") or None,
                    "url": f.get("url"),
                }.items() if v
            },
        })

    for f in xss:
        xtype = (f.get("type") or "XSS")
        # Reflected/DOM XSS is medium; a stored/verified-execution variant is high.
        sev = "medium"
        low = xtype.lower()
        if "stored" in low or "dom" in low or (f.get("severity") in ("high", "critical")):
            sev = "high"
        desc = "Confirmed %s" % xtype
        if f.get("param"):
            desc += " in parameter '%s'" % f["param"]
        desc += "."
        if f.get("evidence"):
            desc += " Evidence: %s" % str(f["evidence"])[:300]
        out.append({
            "severity": sev,
            "name": "Cross-Site Scripting: %s" % (f.get("param") or xtype),
            "location": f.get("url", ""),
            "description": desc,
            "cwe": f.get("cwe") or "CWE-79",
            "tool": "dalfox",
            # Structured confirmation evidence — the parameter, the XSS variant
            # and the dalfox proof-of-concept / reflected evidence.
            "evidence": {
                k: v for k, v in {
                    "tool": "dalfox",
                    "parameter": f.get("param"),
                    "type": xtype,
                    "poc": (str(f.get("poc"))[:300] if f.get("poc") else None),
                    "evidence": (str(f.get("evidence"))[:300] if f.get("evidence") else None),
                    "url": f.get("url"),
                }.items() if v
            },
        })
    return out[:_MAX_FINDINGS]


def _targets(raw: str) -> List[str]:
    """Split, sanitise and scheme-normalise one or more target URLs.

    Each target is run through ``ensure_url`` (guarantees an http(s) scheme and
    rejects option-like hosts via ``reject_optionlike``), the argument-injection
    guard shared by every scanner.
    """
    out: list[str] = []
    for t in re.split(r"[\s,]+", raw or ""):
        t = t.strip()
        if not t:
            continue
        reject_optionlike(t)      # refuse a whole token that is a bare '-flag'
        out.append(ensure_url(t))
    return out


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------
def stream(
    target: str,
    cancel: Optional[threading.Event] = None,
    **options,
) -> Iterator[dict]:
    """Actively test *target* URL(s) for SQL injection and XSS.

    Yields ``log`` progress events, forwards tool ``error`` events, and always
    ends with exactly one terminal ``result`` event — even when neither tool is
    installed (graceful degradation) or nothing is found.
    """
    try:
        targets = _targets(target)
    except ValueError as exc:
        yield error(str(exc))
        return
    if not targets:
        yield error("At least one target URL is required.")
        return

    sqlmap = _sqlmap_cmd()
    dalfox = _dalfox_cmd()

    if sqlmap is None:
        yield log("sqlmap not installed (skipping SQLi).")
    if dalfox is None:
        yield log("dalfox not installed (skipping XSS).")
    if sqlmap is None and dalfox is None:
        yield log(
            "Neither sqlmap nor dalfox is available — nothing to run. "
            "Install sqlmap (pip install sqlmap) and/or dalfox "
            "(go install github.com/hahwul/dalfox/v2@latest) to enable "
            "active injection testing."
        )

    yield log(
        "Active injection testing on %d target(s) "
        "[sqlmap=%s, dalfox=%s]" % (
            len(targets),
            "on" if sqlmap else "off",
            "on" if dalfox else "off",
        )
    )

    # Optional request-body testing: POST/PUT/PATCH with a form or JSON body so
    # authenticated forms and API endpoints are covered, not just GET query
    # params. Read-only sqlmap flags still apply (no data-modifying payloads).
    data = options.get("data") or None
    method = (options.get("method") or "").upper() or None
    content_type = options.get("content_type") or None
    if content_type in ("json", "application/json"):
        content_type = "application/json"
    elif content_type in ("form", "urlencoded"):
        content_type = "application/x-www-form-urlencoded"
    if data and (method in (None, "GET")):
        method = "POST"   # a body implies a body request
    if data:
        yield log(f"Body testing enabled ({method} {content_type or 'form'}).")

    all_sqli: list[dict] = []
    all_xss: list[dict] = []

    for url in targets:
        if cancel is not None and cancel.is_set():
            yield log("⏹ Cancelled.")
            break

        if sqlmap is not None:
            yield log(f"── SQLi scan (sqlmap): {url}")
            for ev in _run_sqlmap(sqlmap, url, cancel, data=data,
                                  ctype=content_type, method=method):
                if ev.get("type") == "_sqli":
                    all_sqli.extend(ev["data"])
                else:
                    yield ev

        if cancel is not None and cancel.is_set():
            yield log("⏹ Cancelled.")
            break

        if dalfox is not None:
            yield log(f"── XSS scan (dalfox): {url}")
            # dalfox --data is form-encoded; skip it for JSON bodies.
            dfdata = data if content_type != "application/json" else None
            for ev in _run_dalfox(dalfox, url, cancel, data=dfdata):
                if ev.get("type") == "_xss":
                    all_xss.extend(ev["data"])
                else:
                    yield ev

    findings = _normalise(all_sqli, all_xss)
    # Annotate every finding with the request method + body kind so the evidence
    # shows whether this was a GET, POST form, or JSON-body injection.
    for f in findings:
        ev = f.setdefault("evidence", {})
        ev.setdefault("http_method", method or "GET")
        if data:
            ev.setdefault("content_type", content_type or "application/x-www-form-urlencoded")
            ev.setdefault("body_tested", True)

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    counts["sqli"] = len(all_sqli)
    counts["xss"] = len(all_xss)
    counts["total"] = len(findings)

    summary = ", ".join(
        f"{k}:{counts[k]}" for k in ("critical", "high", "medium", "low") if counts[k]
    ) or "none"
    yield log(f"✔ Injection testing complete — {len(findings)} finding(s): {summary}")

    yield result({
        "target": targets[0] if len(targets) == 1 else targets,
        "sqli": all_sqli,
        "xss": all_xss,
        "findings": findings,
        "counts": counts,
        "tools": {"sqlmap": sqlmap is not None, "dalfox": dalfox is not None},
    })

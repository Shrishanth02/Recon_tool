"""Scanner-tool preflight — what external binaries the pipeline needs at runtime.

Classification:

* **REQUIRED** — the core auto-pentest stages always invoke these; their absence
  silently loses coverage, so they are reported loudly at startup and surfaced by
  ``GET /preflight``. They are installed in BOTH shipped images
  (``backend/Dockerfile`` for inline execution, ``Dockerfile.worker`` for queued).
* **OPTIONAL** — power stages that already degrade gracefully (they log
  ``"<tool> not installed (skipping ...)"``), so their absence never blocks
  startup and they are not installed by default.
* **DEVELOPMENT-only** — pytest / ruff etc.; not runtime scanners, not checked.

This module NEVER raises and NEVER blocks startup: a missing REQUIRED tool is a
loud, clearly-reported condition (so operators can't miss it), not a crash — an
inline dev box without the toolchain still boots, and OPTIONAL tools stay
optional.
"""

import logging
import shutil

logger = logging.getLogger("reconx.preflight")

#: REQUIRED external binaries -> the pipeline stage that invokes them.
REQUIRED_TOOLS: dict[str, str] = {
    "nmap": "port/service scan (stage 4)",
    "subfinder": "subdomain enumeration (stage 2)",
    "httpx": "HTTP probing (stage 3)",
    "nuclei": "templated vulnerability scan (stage 6)",
    "ffuf": "content discovery (stage 7)",
}

#: OPTIONAL external binaries -> stage. Absence is fine; the stage skips itself.
OPTIONAL_TOOLS: dict[str, str] = {
    "whois": "WHOIS lookup (stage 1)",
    "sqlmap": "SQL injection testing (stage 12)",
    "dalfox": "XSS testing (stage 12)",
    "katana": "deep crawl (stage 10)",
    "gau": "historical URL mining (stage 10)",
    "arjun": "hidden-parameter discovery (stage 10)",
}


def _present(tool: str) -> bool:
    return shutil.which(tool) is not None


def check_tools() -> dict:
    """Return runtime availability of every known scanner tool. Never raises.

    ``{"required": {tool: bool}, "optional": {tool: bool},
       "missing_required": [...], "missing_optional": [...], "ok": bool}`` where
    ``ok`` is True iff every REQUIRED tool is on PATH.
    """
    required = {t: _present(t) for t in REQUIRED_TOOLS}
    optional = {t: _present(t) for t in OPTIONAL_TOOLS}
    missing_required = sorted(t for t, ok in required.items() if not ok)
    missing_optional = sorted(t for t, ok in optional.items() if not ok)
    return {
        "required": required,
        "optional": optional,
        "missing_required": missing_required,
        "missing_optional": missing_optional,
        "ok": not missing_required,
    }


def log_startup_report() -> dict:
    """Emit a clear preflight summary at startup and return the status dict.

    Missing REQUIRED tools are logged at ERROR level (loud, never silent) but do
    NOT stop the process. Missing OPTIONAL tools are an INFO note.
    """
    status = check_tools()
    if status["missing_required"]:
        present = sorted(t for t, ok in status["required"].items() if ok)
        logger.error(
            "PREFLIGHT: missing REQUIRED scanner tools %s — the auto-pentest "
            "pipeline loses coverage for those stages. Install them (see "
            "backend/install-scanners.sh) or route scans to a worker image that "
            "has them. Present: %s",
            status["missing_required"],
            present or "none",
        )
    else:
        logger.info(
            "PREFLIGHT: all required scanner tools present (%s).",
            ", ".join(REQUIRED_TOOLS),
        )
    if status["missing_optional"]:
        logger.info(
            "PREFLIGHT: optional tools not installed (their stages skip "
            "gracefully): %s",
            status["missing_optional"],
        )
    return status

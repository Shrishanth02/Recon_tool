"""Claude-powered finding triage (Phase 4 — optional enhancement).

This module adds an AI layer on top of the deterministic scanners: given a set
of normalized findings it asks Claude to deduplicate them, flag likely false
positives, suggest remediation, and write an executive risk summary.

It is an *optional* enhancement and is engineered to never break the core
product:

* The ``anthropic`` SDK is **lazy-imported inside functions**, so
  ``import app.ai`` succeeds even when the package is not installed.
* When ``settings.ai_enabled`` is ``False`` (no API key) or the SDK is missing,
  the public entrypoints return a structured ``{"enabled": False, ...}`` dict
  and never raise.
* A model refusal is detected via ``stop_reason == "refusal"`` and returned
  gracefully rather than crashing.

Claude is called per the project's Claude API rules: the default model is
``claude-opus-4-8`` (configurable via ``settings.AI_MODEL``), structured output
is obtained with ``messages.parse`` (falling back to a ``json_schema`` config on
older SDKs), and adaptive thinking is enabled with a configurable effort.
"""

import json
from typing import Any

from pydantic import BaseModel, Field

from .config import settings
from .severity import normalize_severity

# System instruction shared by both the parse and json_schema code paths.
_SYSTEM_PROMPT = (
    "You are a meticulous senior application-security analyst. You are given "
    "raw findings from automated recon/vulnerability scanners. Your job is to: "
    "(1) deduplicate findings that describe the same underlying issue, "
    "(2) flag likely false positives conservatively, "
    "(3) suggest a concrete remediation for each real finding, and "
    "(4) write a precise executive summary and a business-risk narrative. "
    "Be precise and conservative: prefer 'needs_review' over guessing, and "
    "never invent findings, CVEs, or severities that are not supported by the "
    "provided data."
)


class TriagedFinding(BaseModel):
    """Per-finding triage verdict produced by Claude."""

    finding_id: int
    verdict: str = Field(
        default="needs_review",
        description="One of: real | false_positive | needs_review",
    )
    suggested_severity: str = ""
    remediation: str = ""
    rationale: str = ""


class TriageOut(BaseModel):
    """Structured output schema for a full triage run."""

    summary: str = ""
    risk_narrative: str = ""
    items: list[TriagedFinding] = Field(default_factory=list)
    dedup_groups: list[list[int]] = Field(default_factory=list)


def _client() -> Any:
    """Construct and return an ``anthropic.Anthropic`` client.

    Isolated in a tiny helper so tests can monkeypatch client construction
    without touching the network. The ``anthropic`` import is deferred to call
    time so importing this module never requires the SDK.
    """
    import anthropic  # lazy: only needed when AI is actually invoked

    # Bound every request: triage runs inline in a web request, so a hung/slow
    # call must not pin a worker (and its DB connection) indefinitely.
    return anthropic.Anthropic(timeout=settings.AI_TIMEOUT)


def _compact_findings(findings: list[dict]) -> list[dict]:
    """Reduce raw findings to the compact fields Claude needs for triage."""
    compact: list[dict] = []
    for idx, f in enumerate(findings or []):
        fid = f.get("id")
        compact.append(
            {
                "id": int(fid) if isinstance(fid, int) else idx,
                "severity": normalize_severity(f.get("severity")),
                "name": f.get("name", ""),
                "location": f.get("location", ""),
                "description": f.get("description", ""),
                "cve": f.get("cve") or [],
                "cwe": f.get("cwe") or [],
                "cvss": f.get("cvss"),
            }
        )
    return compact


def _build_prompt(findings: list[dict]) -> str:
    """Build the user prompt embedding the compact findings as JSON."""
    payload = json.dumps(_compact_findings(findings), indent=2, default=str)
    return (
        "Triage the following scanner findings. Return structured output with an "
        "executive `summary`, a business `risk_narrative`, a per-finding `items` "
        "list (each with finding_id, verdict, suggested_severity, remediation, "
        "rationale), and `dedup_groups` grouping the ids of duplicate findings.\n\n"
        f"FINDINGS (JSON):\n{payload}"
    )


def triage_findings(findings: list[dict]) -> dict:
    """Run AI triage over ``findings`` and return a structured result dict.

    Args:
        findings: Normalized finding dicts (id, severity, name, location,
            description, cve, cwe, cvss). ``id`` should be the persisted finding
            id where available; a positional index is substituted otherwise.

    Returns:
        On success: ``{"enabled": True, "model": <model>, "result": <TriageOut dict>}``.
        When AI is unavailable: ``{"enabled": False, "reason": <why>}``.
        On a model refusal: ``{"enabled": True, "refused": True, "reason": <why>}``.

    This function never raises for the common failure modes (no key, SDK not
    installed, refusal, API error): each maps to a structured dict instead.
    """
    if not settings.ai_enabled:
        return {"enabled": False, "reason": "ANTHROPIC_API_KEY not configured"}

    try:
        import anthropic  # noqa: F401  (presence check; real use via _client)
    except ImportError:
        return {"enabled": False, "reason": "anthropic SDK not installed"}

    prompt = _build_prompt(findings)
    messages = [{"role": "user", "content": prompt}]

    try:
        client = _client()
    except Exception as exc:  # pragma: no cover - defensive
        return {"enabled": False, "reason": f"anthropic client init failed: {exc}"}

    try:
        result = _run_triage(client, messages)
    except Exception as exc:
        return {
            "enabled": True,
            "error": True,
            "reason": f"AI triage failed: {exc}",
        }

    if isinstance(result, dict):  # refusal / graceful failure passthrough
        return result

    return {
        "enabled": True,
        "model": settings.AI_MODEL,
        "result": result.model_dump(),
    }


def _run_triage(client: Any, messages: list[dict]) -> Any:
    """Invoke Claude and return a ``TriageOut`` (or a graceful failure dict).

    Prefers ``client.messages.parse`` for typed structured output and falls back
    to ``client.messages.create`` with a ``json_schema`` output format when the
    installed SDK lacks ``.parse``.
    """
    common = {
        "model": settings.AI_MODEL,
        "max_tokens": 8000,
        "system": _SYSTEM_PROMPT,
        "messages": messages,
        "thinking": {"type": "adaptive"},
    }

    parse = getattr(client.messages, "parse", None)
    if callable(parse):
        response = parse(
            output_format=TriageOut,
            output_config={"effort": settings.AI_EFFORT},
            **common,
        )
        if getattr(response, "stop_reason", None) == "refusal":
            return {
                "enabled": True,
                "refused": True,
                "reason": "model refused to analyze the findings",
            }
        parsed = getattr(response, "parsed_output", None)
        if parsed is None:
            return {
                "enabled": True,
                "error": True,
                "reason": "empty structured output from model",
            }
        return parsed

    # Fallback for SDKs without messages.parse: json_schema output format.
    response = client.messages.create(
        output_config={
            "effort": settings.AI_EFFORT,
            "format": {"type": "json_schema", "schema": TriageOut.model_json_schema()},
        },
        **common,
    )
    if getattr(response, "stop_reason", None) == "refusal":
        return {
            "enabled": True,
            "refused": True,
            "reason": "model refused to analyze the findings",
        }
    text = _first_text_block(response)
    if not text:
        return {
            "enabled": True,
            "error": True,
            "reason": "no text content in model response",
        }
    return TriageOut.model_validate(json.loads(text))


def _first_text_block(response: Any) -> str:
    """Extract the first text block's text from a messages.create response."""
    for block in getattr(response, "content", []) or []:
        if getattr(block, "type", None) == "text":
            return getattr(block, "text", "") or ""
        text = getattr(block, "text", None)
        if isinstance(text, str) and text:
            return text
    return ""

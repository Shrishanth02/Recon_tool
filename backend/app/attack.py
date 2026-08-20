"""MITRE ATT&CK reference data and finding-to-technique mapping (Purple-Team P1).

This module is pure/stdlib: it carries a small, curated slice of the MITRE
ATT&CK Enterprise matrix (the tactics and techniques RECON-X's scanners can
plausibly evidence) plus :func:`map_finding`, which tags a normalized finding
with the ATT&CK technique + tactic its producing tool represents.

The design is deliberately data-driven so the mapping is easy to extend:

* :data:`TACTICS` is the ordered list of the 14 Enterprise tactics.
* :data:`TECHNIQUES` maps ``technique_id -> {"name", "tactic"}``.
* :data:`_TOOL_TECHNIQUE` maps a scanner tool id to a static technique id for
  the tools whose meaning doesn't depend on the individual finding.
* :data:`_NUCLEI_RULES` is an ordered list of ``(keywords, technique_id)`` pairs
  used to classify a nuclei finding by matching its name + ``info.tags`` (case
  insensitively). The first rule whose keyword appears wins.

``map_finding(tool, finding)`` returns ``{"technique_id", "technique", "tactic"}``
or ``None`` when the tool has no sensible ATT&CK mapping. Nothing here touches
the database, the ORM, or any third-party package, so it imports cleanly and is
cheap to unit-test.
"""

from __future__ import annotations

from typing import Any

# --------------------------------------------------------------------------- #
# Tactics — the 14 ordered ATT&CK Enterprise tactics (id -> display name).
# The ordering mirrors the ATT&CK matrix kill-chain columns and is used by the
# coverage matrix so the UI can render tactics left-to-right.
# --------------------------------------------------------------------------- #
TACTICS: list[dict[str, str]] = [
    {"id": "reconnaissance", "name": "Reconnaissance"},
    {"id": "resource-development", "name": "Resource Development"},
    {"id": "initial-access", "name": "Initial Access"},
    {"id": "execution", "name": "Execution"},
    {"id": "persistence", "name": "Persistence"},
    {"id": "privilege-escalation", "name": "Privilege Escalation"},
    {"id": "defense-evasion", "name": "Defense Evasion"},
    {"id": "credential-access", "name": "Credential Access"},
    {"id": "discovery", "name": "Discovery"},
    {"id": "lateral-movement", "name": "Lateral Movement"},
    {"id": "collection", "name": "Collection"},
    {"id": "command-and-control", "name": "Command and Control"},
    {"id": "exfiltration", "name": "Exfiltration"},
    {"id": "impact", "name": "Impact"},
]

# Fast lookup: tactic id -> display name.
TACTIC_NAMES: dict[str, str] = {t["id"]: t["name"] for t in TACTICS}

# Ordered index of each tactic (for stable sorting of the coverage matrix).
TACTIC_ORDER: dict[str, int] = {t["id"]: i for i, t in enumerate(TACTICS)}


# --------------------------------------------------------------------------- #
# Techniques — the curated slice of ATT&CK techniques we map onto.
# technique_id -> {"name": <display>, "tactic": <tactic id>}
# --------------------------------------------------------------------------- #
TECHNIQUES: dict[str, dict[str, str]] = {
    "T1596": {
        "name": "Search Open Technical Databases",
        "tactic": "reconnaissance",
    },
    "T1590.005": {
        "name": "Gather Victim Network Information: IP Addresses",
        "tactic": "reconnaissance",
    },
    "T1590.002": {
        "name": "Gather Victim Network Information: DNS",
        "tactic": "reconnaissance",
    },
    "T1595.002": {
        "name": "Active Scanning: Vulnerability Scanning",
        "tactic": "reconnaissance",
    },
    "T1592.002": {
        "name": "Gather Victim Host Information: Software",
        "tactic": "reconnaissance",
    },
    "T1592": {
        "name": "Gather Victim Host Information",
        "tactic": "reconnaissance",
    },
    "T1046": {
        "name": "Network Service Discovery",
        "tactic": "discovery",
    },
    "T1083": {
        "name": "File and Directory Discovery",
        "tactic": "discovery",
    },
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "tactic": "initial-access",
    },
    "T1078": {
        "name": "Valid Accounts",
        "tactic": "initial-access",
    },
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactic": "execution",
    },
    "T1090": {
        "name": "Proxy",
        "tactic": "command-and-control",
    },
    "T1584": {
        "name": "Compromise Infrastructure",
        "tactic": "resource-development",
    },
}


# --------------------------------------------------------------------------- #
# Static per-tool technique mapping for tools whose meaning is fixed regardless
# of the individual finding.
# --------------------------------------------------------------------------- #
_TOOL_TECHNIQUE: dict[str, str] = {
    "whois": "T1596",
    "subdomains": "T1590.005",
    "httpx": "T1595.002",
    "tech": "T1592.002",
    "dirbuster": "T1083",
    "dns_zone_transfer": "T1590.002",
    "nmap": "T1046",
    "reverse": "T1590.005",
}


# --------------------------------------------------------------------------- #
# Nuclei classification — ordered (keywords, technique_id) rules. The first rule
# whose keyword is found (as a substring, case-insensitively) in the finding's
# name + tags wins. The default when nothing matches is T1595.002.
# --------------------------------------------------------------------------- #
_NUCLEI_RULES: list[tuple[tuple[str, ...], str]] = [
    (("sqli", "sql-injection", "injection"), "T1190"),
    (("rce", "remote-code", "code-execution"), "T1190"),
    (("xss", "cross-site-scripting"), "T1059"),
    (("default-login", "default-creds", "creds", "credential", "exposed-panel",
      "login"), "T1078"),
    (("lfi", "traversal", "path-traversal"), "T1083"),
    (("ssrf",), "T1090"),
    (("take-over", "takeover", "subdomain-takeover"), "T1584"),
    (("exposure", "config", "disclosure", "misconfig"), "T1592"),
]

_NUCLEI_DEFAULT = "T1595.002"


def _technique_payload(technique_id: str | None) -> dict[str, str] | None:
    """Return the ``{"technique_id","technique","tactic"}`` payload for an id.

    Returns ``None`` when ``technique_id`` is falsy or unknown, so callers get a
    clean "unmapped" signal instead of a partially-populated dict.
    """
    if not technique_id:
        return None
    meta = TECHNIQUES.get(technique_id)
    if meta is None:
        return None
    return {
        "technique_id": technique_id,
        "technique": meta["name"],
        "tactic": meta["tactic"],
    }


def _nuclei_haystack(finding: dict[str, Any]) -> str:
    """Build the lower-cased text (name + tags) a nuclei finding is matched on.

    ``tags`` may live at the top level or under an ``info`` block, and may be a
    list or a comma-separated string; all shapes are flattened into one string.
    """
    parts: list[str] = [str(finding.get("name", ""))]
    info = finding.get("info")
    if isinstance(info, dict):
        parts.append(str(info.get("name", "")))
        tags = info.get("tags")
    else:
        tags = None
    # Prefer top-level tags, fall back to info.tags.
    tags = finding.get("tags", tags)
    if isinstance(tags, str):
        parts.append(tags)
    elif isinstance(tags, (list, tuple)):
        parts.extend(str(t) for t in tags)
    return " ".join(parts).lower()


def _map_nuclei(finding: dict[str, Any]) -> dict[str, str] | None:
    """Classify a nuclei finding into an ATT&CK technique by its name + tags."""
    haystack = _nuclei_haystack(finding)
    for keywords, technique_id in _NUCLEI_RULES:
        if any(keyword in haystack for keyword in keywords):
            return _technique_payload(technique_id)
    return _technique_payload(_NUCLEI_DEFAULT)


def map_finding(tool: str, finding: dict[str, Any]) -> dict[str, str] | None:
    """Map a scanner finding to its MITRE ATT&CK technique + tactic.

    Parameters
    ----------
    tool:
        The scanner tool id that produced the finding (``"nmap"``, ``"nuclei"``,
        ``"whois"``, ...).
    finding:
        The normalized finding dict (as produced by
        :func:`app.crud.derive_findings`). For nuclei this may also carry the
        raw ``tags``/``info`` used to refine the mapping.

    Returns
    -------
    dict | None
        ``{"technique_id", "technique", "tactic"}`` when a sensible mapping
        exists, else ``None`` (tools with no ATT&CK meaning, or an unknown tool).

    Examples
    --------
    >>> map_finding("nmap", {"name": "Open port 22/tcp (ssh)"})
    {'technique_id': 'T1046', 'technique': 'Network Service Discovery', 'tactic': 'discovery'}
    >>> map_finding("nuclei", {"name": "SQLi", "tags": ["sqli"]})["technique_id"]
    'T1190'
    >>> map_finding("unknown-tool", {})  # returns None
    """
    if not tool:
        return None
    finding = finding or {}
    if tool == "nuclei":
        return _map_nuclei(finding)
    return _technique_payload(_TOOL_TECHNIQUE.get(tool))

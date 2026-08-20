"""Offline, curated product/version -> known-CVE knowledge base.

Maps a detected component + version (e.g. from ``nmap -sV``) to a known CVE using
a correct version-range comparison. It is deliberately OFFLINE (no external or
paid API) and CONSERVATIVE: a CVE is only returned when the detected version
actually falls inside the affected range — never merely because a version
"looks old", and never without a concrete version.

A match is a SIGNAL (a strong version-based inference), not a validated exploit;
the caller records it as ``detection_tier="signal"``. Extend :data:`VULN_DB` to
broaden coverage — the matching engine stays the same.
"""

import re
from typing import Optional


def _vkey(v: str) -> list:
    """A comparable key for a loosely-formatted version string.

    Splits into numeric and alpha tokens so that ``1.0.1 < 1.0.1f < 1.0.1g`` and
    ``8.2p1 < 8.2p2 < 9.6`` all order correctly (numeric tokens sort before an
    alpha token at the same position, and a longer version outranks its prefix).
    """
    key: list = []
    for tok in re.findall(r"\d+|[a-zA-Z]+", str(v).lower()):
        if tok.isdigit():
            key.append((0, int(tok), ""))
        else:
            key.append((1, 0, tok))
    return key


def _cmp(a: str, b: str) -> int:
    ka, kb = _vkey(a), _vkey(b)
    return (ka > kb) - (ka < kb)


def _in_range(version: str, rng: dict) -> bool:
    """True iff ``version`` satisfies EVERY constraint in ``rng`` (AND)."""
    if not version:
        return False
    if "eq" in rng and _cmp(version, rng["eq"]) != 0:
        return False
    if "lt" in rng and not _cmp(version, rng["lt"]) < 0:
        return False
    if "le" in rng and not _cmp(version, rng["le"]) <= 0:
        return False
    if "gt" in rng and not _cmp(version, rng["gt"]) > 0:
        return False
    if "ge" in rng and not _cmp(version, rng["ge"]) >= 0:
        return False
    return True


def _range_text(rng: dict) -> str:
    order = [("eq", "=="), ("ge", ">="), ("gt", ">"), ("le", "<="), ("lt", "<")]
    parts = [f"{sym} {rng[k]}" for k, sym in order if k in rng]
    return ", ".join(parts) or "any"


# Curated seed — every entry is a real CVE with a real affected range. Extend
# freely; keep each range accurate (the whole point is "sufficient evidence").
VULN_DB: list[dict] = [
    {"product": "openssh", "cve": "CVE-2023-48795",
     "title": "OpenSSH 'Terrapin' prefix truncation weakens SSH channel integrity",
     "cwe": ["CWE-354"], "cvss": 5.9, "range": {"lt": "9.6"}},
    {"product": "openssl", "cve": "CVE-2014-0160",
     "title": "OpenSSL 'Heartbleed' memory disclosure",
     "cwe": ["CWE-125"], "cvss": 7.5, "range": {"ge": "1.0.1", "le": "1.0.1f"}},
    {"product": "apache httpd", "cve": "CVE-2021-41773",
     "title": "Apache HTTP Server path traversal / RCE (mod_cgi)",
     "cwe": ["CWE-22"], "cvss": 7.5, "range": {"eq": "2.4.49"}},
    {"product": "vsftpd", "cve": "CVE-2011-2523",
     "title": "vsftpd 2.3.4 backdoor command execution",
     "cwe": ["CWE-78"], "cvss": 9.8, "range": {"eq": "2.3.4"}},
    {"product": "proftpd", "cve": "CVE-2015-3306",
     "title": "ProFTPD mod_copy unauthenticated remote command execution",
     "cwe": ["CWE-264"], "cvss": 9.8, "range": {"eq": "1.3.5"}},
]


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", (s or "").strip().lower())


def severity_for(cvss: Optional[float]) -> str:
    if cvss is None:
        return "medium"
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    return "low"


def match(product: str, version: str, cpe: Optional[list] = None) -> list[dict]:
    """Return known CVEs whose affected product + range matches (product, version).

    Conservative: requires BOTH a product-name match (the KB product name is a
    substring of the detected product) AND the version inside the affected range.
    Returns ``[]`` when the version is missing — we never guess without a version.
    """
    prod = _norm(product)
    ver = (version or "").strip()
    if not prod or not ver:
        return []
    out: list[dict] = []
    for entry in VULN_DB:
        if _norm(entry["product"]) not in prod:
            continue
        if not _in_range(ver, entry["range"]):
            continue
        out.append({
            "cve": entry["cve"],
            "title": entry["title"],
            "cwe": list(entry.get("cwe", [])),
            "cvss": entry.get("cvss"),
            "severity": severity_for(entry.get("cvss")),
            "affected_range": _range_text(entry["range"]),
            "matched_product": entry["product"],
        })
    return out

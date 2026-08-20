"""Safe, non-destructive Tier-2 validation of findings.

Re-verifies SIGNAL findings using the location/evidence a scanner already
discovered — a read-only HTTP GET (or a header re-read), ALWAYS behind the
SSRF/egress netguard (and the engagement scope when supplied). On success a
finding moves ``signal -> validated`` with the observed evidence and a higher
confidence; on failure it STAYS ``signal``.

Guarantees:
  * never destructive — read-only GET, redirects NOT followed (an SSRF-safe and
    soft-404-safe choice), no payloads sent;
  * never AI-based — validation is a concrete observation, not a model opinion;
  * never invents evidence — only records what the live response actually showed;
  * never bypasses scope or netguard — both run before any request leaves;
  * already-validated findings (injection/webaudit/AXFR) are PRESERVED, not
    re-attempted.
"""

import re
from typing import Any, Optional
from urllib.parse import urlsplit

import requests

from . import models, netguard
from . import scope as scope_mod
from .database import SessionLocal

_UA = "RedOpsX-Validator/1.0"
_TIMEOUT = 8
#: Hard cap on how many findings a single validation pass will re-request, so a
#: huge workspace can never turn finalization into an unbounded scan.
_MAX_VALIDATIONS = 40


def _host_of(location: str) -> str:
    loc = (location or "").strip()
    if "://" not in loc:
        loc = "http://" + loc
    return urlsplit(loc).hostname or ""


def _url_of(location: str) -> str:
    loc = (location or "").strip()
    if not loc:
        return ""
    return loc if "://" in loc else "https://" + loc


def _safe_fetch(url: str, scope_list) -> tuple[Optional["requests.Response"], str]:
    """GET *url* only after scope + netguard pass. Read-only, no redirects.

    Returns ``(response, "ok")`` or ``(None, reason)``. This is the ONLY egress
    path in the module and it can never be reached without both gates passing.
    """
    host = _host_of(url)
    if not host:
        return None, "no host"
    # Scope (skipped only when the engagement scope is empty == unrestricted).
    if scope_list:
        ok, why = scope_mod.check(host, scope_list)
        if not ok:
            return None, f"out of scope ({why})"
    # SSRF/egress guard — ALWAYS runs (blocks loopback/RFC-1918/link-local/metadata).
    safe, why = netguard.validate_target(host)
    if not safe:
        return None, f"blocked by netguard ({why})"
    try:
        resp = requests.get(
            url, headers={"User-Agent": _UA}, timeout=_TIMEOUT,
            verify=False, allow_redirects=False,
        )
        return resp, "ok"
    except requests.RequestException as exc:
        return None, f"request failed ({exc})"


# --------------------------------------------------------------------------- #
# Per-class validators. Each returns:
#   None                              -> nothing safely checkable; stay signal
#   {"ok": bool, "method": str, "evidence": {...}, "reason": str|None}
# --------------------------------------------------------------------------- #
def _validate_security_header(f: "models.Finding", scope_list) -> Optional[dict]:
    header = None
    m = re.search(r"missing security header:\s*([A-Za-z\-]+)", f.name or "", re.I)
    if m:
        header = m.group(1).strip().lower()
    if not header:
        header = str((f.evidence or {}).get("header", "")).strip().lower() or None
    if not header:
        return None
    resp, why = _safe_fetch(_url_of(f.location), scope_list)
    if resp is None:
        return {"ok": False, "method": "http-header-recheck", "evidence": {}, "reason": why}
    if 300 <= resp.status_code < 400:
        # A redirect response's headers aren't comparable — inconclusive.
        return {"ok": False, "method": "http-header-recheck",
                "evidence": {"http_status": resp.status_code}, "reason": "redirect — inconclusive"}
    present = header in {k.lower() for k in resp.headers.keys()}
    # The finding claims the header is MISSING -> validated iff still missing.
    return {
        "ok": (not present),
        "method": "http-header-recheck",
        "evidence": {"header": header, "observed": resp.headers.get(header) or "absent",
                     "http_status": resp.status_code},
        "reason": None if not present else "header now present",
    }


def _validate_exposed_file(f: "models.Finding", scope_list) -> Optional[dict]:
    resp, why = _safe_fetch(_url_of(f.location), scope_list)
    if resp is None:
        return {"ok": False, "method": "http-file-recheck", "evidence": {}, "reason": why}
    if resp.status_code != 200:
        return {"ok": False, "method": "http-file-recheck",
                "evidence": {"http_status": resp.status_code}, "reason": f"HTTP {resp.status_code}"}
    sample = (resp.text or "")[:4096]
    ctype = resp.headers.get("Content-Type", "")
    sig = str((f.evidence or {}).get("signature_matched", "")).strip()
    if sig and sig != "(binary/no-signature)":
        confirmed = sig.lower() in sample.lower()
    else:
        confirmed = "text/html" not in ctype.lower()
    return {
        "ok": confirmed,
        "method": "http-file-recheck",
        "evidence": {"http_status": resp.status_code, "content_type": ctype,
                     "sample": sample[:200]},
        "reason": None if confirmed else "signature not matched (soft-404?)",
    }


def _validate_nuclei_reproduce(f: "models.Finding", scope_list) -> Optional[dict]:
    # Only reproducible when nuclei extracted a concrete, specific indicator.
    extracted = [str(x) for x in ((f.evidence or {}).get("extracted") or []) if len(str(x)) >= 4]
    if not extracted:
        return None  # nothing safely reproducible -> stay signal
    resp, why = _safe_fetch(_url_of(f.location), scope_list)
    if resp is None:
        return {"ok": False, "method": "http-extract-recheck", "evidence": {}, "reason": why}
    body = resp.text or ""
    hit = next((x for x in extracted if x in body), None)
    return {
        "ok": hit is not None,
        "method": "http-extract-recheck",
        "evidence": ({"http_status": resp.status_code, "reproduced_indicator": hit}
                     if hit else {"http_status": resp.status_code}),
        "reason": None if hit else "extracted indicator not reproduced",
    }


def _pick_validator(f: "models.Finding"):
    name = (f.name or "").lower()
    cwe = {str(c).upper() for c in (f.cwe or [])}
    if "missing security header" in name or "CWE-693" in cwe:
        return _validate_security_header
    if "exposed" in name or "sensitive file" in name:
        return _validate_exposed_file
    if (f.source or "") == "nuclei":
        return _validate_nuclei_reproduce
    return None


def validate_workspace(workspace_id: int, scope_list=None, *, session_factory=SessionLocal) -> dict:
    """Attempt safe Tier-2 validation of a workspace's SIGNAL vuln findings.

    Uses its OWN session (thread-safe when run in an executor) and commits. Only
    ``signal`` + ``kind="vuln"`` findings are considered — already-validated
    injection/webaudit/AXFR are left untouched.
    """
    db = session_factory()
    attempted = validated = 0
    try:
        findings = (
            db.query(models.Finding)
            .filter(
                models.Finding.workspace_id == workspace_id,
                models.Finding.detection_tier == "signal",
                models.Finding.kind == "vuln",
            )
            .order_by(models.Finding.id)
            .all()
        )
        for f in findings:
            if attempted >= _MAX_VALIDATIONS:
                break
            fn = _pick_validator(f)
            if fn is None:
                continue
            attempted += 1
            res = fn(f, scope_list)
            if not res:
                attempted -= 1  # nothing was actually attempted
                continue
            ev = dict(f.evidence or {})
            ev["validation"] = {
                "method": res.get("method"),
                "result": "confirmed" if res["ok"] else "not_confirmed",
                "reason": res.get("reason"),
            }
            if res["ok"]:
                # signal -> VALIDATED, with the observed evidence.
                f.detection_tier = "validated"
                f.confidence = max(int(f.confidence or 0), 85)
                ev.update(res.get("evidence") or {})
                validated += 1
            # On failure the finding STAYS signal (never falsely validated); we
            # only record that a check was attempted.
            f.evidence = ev
            db.add(f)
        db.commit()
    finally:
        db.close()
    return {"attempted": attempted, "validated": validated}

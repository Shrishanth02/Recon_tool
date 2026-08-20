"""Conservative cross-scanner correlation.

Links findings that refer to the SAME underlying security issue — same
``normalized_host | normalized_endpoint | vulnerability_class`` — across
DIFFERENT scanners, WITHOUT merging them. Each finding keeps its own source and
evidence; correlated findings gain:

  * a shared ``correlation_id`` (so the group is identifiable),
  * a ``related`` list of ``{id, source, name}`` (so a finding shows exactly
    which other scanner results support it),
  * an idempotent confidence FLOOR from corroboration (raised via ``max`` so
    re-running never compounds; correlation alone never lifts a finding to
    VALIDATED — only the validation layer does that).

It is deliberately conservative: a group is only formed when there are at least
two findings from at least two DISTINCT sources sharing the identity key.
Different host / endpoint / class stays separate. It also enriches each
finding's evidence with host context (server / technology) pulled read-only from
the workspace's httpx / tech scan results — the "nuclei + httpx + tech"
combination — without any network access.
"""

import hashlib
import re
from urllib.parse import urlsplit

from sqlalchemy import select

from . import models

#: Signal findings never exceed this confidence from correlation alone (a value
#: below the validation floor of 85), so "corroborated" never masquerades as
#: "validated".
_SIGNAL_CONF_CAP = 84


def _host(location: str) -> str:
    loc = (location or "").strip()
    if "://" not in loc:
        loc = "http://" + loc
    return (urlsplit(loc).hostname or "").lower()


def _endpoint(location: str) -> str:
    loc = (location or "").strip()
    if "://" not in loc:
        loc = "http://" + loc
    path = urlsplit(loc).path or "/"
    if len(path) > 1 and path.endswith("/"):
        path = path.rstrip("/")
    return path or "/"


def _vuln_class(f: "models.Finding") -> str:
    """The issue's class identity: primary CWE if present (stable across tools),
    else a normalized name token."""
    cwe = f.cwe or []
    if cwe:
        return sorted(str(c).upper() for c in cwe)[0]
    name = (f.name or "").lower()
    # Drop trailing identifiers/params so "SQLi: id" and "SQLi: q" share a class.
    return re.sub(r"[^a-z ]+", " ", name).strip()[:40]


def _corr_key(f: "models.Finding") -> str:
    return "|".join([_host(f.location), _endpoint(f.location), _vuln_class(f)])


def _host_context(db, workspace_id: int) -> dict:
    """host -> {server, tech, technologies, status, title} from httpx/tech scans."""
    ctx: dict[str, dict] = {}
    scans = db.scalars(
        select(models.Scan)
        .where(
            models.Scan.workspace_id == workspace_id,
            models.Scan.tool.in_(("httpx", "tech")),
        )
        .order_by(models.Scan.id.desc())
    ).all()
    for s in scans:
        res = s.result or {}
        if s.tool == "httpx":
            for row in (res.get("rows") or []):
                host = (row.get("host") or _host(row.get("url", ""))).lower()
                if host and host not in ctx:
                    ctx[host] = {
                        "server": row.get("webserver"), "tech": row.get("tech"),
                        "status": row.get("status"), "title": row.get("title"),
                    }
        elif s.tool == "tech":
            host = _host(res.get("url", ""))
            if host and host not in ctx:
                ctx[host] = {"technologies": list((res.get("detected_tech") or {}).keys())}
    # drop empties
    return {h: {k: v for k, v in c.items() if v} for h, c in ctx.items()}


def correlate_workspace(db, workspace_id: int) -> dict:
    """Correlate a workspace's findings in place (caller commits)."""
    findings = db.scalars(
        select(models.Finding).where(models.Finding.workspace_id == workspace_id)
    ).all()
    context = _host_context(db, workspace_id)

    groups: dict[str, list] = {}
    for f in findings:
        # Host-context enrichment (idempotent) — attach server/tech for the host.
        h = _host(f.location)
        if h and h in context:
            ev = dict(f.evidence or {})
            ev["host_context"] = context[h]
            f.evidence = ev
            db.add(f)
        groups.setdefault(_corr_key(f), []).append(f)

    n_groups = 0
    n_linked = 0
    for key, group in groups.items():
        sources = {g.source for g in group}
        # CONSERVATIVE: correlate only when >=2 findings from >=2 distinct sources.
        if len(group) < 2 or len(sources) < 2:
            for g in group:
                if g.correlation_id is not None or g.related:
                    g.correlation_id = None
                    g.related = []
                    db.add(g)
            continue
        n_groups += 1
        cid = "corr_" + hashlib.sha256(
            f"{workspace_id}|{key}".encode("utf-8", "replace")
        ).hexdigest()[:16]
        has_validated = any(g.detection_tier == "validated" for g in group)
        for g in group:
            g.correlation_id = cid
            g.related = [
                {"id": o.id, "source": o.source, "name": o.name}
                for o in group if o.id != g.id
            ]
            # Idempotent corroboration floor (max, never additive).
            if g.detection_tier == "validated":
                g.confidence = max(int(g.confidence or 0), 90)
            else:
                floor = 75 if has_validated else 65
                g.confidence = min(_SIGNAL_CONF_CAP, max(int(g.confidence or 0), floor))
            db.add(g)
            n_linked += 1
    db.flush()
    return {"groups": n_groups, "linked": n_linked}

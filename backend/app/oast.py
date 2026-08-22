"""OAST (out-of-band application security testing) collaborator — self-hosted.

Confirming BLIND server-side vulnerabilities (blind SSRF, blind RCE, …) requires a
callback the target can reach out to. This module is the minimal, self-hosted
collaborator: a scanner plants an unguessable token inside a payload
(``{OAST_BASE_URL}/oast/<token>``); if the target makes the out-of-band request,
the public callback route records an interaction, and the owning scan correlates
the token to a CONFIRMED finding.

Security properties:
  * **Tenant isolation** is structural — a probe is bound to ONE workspace at mint,
    an interaction FKs its probe, and correlation filters by BOTH the caller's
    workspace_id AND its own minted tokens, so a callback can never be read by
    another tenant (and tokens are unguessable, so they can't be claimed).
  * **Bounded / non-destructive** — probes are short-lived (``OAST_PROBE_TTL_MIN``)
    and lazily cleaned up; interactions per probe are capped; only unknown-token
    hits are dropped (never stored), so the tables can't be flooded via the token.
  * **No secret exposure** — only minimal, non-sensitive metadata is recorded
    (source IP, method, path) — never request bodies, headers, cookies, or tokens
    beyond the opaque probe id; the public route reflects nothing.
  * **Secure-by-default OFF** — with no ``OAST_BASE_URL`` configured, ``available``
    is False, no probe is ever minted, and scanner behaviour is unchanged.
"""

import re
from datetime import datetime, timedelta, timezone
from typing import Optional

import secrets

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import models
from .config import settings

# 32 hex chars — unguessable and small enough to validate cheaply on the public
# route so a garbage/oversized token never reaches the DB.
_TOKEN_RE = re.compile(r"^[0-9a-f]{32}$")
_MAX_INTERACTIONS_PER_PROBE = 50   # bound the table against a flood on a known token


def available() -> bool:
    """True iff the collaborator is enabled AND has a public base URL — the
    precondition for planting probes and correlating callbacks."""
    return settings.oast_configured


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _as_aware(dt: Optional[datetime]) -> Optional[datetime]:
    """Coerce a DB datetime to aware-UTC. SQLite returns naive datetimes while
    PostgreSQL returns aware ones; normalise so comparisons never mix the two."""
    if dt is not None and dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def new_token() -> str:
    return secrets.token_hex(16)


def callback_url(token: str) -> str:
    base = settings.OAST_BASE_URL.strip().rstrip("/")
    return f"{base}/oast/{token}"


def is_valid_token(token: str) -> bool:
    return bool(token and _TOKEN_RE.match(token))


def mint_probe(db: Session, workspace_id: int, kind: str = "ssrf") -> Optional[tuple]:
    """Mint + persist a workspace-bound probe; return ``(token, callback_url)`` or
    ``None`` when OAST is not configured. Lazily removes expired probes first."""
    if not available() or not workspace_id:
        return None
    cleanup(db)
    token = new_token()
    probe = models.OastProbe(
        workspace_id=workspace_id, token=token, kind=(kind or "ssrf")[:32],
        expires_at=_now() + timedelta(minutes=max(1, settings.OAST_PROBE_TTL_MIN)),
    )
    db.add(probe)
    db.flush()
    return token, callback_url(token)


def record_interaction(db: Session, token: str, *, source_ip: str = "",
                       method: str = "", path: str = "") -> bool:
    """Record a callback hit. Returns True iff it belonged to a live probe.

    Unknown / malformed / expired tokens are IGNORED (not stored), so the public
    route can't be used to fill the tables; interactions per probe are capped.
    """
    if not is_valid_token(token):
        return False
    probe = db.execute(
        select(models.OastProbe).where(models.OastProbe.token == token)
    ).scalar_one_or_none()
    if probe is None or _as_aware(probe.expires_at) < _now():
        return False
    count = db.execute(
        select(func.count(models.OastInteraction.id))
        .where(models.OastInteraction.probe_id == probe.id)
    ).scalar_one()
    if count >= _MAX_INTERACTIONS_PER_PROBE:
        return True   # already have proof; don't grow the table further
    db.add(models.OastInteraction(
        probe_id=probe.id, source_ip=(source_ip or "")[:64],
        method=(method or "")[:10], path=(path or "")[:512],
    ))
    return True


def hits_for(db: Session, workspace_id: int, tokens) -> set:
    """The subset of ``tokens`` that (a) belong to ``workspace_id`` AND (b)
    received at least one interaction. Filtering by workspace_id in addition to the
    token set is defence-in-depth for tenant isolation."""
    toks = [t for t in (tokens or []) if is_valid_token(t)]
    if not toks or not workspace_id:
        return set()
    rows = db.execute(
        select(models.OastProbe.token)
        .join(models.OastInteraction, models.OastInteraction.probe_id == models.OastProbe.id)
        .where(
            models.OastProbe.workspace_id == workspace_id,
            models.OastProbe.token.in_(toks),
        )
        .distinct()
    ).all()
    return {r[0] for r in rows}


def cleanup(db: Session, now: Optional[datetime] = None) -> int:
    """Delete expired probes (their interactions cascade). Returns the count.

    Expiry is compared in Python (via :func:`_as_aware`) so it is correct on both
    SQLite (naive) and PostgreSQL (aware); the probe table is kept small by this
    same routine running on every mint."""
    cutoff = now or _now()
    probes = db.execute(select(models.OastProbe)).scalars().all()
    removed = 0
    for probe in probes:
        if _as_aware(probe.expires_at) < cutoff:
            db.delete(probe)
            removed += 1
    return removed

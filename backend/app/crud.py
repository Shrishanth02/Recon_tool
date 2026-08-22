"""Tenant-aware database operations used by the routers.

This module owns all persistence beyond the raw ORM: authentication, workspace
summaries, scan persistence, and finding derivation. The ``derive_findings``
and ``save_scan`` logic is a faithful port of the original single-user
``db.py`` (nuclei/nmap/dirbuster derivation), rewritten to target the new
``Finding`` model with a ``workspace_id`` and ``status="open"``.
"""

import hashlib
import logging
import re
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import attack, models, secretbox, security, vulndb
from .config import settings
from .severity import is_known_severity, normalize_severity

logger = logging.getLogger("reconx.crud")


def _clamp(value: Any, limit: int) -> str:
    """Truncate a value to a column width before persist.

    Scanner-derived ``name``/``location`` can exceed the ``Finding`` column widths
    (e.g. a very long nuclei/injection URL). SQLite silently accepts the overflow,
    but Postgres raises ``DataError`` at flush and fails the whole ``save_scan`` —
    losing a completed scan. Clamping at the write boundary keeps the finding.
    """
    s = "" if value is None else str(value)
    return s if len(s) <= limit else s[:limit]


# Severity ordering used when listing findings (critical first).
_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
# Trust ordering for detection tiers (higher = stronger evidence). Used when a
# re-observed finding is merged: the stronger tier wins.
_TIER_RANK = {"signal": 0, "validated": 1, "exploited": 2}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def slugify(value: str) -> str:
    """Turn an arbitrary name into a URL-safe slug."""
    base = re.sub(r"[^a-z0-9]+", "-", (value or "").lower()).strip("-")
    return base or "item"


def _unique_org_slug(db: Session, name: str) -> str:
    base = slugify(name)
    slug = base
    while db.scalar(select(models.Organization).where(models.Organization.slug == slug)):
        slug = f"{base}-{secrets.token_hex(2)}"
    return slug


# --------------------------------------------------------------------------- #
# Users / auth
# --------------------------------------------------------------------------- #
def get_user_by_email(db: Session, email: str) -> models.User | None:
    return db.scalar(select(models.User).where(models.User.email == email.lower().strip()))


def get_user(db: Session, user_id: int) -> models.User | None:
    return db.get(models.User, user_id)


def authenticate(db: Session, email: str, password: str) -> models.User | None:
    """Return the user if the email/password pair is valid, else None."""
    user = get_user_by_email(db, email)
    if not user or not user.is_active:
        return None
    if not security.verify_password(password, user.password_hash):
        return None
    return user


# --------------------------------------------------------------------------- #
# Refresh-token rotation + replay detection (STEP 2)
# --------------------------------------------------------------------------- #
def issue_refresh_token(
    db: Session, user_id: int, *, family_id: str | None = None
) -> models.RefreshToken:
    """Create + persist a new refresh-token record (caller commits).

    Starts a fresh rotation family unless ``family_id`` is given (rotation keeps
    the lineage). The returned row's ``jti``/``family_id`` are embedded in the JWT.
    """
    now = _now()
    rt = models.RefreshToken(
        jti=secrets.token_urlsafe(32),
        user_id=user_id,
        family_id=family_id or secrets.token_urlsafe(16),
        expires_at=now + timedelta(days=settings.REFRESH_TTL_DAYS),
    )
    db.add(rt)
    db.flush()
    return rt


def revoke_refresh_family(db: Session, family_id: str) -> int:
    """Revoke every token in a rotation family (this session lineage only)."""
    return (
        db.query(models.RefreshToken)
        .filter(
            models.RefreshToken.family_id == family_id,
            models.RefreshToken.revoked.is_(False),
        )
        .update({"revoked": True}, synchronize_session=False)
    )


def revoke_user_refresh_tokens(db: Session, user_id: int) -> int:
    """Revoke ALL of a user's refresh tokens (belt-and-suspenders for logout-all)."""
    return (
        db.query(models.RefreshToken)
        .filter(
            models.RefreshToken.user_id == user_id,
            models.RefreshToken.revoked.is_(False),
        )
        .update({"revoked": True}, synchronize_session=False)
    )


def rotate_refresh_token(
    db: Session, jti: str
) -> tuple[str, "models.RefreshToken | None"]:
    """Consume ``jti`` and mint its successor (caller commits).

    Returns ``(status, successor)``:
      * ``("ok", row)``       — rotated; embed ``row``'s jti/family in the new JWT.
      * ``("reuse", None)``   — REPLAY of an already-consumed token; the family is
                                revoked (contains a stolen token to its session).
      * ``("invalid", None)`` — unknown / revoked / expired token.
    """
    rec = (
        db.query(models.RefreshToken)
        .filter(models.RefreshToken.jti == jti)
        .one_or_none()
    )
    if rec is None or rec.revoked:
        return "invalid", None
    now = _now()
    exp = rec.expires_at
    if exp is not None and exp.tzinfo is None:  # SQLite reads back naive
        exp = exp.replace(tzinfo=timezone.utc)
    if exp is not None and exp < now:
        return "invalid", None
    if rec.consumed_at is not None:
        # Replay of a rotated token -> revoke the whole family (session-scoped,
        # never account-wide, so it cannot be abused for a lockout DoS).
        revoke_refresh_family(db, rec.family_id)
        return "reuse", None
    # Atomically CLAIM the token: consume it ONLY if still unconsumed. Under a
    # concurrent double-use exactly one UPDATE matches; the loser (0 rows) is
    # treated as replay and the family is revoked — so a race can never mint two
    # live successors from a single refresh token.
    claimed = (
        db.query(models.RefreshToken)
        .filter(
            models.RefreshToken.jti == jti,
            models.RefreshToken.consumed_at.is_(None),
            models.RefreshToken.revoked.is_(False),
        )
        .update({"consumed_at": now}, synchronize_session=False)
    )
    if not claimed:
        revoke_refresh_family(db, rec.family_id)
        return "reuse", None
    successor = issue_refresh_token(db, rec.user_id, family_id=rec.family_id)
    return "ok", successor


# --------------------------------------------------------------------------- #
# OIDC login-transaction state (CSRF + replay guard)
# --------------------------------------------------------------------------- #
def create_sso_state(
    db: Session, org_id: int, *, ttl_seconds: int | None = None
) -> models.SsoState:
    """Create + persist a single-use OIDC login-transaction record (caller commits).

    ``state_id`` (the OIDC ``state`` parameter, also set as a browser cookie) and
    ``nonce`` (the OIDC ``nonce`` parameter, later matched against the id_token)
    are unguessable random tokens. The row lives ``ttl_seconds`` and can be
    consumed exactly once by the callback.
    """
    ttl = int(ttl_seconds if ttl_seconds is not None else settings.SSO_STATE_TTL_SECONDS)
    rec = models.SsoState(
        state_id=secrets.token_urlsafe(32),
        org_id=org_id,
        nonce=secrets.token_urlsafe(32),
        expires_at=_now() + timedelta(seconds=ttl),
    )
    db.add(rec)
    db.flush()
    return rec


def consume_sso_state(
    db: Session, state_id: str, *, expected_org_id: int | None = None
) -> tuple[str, "models.SsoState | None"]:
    """Atomically claim an OIDC login-transaction row exactly once (caller commits).

    Returns ``(status, record)``:
      * ``("ok", row)``       — valid, unexpired, unused and (if requested) the
                                right org; the row is now consumed. Read the bound
                                org (``row.org_id``) + ``row.nonce`` from it.
      * ``("invalid", None)`` — unknown / already-used (replay) / expired state,
                                or a mismatch against ``expected_org_id`` (a state
                                minted for a different org).

    ``expected_org_id`` is the tenant the callback is authenticating into (from
    the slug in the path); a state minted for another org is rejected. When
    ``None`` (the fixed-redirect callback that carries no slug) the org is taken
    from the record itself, so cross-tenant confusion is impossible either way.
    """
    if not state_id:
        return "invalid", None
    rec = (
        db.query(models.SsoState)
        .filter(models.SsoState.state_id == state_id)
        .one_or_none()
    )
    if rec is None or rec.consumed:
        return "invalid", None
    exp = rec.expires_at
    if exp is not None and exp.tzinfo is None:  # SQLite reads back naive
        exp = exp.replace(tzinfo=timezone.utc)
    if exp is not None and exp < _now():
        return "invalid", None
    if expected_org_id is not None and rec.org_id != expected_org_id:
        # A state minted for org A must never authenticate into org B.
        return "invalid", None
    # Atomically CLAIM: mark consumed ONLY if still unconsumed. Under a concurrent
    # double-callback exactly one UPDATE matches; the loser (0 rows) is treated as
    # replay and rejected, so a single state can never authenticate two sessions.
    claimed = (
        db.query(models.SsoState)
        .filter(
            models.SsoState.state_id == state_id,
            models.SsoState.consumed.is_(False),
        )
        .update({"consumed": True}, synchronize_session=False)
    )
    if not claimed:
        return "invalid", None
    return "ok", rec


def list_user_orgs(db: Session, user: models.User) -> list[models.Organization]:
    rows = db.scalars(
        select(models.Organization)
        .join(models.Membership, models.Membership.org_id == models.Organization.id)
        .where(models.Membership.user_id == user.id)
        .order_by(models.Organization.id)
    ).all()
    return list(rows)


def list_user_memberships(db: Session, user: models.User) -> list[models.Membership]:
    rows = db.scalars(
        select(models.Membership)
        .where(models.Membership.user_id == user.id)
        .order_by(models.Membership.id)
    ).all()
    return list(rows)


def get_membership(db: Session, user_id: int, org_id: int) -> models.Membership | None:
    return db.scalar(
        select(models.Membership).where(
            models.Membership.user_id == user_id,
            models.Membership.org_id == org_id,
        )
    )


def create_user_with_org(
    db: Session,
    email: str,
    password: str,
    full_name: str = "",
    org_name: str | None = None,
) -> tuple[models.User, models.Organization, models.Workspace]:
    """Create a User + Organization + owner Membership + default Workspace.

    Returns ``(user, org, workspace)``. The caller commits.
    """
    email = email.lower().strip()
    user = models.User(
        email=email,
        password_hash=security.hash_password(password),
        full_name=full_name or "",
    )
    org_display = (org_name or "").strip() or (
        f"{full_name.strip()}'s Org" if full_name.strip() else email.split("@")[0]
    )
    org = models.Organization(
        name=org_display,
        slug=_unique_org_slug(db, org_display),
    )
    db.add(user)
    db.add(org)
    db.flush()  # assign ids

    membership = models.Membership(user_id=user.id, org_id=org.id, role="owner")
    workspace = models.Workspace(
        org_id=org.id,
        name="Default Engagement",
        slug="default-engagement",
        description="Auto-created workspace",
        scope=[],
    )
    db.add(membership)
    db.add(workspace)
    db.flush()
    return user, org, workspace


# --------------------------------------------------------------------------- #
# Organizations / workspaces
# --------------------------------------------------------------------------- #
def create_org(db: Session, user: models.User, name: str) -> models.Organization:
    """Create a new organization owned by ``user`` with a default workspace."""
    org = models.Organization(name=name, slug=_unique_org_slug(db, name))
    db.add(org)
    db.flush()
    db.add(models.Membership(user_id=user.id, org_id=org.id, role="owner"))
    db.add(
        models.Workspace(
            org_id=org.id,
            name="Default Engagement",
            slug="default-engagement",
            description="Auto-created workspace",
            scope=[],
        )
    )
    db.flush()
    return org


def get_org(db: Session, org_id: int) -> models.Organization | None:
    return db.get(models.Organization, org_id)


def default_workspace_id_for_org(db: Session, org_id: int) -> int | None:
    """Return the id of the org's oldest workspace, or None if it has none."""
    return db.scalar(
        select(models.Workspace.id)
        .where(models.Workspace.org_id == org_id)
        .order_by(models.Workspace.id)
        .limit(1)
    )


def create_workspace(
    db: Session, org_id: int, name: str, description: str = "", scope: list | None = None
) -> models.Workspace:
    ws = models.Workspace(
        org_id=org_id,
        name=name,
        slug=slugify(name),
        description=description or "",
        scope=scope or [],
    )
    db.add(ws)
    db.flush()
    return ws


def get_workspace(db: Session, ws_id: int) -> models.Workspace | None:
    return db.get(models.Workspace, ws_id)


def list_workspaces(db: Session, org_id: int) -> list[models.Workspace]:
    rows = db.scalars(
        select(models.Workspace)
        .where(models.Workspace.org_id == org_id)
        .order_by(models.Workspace.id.desc())
    ).all()
    return list(rows)


def workspace_summary(db: Session, ws: models.Workspace) -> dict[str, Any]:
    """Attach ``scan_count``/``finding_count``/``severity_counts`` to a workspace.

    Mirrors the original ``db._project_with_summary`` but for workspaces.
    Returns a plain dict suitable for feeding ``WorkspaceOut.model_validate``.
    """
    scan_count = db.scalar(
        select(func.count(models.Scan.id)).where(models.Scan.workspace_id == ws.id)
    ) or 0
    sev_rows = db.execute(
        select(models.Finding.severity, func.count(models.Finding.id))
        .where(models.Finding.workspace_id == ws.id)
        .group_by(models.Finding.severity)
    ).all()
    severity_counts = {sev: n for sev, n in sev_rows}
    return {
        "id": ws.id,
        "org_id": ws.org_id,
        "name": ws.name,
        "slug": ws.slug,
        "description": ws.description,
        "scope": ws.scope or [],
        "created_at": ws.created_at,
        "scan_count": scan_count,
        "finding_count": sum(severity_counts.values()),
        "severity_counts": severity_counts,
    }


def update_scope(db: Session, ws: models.Workspace, scope: list) -> models.Workspace:
    ws.scope = scope or []
    db.add(ws)
    db.flush()
    return ws


def delete_workspace(db: Session, ws: models.Workspace) -> None:
    db.delete(ws)
    db.flush()


# --------------------------------------------------------------------------- #
# API keys
# --------------------------------------------------------------------------- #
def create_api_key(
    db: Session, org_id: int, name: str, created_by: int | None
) -> tuple[models.ApiKey, str]:
    """Create an API key; returns ``(api_key_row, full_key)`` (key shown once)."""
    full_key, prefix, key_hash = security.new_api_key()
    row = models.ApiKey(
        org_id=org_id,
        name=name,
        prefix=prefix,
        key_hash=key_hash,
        created_by=created_by,
    )
    db.add(row)
    db.flush()
    return row, full_key


def list_api_keys(db: Session, org_id: int) -> list[models.ApiKey]:
    rows = db.scalars(
        select(models.ApiKey)
        .where(models.ApiKey.org_id == org_id)
        .order_by(models.ApiKey.id.desc())
    ).all()
    return list(rows)


def resolve_api_key(db: Session, full_key: str) -> models.ApiKey | None:
    """Look up a non-revoked API key by its prefix and verify its secret."""
    prefix = security.api_key_prefix(full_key)
    if not prefix:
        return None
    candidates = db.scalars(
        select(models.ApiKey).where(
            models.ApiKey.prefix == prefix, models.ApiKey.revoked.is_(False)
        )
    ).all()
    for row in candidates:
        if security.verify_api_key(full_key, row.key_hash):
            row.last_used_at = _now()
            db.add(row)
            db.flush()
            return row
    return None


# --------------------------------------------------------------------------- #
# Assets
# --------------------------------------------------------------------------- #
def create_asset(
    db: Session, workspace_id: int, value: str, atype: str = "domain"
) -> models.Asset:
    asset = models.Asset(
        workspace_id=workspace_id,
        value=value.lower().strip(),
        atype=atype,
        verification_token=secrets.token_hex(16),
    )
    db.add(asset)
    db.flush()
    return asset


def list_assets(db: Session, workspace_id: int) -> list[models.Asset]:
    rows = db.scalars(
        select(models.Asset)
        .where(models.Asset.workspace_id == workspace_id)
        .order_by(models.Asset.id.desc())
    ).all()
    return list(rows)


def get_asset(db: Session, asset_id: int) -> models.Asset | None:
    return db.get(models.Asset, asset_id)


def mark_asset_verified(db: Session, asset: models.Asset) -> models.Asset:
    asset.verified = True
    asset.verified_at = _now()
    db.add(asset)
    db.flush()
    return asset


# --------------------------------------------------------------------------- #
# Scans + findings
# --------------------------------------------------------------------------- #
def redact_scan_options(options):
    """Return a copy of a scan's ``options`` with secret auth VALUES masked.

    A completed scan never needs its credential back, so — unlike the connector
    pattern (store raw, mask on read) — the secret is masked at WRITE time: the
    stored value is already safe, so it cannot leak via the ScanOut API, reports,
    or a raw DB read. Non-secret options (scan_type, selectors, login_url, …) are
    preserved. Shares :data:`app.secretbox.SECRET_OPTION_KEYS` with the schedule
    at-rest encryption so the two paths can never disagree on what is secret.
    """
    return secretbox.mask_options(options)


def save_scan(db: Session, record: dict) -> models.Scan:
    """Persist a completed scan and derive its findings.

    ``record`` keys mirror the original ``db.save_scan`` contract plus
    ``workspace_id`` and optional ``created_by``. The caller commits. Secret auth
    values in ``options`` are masked at this single write boundary
    (:func:`redact_scan_options`) so credentials never reach the DB.
    """
    started_dt = _coerce_dt(record.get("started_at"))
    finished_dt = _coerce_dt(record.get("finished_at"))
    # Derive the elapsed seconds from the timestamps when the caller didn't
    # supply a duration (the REST/WS/queue paths don't), so History and the
    # report show a real runtime instead of 0.0s.
    duration = record.get("duration", 0) or 0
    if not duration and started_dt and finished_dt:
        try:
            duration = max(0.0, (finished_dt - started_dt).total_seconds())
        except TypeError:
            duration = 0
    scan = models.Scan(
        workspace_id=record["workspace_id"],
        created_by=record.get("created_by"),
        tool=record.get("tool"),
        target=record.get("target"),
        status=record.get("status"),
        options=redact_scan_options(record.get("options")),
        logs=record.get("logs") or [],
        result=record.get("result"),
        error=record.get("error"),
        started_at=started_dt,
        finished_at=finished_dt,
        duration=duration,
    )
    db.add(scan)
    db.flush()  # assign scan.id

    tool = record.get("tool")
    ws_id = record["workspace_id"]
    # Track keys created in THIS call so two identical findings in one scan also
    # dedup against each other (not just against previously-persisted rows).
    local: dict[str, models.Finding] = {}
    for f in derive_findings(tool, record.get("result")):
        # P0-7: normalize severity at the single write boundary so the DB only
        # ever stores a canonical value (critical|high|medium|low|info). When the
        # scanner's value was NOT already a known severity, preserve the ORIGINAL
        # in evidence.raw_severity — never silently discard a scanner's own label.
        _raw_sev = f.get("severity")
        if not is_known_severity(_raw_sev):
            _ev = dict(f.get("evidence") or {})
            _ev.setdefault("raw_severity", _raw_sev)
            f["evidence"] = _ev
        f["severity"] = normalize_severity(_raw_sev)

        # STEP 4: clamp the attacker-influenced fields to their column widths so an
        # over-long scanner value can't raise a Postgres DataError at flush and
        # lose the whole completed scan (see :func:`_clamp`).
        f["name"] = _clamp(f.get("name"), 500)
        f["location"] = _clamp(f.get("location"), 1000)

        # Purple-Team P1: tag the finding with its MITRE ATT&CK technique/tactic.
        # ``map_finding`` returns None when the tool has no sensible mapping, in
        # which case both columns stay NULL (the finding renders as "unmapped").
        # STEP 4: never let a mapper error abort the whole scan's findings —
        # degrade this one finding to "unmapped" and keep going.
        try:
            mapping = attack.map_finding(tool or "", f) or {}
        except Exception as exc:  # noqa: BLE001 - resilience: one finding must not DoS the scan
            logger.warning("save_scan: ATT&CK mapping failed (tool=%s): %s", tool, exc)
            mapping = {}
        key = _dedupe_key(tool or "", f["name"], f["location"], f.get("cwe"))
        existing = local.get(key) or db.scalar(
            select(models.Finding).where(
                models.Finding.workspace_id == ws_id,
                models.Finding.dedupe_key == key,
            )
        )
        if existing is not None:
            # Re-observed the same issue: merge rather than duplicate. Keep the
            # strongest severity/tier/confidence, refresh evidence + scan link,
            # and PRESERVE any analyst triage decision (never reopen a finding a
            # human marked false_positive/resolved).
            existing.seen_count = (existing.seen_count or 1) + 1
            existing.scan_id = scan.id
            if _SEV_RANK.get(f["severity"], 5) < _SEV_RANK.get(existing.severity, 5):
                existing.severity = f["severity"]
            if _TIER_RANK.get(f.get("detection_tier"), 0) > _TIER_RANK.get(
                existing.detection_tier, 0
            ):
                existing.detection_tier = f.get("detection_tier")
            existing.confidence = max(
                int(existing.confidence or 0), int(f.get("confidence", 50))
            )
            if f.get("evidence"):
                existing.evidence = f["evidence"]
            if f.get("cvss") is not None:
                existing.cvss = (
                    f["cvss"] if existing.cvss is None
                    else max(existing.cvss, f["cvss"])
                )
            db.add(existing)
            continue
        finding = models.Finding(
            scan_id=scan.id,
            workspace_id=ws_id,
            source=tool or "",
            severity=f["severity"],
            name=f["name"],
            location=f["location"],
            description=f.get("description", ""),
            cve=f.get("cve") or [],
            cwe=f.get("cwe") or [],
            cvss=f.get("cvss"),
            status="open",
            technique_id=mapping.get("technique_id"),
            tactic=mapping.get("tactic"),
            detection_tier=f.get("detection_tier", "signal"),
            kind=f.get("kind", "vuln"),
            confidence=int(f.get("confidence", 50)),
            evidence=f.get("evidence") or {},
            dedupe_key=key,
            seen_count=1,
        )
        db.add(finding)
        local[key] = finding
    db.flush()
    return scan


def _coerce_dt(value: Any) -> datetime | None:
    """Accept ISO strings (legacy) or datetimes; return a datetime or None."""
    if value is None or isinstance(value, datetime):
        return value
    try:
        return datetime.fromisoformat(str(value))
    except ValueError:
        return None


def list_scans(db: Session, workspace_id: int, limit: int = 100) -> list[models.Scan]:
    rows = db.scalars(
        select(models.Scan)
        .where(models.Scan.workspace_id == workspace_id)
        .order_by(models.Scan.id.desc())
        .limit(limit)
    ).all()
    return list(rows)


def get_scan(db: Session, scan_id: int) -> models.Scan | None:
    return db.get(models.Scan, scan_id)


def delete_scan(db: Session, scan: models.Scan) -> None:
    """Delete a stored scan and any findings it produced. Caller commits."""
    db.query(models.Finding).filter(models.Finding.scan_id == scan.id).delete(
        synchronize_session=False
    )
    db.delete(scan)


def clear_workspace_scans(db: Session, workspace_id: int) -> int:
    """Delete ALL scans + findings for a workspace. Returns #scans removed. Caller commits."""
    n = (
        db.query(models.Scan)
        .filter(models.Scan.workspace_id == workspace_id)
        .count()
    )
    db.query(models.Finding).filter(
        models.Finding.workspace_id == workspace_id
    ).delete(synchronize_session=False)
    db.query(models.Scan).filter(
        models.Scan.workspace_id == workspace_id
    ).delete(synchronize_session=False)
    return n


def list_findings(db: Session, workspace_id: int) -> list[models.Finding]:
    """Return findings for a workspace, critical-first then newest-first."""
    rows = db.scalars(
        select(models.Finding).where(models.Finding.workspace_id == workspace_id)
    ).all()
    return sorted(rows, key=lambda f: (_SEV_RANK.get(f.severity, 5), -f.id))


def get_finding(db: Session, finding_id: int) -> models.Finding | None:
    return db.get(models.Finding, finding_id)


def attack_coverage(db: Session, workspace_id: int) -> dict[str, Any]:
    """Build a MITRE ATT&CK coverage matrix over a workspace's findings (P1).

    Groups every mapped finding in ``workspace_id`` by ATT&CK tactic, then by
    technique, counting findings and tallying their severities. Only tactics and
    techniques with at least one finding are included; findings with no ATT&CK
    mapping (NULL ``technique_id``) are skipped. Tactics are returned in the
    canonical ATT&CK kill-chain order (see :data:`app.attack.TACTICS`), and
    techniques within a tactic are ordered by descending finding count.

    Returns a dict shaped as::

        {
          "tactics": [
            {"tactic": <id>, "name": <display>, "techniques": [
              {"technique_id": <id>, "name": <display>, "count": <int>,
               "severities": {<severity>: <int>, ...}},
              ...
            ]},
            ...
          ],
          "total_techniques": <int>,   # distinct techniques with >=1 finding
          "total_findings": <int>,     # mapped findings counted
        }
    """
    rows = db.execute(
        select(
            models.Finding.tactic,
            models.Finding.technique_id,
            models.Finding.severity,
            func.count(models.Finding.id),
        )
        .where(
            models.Finding.workspace_id == workspace_id,
            models.Finding.technique_id.is_not(None),
        )
        .group_by(
            models.Finding.tactic,
            models.Finding.technique_id,
            models.Finding.severity,
        )
    ).all()

    # tactic id -> {technique_id -> {"count": int, "severities": {sev: n}}}
    tactics: dict[str, dict[str, dict[str, Any]]] = {}
    total_findings = 0
    for tactic, technique_id, severity, count in rows:
        # Resolve the tactic from the technique metadata when the stored value is
        # missing (defensive; both are written together in save_scan).
        tactic_id = tactic or attack.TECHNIQUES.get(technique_id, {}).get("tactic")
        if not technique_id or not tactic_id:
            continue
        techniques = tactics.setdefault(tactic_id, {})
        entry = techniques.setdefault(
            technique_id, {"count": 0, "severities": {}}
        )
        entry["count"] += count
        entry["severities"][severity] = entry["severities"].get(severity, 0) + count
        total_findings += count

    tactics_out: list[dict[str, Any]] = []
    total_techniques = 0
    for tactic_id in sorted(tactics, key=lambda t: attack.TACTIC_ORDER.get(t, 999)):
        techniques = tactics[tactic_id]
        total_techniques += len(techniques)
        techniques_out = [
            {
                "technique_id": tid,
                "name": attack.TECHNIQUES.get(tid, {}).get("name", tid),
                "count": data["count"],
                "severities": data["severities"],
            }
            for tid, data in techniques.items()
        ]
        # Most-evidenced techniques first, then by id for stable ordering.
        techniques_out.sort(key=lambda x: (-x["count"], x["technique_id"]))
        tactics_out.append(
            {
                "tactic": tactic_id,
                "name": attack.TACTIC_NAMES.get(tactic_id, tactic_id),
                "techniques": techniques_out,
            }
        )

    return {
        "tactics": tactics_out,
        "total_techniques": total_techniques,
        "total_findings": total_findings,
    }


def update_finding_status(
    db: Session, finding: models.Finding, status: str
) -> models.Finding:
    finding.status = status
    db.add(finding)
    db.flush()
    return finding


# --------------------------------------------------------------------------- #
# Asset-authorization gate (Phase 2)
# --------------------------------------------------------------------------- #
def is_target_authorized(db: Session, workspace_id: int, target: str) -> bool:
    """Return whether ``target`` may be scanned in ``workspace_id``.

    When ``settings.REQUIRE_VERIFIED_ASSET`` is ``False`` (the default) every
    target is authorized — this gate is a no-op and Phase 0/1 behavior is
    unchanged. When enabled, the target is authorized only if its host exactly
    matches, or is a subdomain of, a **verified** :class:`~app.models.Asset` in
    the workspace (case-insensitive suffix match). A target that expands to
    several hosts (a comma/space list) requires *every* host to be authorized.
    """
    from .config import settings  # local import: crud stays config-decoupled

    if not settings.REQUIRE_VERIFIED_ASSET:
        return True

    hosts = _target_hosts(target)
    if not hosts:
        return False

    verified_values = [
        (value or "").strip().lower()
        for value in db.scalars(
            select(models.Asset.value).where(
                models.Asset.workspace_id == workspace_id,
                models.Asset.verified.is_(True),
            )
        ).all()
    ]
    verified_values = [v for v in verified_values if v]
    if not verified_values:
        return False

    for host in hosts:
        if not any(
            host == value or host.endswith("." + value) for value in verified_values
        ):
            return False
    return True


def _target_hosts(target: str) -> list[str]:
    """Reduce a raw target (possibly a list) to bare, lower-cased hosts."""
    raw = (target or "").strip().lower()
    hosts: list[str] = []
    for item in re.split(r"[\s,]+", raw):
        if not item:
            continue
        item = re.sub(r"^[a-z][a-z0-9+.\-]*://", "", item)
        item = item.split("/")[0]
        if item.count(":") == 1:  # host:port (leave bare IPv6 literals intact)
            item = item.split(":")[0]
        item = item.strip()
        if item:
            hosts.append(item)
    return hosts


# --------------------------------------------------------------------------- #
# Phase 4: schedules
# --------------------------------------------------------------------------- #
def _cron_field_matches(field: str, value: int, lo: int, hi: int) -> bool:
    """Return whether a single crontab ``field`` matches ``value``.

    Supports ``*``, comma-lists, ``a-b`` ranges, and ``*/n`` or ``a-b/n`` steps
    over the inclusive ``[lo, hi]`` domain. Unparseable fields are treated as a
    wildcard (fail-open) so a malformed cron never raises.
    """
    field = (field or "*").strip()
    for part in field.split(","):
        part = part.strip()
        step = 1
        if "/" in part:
            base, _, step_s = part.partition("/")
            try:
                step = max(1, int(step_s))
            except ValueError:
                step = 1
            part = base.strip() or "*"
        if part == "*":
            start, end = lo, hi
        elif "-" in part:
            a, _, b = part.partition("-")
            try:
                start, end = int(a), int(b)
            except ValueError:
                return True
        else:
            try:
                only = int(part)
            except ValueError:
                return True
            if only == value:
                return True
            continue
        if lo <= value <= hi and start <= value <= end and (value - start) % step == 0:
            return True
    return False


def cron_next(cron: str, after: datetime | None = None) -> datetime | None:
    """Compute the next UTC run time for a 5-field crontab ``cron`` after ``after``.

    Fields are ``minute hour day-of-month month day-of-week`` (Sunday = 0). The
    search is a bounded minute-by-minute scan over the next ~4 years; if no match
    is found (or the expression is malformed) ``None`` is returned so callers can
    fall back to "run now / recompute later" semantics.
    """
    from datetime import timedelta

    parts = (cron or "").split()
    if len(parts) != 5:
        return None
    minute_f, hour_f, dom_f, month_f, dow_f = parts

    base = (after or _now()).astimezone(timezone.utc).replace(second=0, microsecond=0)
    candidate = base + timedelta(minutes=1)
    # ~4 years of minutes is a generous upper bound for any valid cron.
    for _ in range(367 * 24 * 60 * 4):
        # cron day-of-week: Sunday=0 .. Saturday=6 (isoweekday() % 7 maps Sun 7->0).
        dow = candidate.isoweekday() % 7
        if (
            _cron_field_matches(minute_f, candidate.minute, 0, 59)
            and _cron_field_matches(hour_f, candidate.hour, 0, 23)
            and _cron_field_matches(dom_f, candidate.day, 1, 31)
            and _cron_field_matches(month_f, candidate.month, 1, 12)
            and _cron_field_matches(dow_f, dow, 0, 6)
        ):
            return candidate
        candidate += timedelta(minutes=1)
    return None


def create_schedule(
    db: Session,
    workspace_id: int,
    tool: str,
    target: str,
    cron: str,
    options: dict | None = None,
    enabled: bool = True,
    created_by: int | None = None,
    config: dict | None = None,
) -> models.Schedule:
    """Create a recurring schedule; ``next_run_at`` is derived from ``cron``.

    ``tool`` is either a scanner id (the worker enqueues a scan job) or the
    special value ``"purple"`` (the worker runs a full purple loop inline —
    emulate + validate — via :func:`app.purple.run_purple`). ``config`` carries
    purple-specific settings that don't belong in the scanner ``options`` blob,
    e.g. ``{"connector_id": <int>, "techniques": ["E1", ...]}``; it defaults to
    an empty object for ordinary scanner schedules.
    """
    sched = models.Schedule(
        workspace_id=workspace_id,
        tool=tool,
        target=target,
        cron=cron,
        # Encrypt credential-bearing option values at rest; a scheduled scan must
        # retain its session secret to re-run, so it is stored as ciphertext (not
        # masked) and decrypted in-memory only when the worker builds the job.
        options=secretbox.encrypt_options(options or {}),
        config=config or {},
        enabled=enabled,
        created_by=created_by,
        next_run_at=cron_next(cron),
    )
    db.add(sched)
    db.flush()
    return sched


def list_schedules(db: Session, workspace_id: int) -> list[models.Schedule]:
    rows = db.scalars(
        select(models.Schedule)
        .where(models.Schedule.workspace_id == workspace_id)
        .order_by(models.Schedule.id.desc())
    ).all()
    return list(rows)


def get_schedule(db: Session, schedule_id: int) -> models.Schedule | None:
    return db.get(models.Schedule, schedule_id)


def delete_schedule(db: Session, schedule: models.Schedule) -> None:
    db.delete(schedule)
    db.flush()


def set_schedule_enabled(
    db: Session, schedule: models.Schedule, enabled: bool
) -> models.Schedule:
    schedule.enabled = enabled
    db.add(schedule)
    db.flush()
    return schedule


def due_schedules(db: Session, now_iso: str | datetime | None = None) -> list[models.Schedule]:
    """Return enabled schedules that are due (``next_run_at`` <= now or NULL)."""
    now = _coerce_dt(now_iso) if now_iso is not None else _now()
    if now is None:
        now = _now()
    rows = db.scalars(
        select(models.Schedule)
        .where(
            models.Schedule.enabled.is_(True),
            (models.Schedule.next_run_at.is_(None))
            | (models.Schedule.next_run_at <= now),
        )
        .order_by(models.Schedule.id)
    ).all()
    return list(rows)


# --------------------------------------------------------------------------- #
# Phase 4: notification channels
# --------------------------------------------------------------------------- #
def create_channel(
    db: Session,
    org_id: int,
    ctype: str,
    config: dict | None = None,
    events: list | None = None,
    enabled: bool = True,
) -> models.NotificationChannel:
    channel = models.NotificationChannel(
        org_id=org_id,
        ctype=ctype,
        config=config or {},
        events=events or ["new_finding"],
        enabled=enabled,
    )
    db.add(channel)
    db.flush()
    return channel


def list_channels(db: Session, org_id: int) -> list[models.NotificationChannel]:
    rows = db.scalars(
        select(models.NotificationChannel)
        .where(models.NotificationChannel.org_id == org_id)
        .order_by(models.NotificationChannel.id.desc())
    ).all()
    return list(rows)


def delete_channel(db: Session, channel: models.NotificationChannel) -> None:
    db.delete(channel)
    db.flush()


# --------------------------------------------------------------------------- #
# Phase 4: triage results + scan diffing support
# --------------------------------------------------------------------------- #
def save_triage(
    db: Session,
    workspace_id: int,
    created_by: int | None,
    model: str,
    triage_dict: dict,
) -> models.TriageResult:
    """Persist a structured AI-triage payload for a workspace.

    ``triage_dict`` is the ``TriageOut``-shaped dict (typically
    ``ai.triage_findings(...)["result"]``); its ``summary``/``risk_narrative``
    headline fields are copied to dedicated columns for cheap listing.
    """
    triage = models.TriageResult(
        workspace_id=workspace_id,
        created_by=created_by,
        model=model or "",
        summary=(triage_dict or {}).get("summary", "") or "",
        risk_narrative=(triage_dict or {}).get("risk_narrative", "") or "",
        data=triage_dict or {},
    )
    db.add(triage)
    db.flush()
    return triage


def latest_triage(db: Session, workspace_id: int) -> models.TriageResult | None:
    return db.scalar(
        select(models.TriageResult)
        .where(models.TriageResult.workspace_id == workspace_id)
        .order_by(models.TriageResult.id.desc())
        .limit(1)
    )


def latest_two_scans(
    db: Session, workspace_id: int, tool: str, target: str
) -> tuple[models.Scan | None, models.Scan | None]:
    """Return ``(previous, current)`` — the two most recent matching scans.

    Used by the diffing layer to compare a target's latest scan against its
    predecessor. If fewer than two scans exist the missing slot is ``None``;
    ``current`` is always the most recent (or ``None`` when there are none).
    """
    rows = db.scalars(
        select(models.Scan)
        .where(
            models.Scan.workspace_id == workspace_id,
            models.Scan.tool == tool,
            models.Scan.target == target,
        )
        .order_by(models.Scan.id.desc())
        .limit(2)
    ).all()
    current = rows[0] if len(rows) >= 1 else None
    previous = rows[1] if len(rows) >= 2 else None
    return previous, current


# --------------------------------------------------------------------------- #
# Phase 3: billing — subscriptions, usage counters, licenses
# --------------------------------------------------------------------------- #
def get_subscription(db: Session, org_id: int) -> models.Subscription | None:
    """Return the org's :class:`~app.models.Subscription` row, or ``None``."""
    return db.scalar(
        select(models.Subscription).where(models.Subscription.org_id == org_id)
    )


def get_subscription_by_customer(
    db: Session, customer_id: str | None
) -> models.Subscription | None:
    """Return the subscription linked to a Stripe ``customer_id``, or ``None``."""
    if not customer_id:
        return None
    return db.scalar(
        select(models.Subscription).where(
            models.Subscription.customer_id == customer_id
        )
    )


def upsert_subscription(
    db: Session, org_id: int, **fields: Any
) -> models.Subscription:
    """Create or update the org's subscription with the given ``fields``.

    Only keys that map to real ``Subscription`` columns are applied; unknown
    keys and explicit ``None`` values are ignored (so a partial webhook update
    never clobbers existing data with nulls). The caller commits.
    """
    sub = get_subscription(db, org_id)
    if sub is None:
        sub = models.Subscription(org_id=org_id)
        db.add(sub)
    allowed = {
        "provider",
        "customer_id",
        "subscription_id",
        "plan",
        "status",
        "current_period_end",
        "seats",
    }
    for key, value in fields.items():
        if key in allowed and value is not None:
            setattr(sub, key, value)
    db.flush()
    return sub


def count_org_scans_this_month(db: Session, org_id: int) -> int:
    """Count scans started in the current calendar month across the org.

    Joins ``scans`` to ``workspaces`` on ``workspace.org_id == org_id`` and
    filters ``started_at`` into the ``[month_start, now]`` window. Scans with a
    NULL ``started_at`` are not counted toward the period.
    """
    now = _now()
    month_start = now.replace(
        day=1, hour=0, minute=0, second=0, microsecond=0
    )
    return db.scalar(
        select(func.count(models.Scan.id))
        .join(models.Workspace, models.Workspace.id == models.Scan.workspace_id)
        .where(
            models.Workspace.org_id == org_id,
            models.Scan.started_at.is_not(None),
            models.Scan.started_at >= month_start,
        )
    ) or 0


def count_org_assets(db: Session, org_id: int) -> int:
    """Count assets across all of the org's workspaces."""
    return db.scalar(
        select(func.count(models.Asset.id))
        .join(models.Workspace, models.Workspace.id == models.Asset.workspace_id)
        .where(models.Workspace.org_id == org_id)
    ) or 0


def count_org_seats(db: Session, org_id: int) -> int:
    """Count seats (memberships) in the org."""
    return db.scalar(
        select(func.count(models.Membership.id)).where(
            models.Membership.org_id == org_id
        )
    ) or 0


def save_license(
    db: Session,
    org_id: int | None,
    key_id: str,
    tier: str,
    entitlements: dict,
    expires_at: datetime | None,
) -> models.License:
    """Create or update a :class:`~app.models.License` row keyed by ``key_id``.

    Records the decoded entitlements of an installed license token so it can be
    audited/revoked. Upserts on the unique ``key_id`` (the token's ``jti``). The
    caller commits.
    """
    lic = db.scalar(
        select(models.License).where(models.License.key_id == key_id)
    )
    if lic is None:
        lic = models.License(key_id=key_id)
        db.add(lic)
    lic.org_id = org_id
    lic.tier = tier or "free"
    lic.entitlements = entitlements or {}
    lic.expires_at = expires_at
    db.flush()
    return lic


def get_org_license(db: Session, org_id: int) -> models.License | None:
    """Return the org's most recent non-revoked license, or ``None``."""
    return db.scalar(
        select(models.License)
        .where(
            models.License.org_id == org_id,
            models.License.revoked.is_(False),
        )
        .order_by(models.License.id.desc())
        .limit(1)
    )


# --------------------------------------------------------------------------- #
# Audit
# --------------------------------------------------------------------------- #
def audit(
    db: Session,
    org_id: int | None,
    user_id: int | None,
    action: str,
    detail: str = "",
) -> None:
    db.add(
        models.AuditLog(org_id=org_id, user_id=user_id, action=action, detail=detail)
    )
    db.flush()


# --------------------------------------------------------------------------- #
# Phase 5: SSO config, org branding, token revocation, audit, GDPR export,
# retention purge. Everything here is append-only and gated by its caller so the
# verified Phase 0-4 flows (and the existing test suite) are unaffected.
# --------------------------------------------------------------------------- #
def get_org_by_slug(db: Session, slug: str) -> models.Organization | None:
    """Return the organization with the given ``slug``, or ``None``."""
    return db.scalar(
        select(models.Organization).where(
            models.Organization.slug == (slug or "").strip().lower()
        )
    )


def get_sso_config(db: Session, org_id: int) -> models.SsoConfig | None:
    """Return the org's :class:`~app.models.SsoConfig` row, or ``None``."""
    return db.scalar(
        select(models.SsoConfig).where(models.SsoConfig.org_id == org_id)
    )


def upsert_sso_config(db: Session, org_id: int, **fields: Any) -> models.SsoConfig:
    """Create or update the org's SSO configuration with ``fields``.

    Only keys mapping to real ``SsoConfig`` columns are applied; unknown keys
    are ignored. Unlike a webhook upsert, explicit values (including empty
    strings) *are* written so an admin can clear a field — but ``None`` values
    are skipped so a partial update never nulls unrelated columns. The caller
    commits.
    """
    cfg = get_sso_config(db, org_id)
    if cfg is None:
        cfg = models.SsoConfig(org_id=org_id)
        db.add(cfg)
    allowed = {
        "provider",
        "issuer",
        "discovery_url",
        "client_id",
        "client_secret",
        "saml_metadata",
        "x509_cert",
        "enabled",
    }
    for key, value in fields.items():
        if key in allowed and value is not None:
            setattr(cfg, key, value)
    db.flush()
    return cfg


def set_org_branding(db: Session, org_id: int, **fields: Any) -> models.Organization | None:
    """Apply white-label branding fields to an organization.

    Recognized keys: ``brand_name``, ``brand_primary_color``, ``brand_logo_url``,
    ``report_footer``, ``sso_default_role``. ``None`` values are skipped (so a
    partial update leaves other fields intact); pass an empty string to clear a
    field. Returns the org, or ``None`` when it does not exist. The caller commits.
    """
    org = get_org(db, org_id)
    if org is None:
        return None
    allowed = {
        "brand_name",
        "brand_primary_color",
        "brand_logo_url",
        "report_footer",
        "sso_default_role",
    }
    for key, value in fields.items():
        if key in allowed and value is not None:
            setattr(org, key, value)
    db.flush()
    return org


def org_branding(org: models.Organization | None) -> dict[str, Any]:
    """Return an org's branding as a plain dict for :func:`app.report.generate`.

    Keys mirror the branding columns. Returns an empty dict when ``org`` is
    ``None`` or carries no branding, so callers can pass the result straight to
    the report generator (which treats an empty/None dict as "use defaults").
    """
    if org is None:
        return {}
    data = {
        "brand_name": getattr(org, "brand_name", None),
        "brand_primary_color": getattr(org, "brand_primary_color", None),
        "brand_logo_url": getattr(org, "brand_logo_url", None),
        "report_footer": getattr(org, "report_footer", None),
    }
    return {k: v for k, v in data.items() if v}


def bump_token_version(db: Session, user: models.User) -> int:
    """Increment a user's ``token_version`` to revoke all versioned sessions.

    Returns the new version. Tokens that carry the old ``"ver"`` claim will fail
    the check in :func:`app.deps.get_current_user`; tokens without a ``"ver"``
    claim are unaffected (backward compatible). The caller commits.
    """
    user.token_version = int(getattr(user, "token_version", 0) or 0) + 1
    db.add(user)
    db.flush()
    return user.token_version


def list_audit(db: Session, org_id: int, limit: int = 200) -> list[models.AuditLog]:
    """Return an org's most recent audit-log entries (newest first)."""
    rows = db.scalars(
        select(models.AuditLog)
        .where(models.AuditLog.org_id == org_id)
        .order_by(models.AuditLog.id.desc())
        .limit(limit)
    ).all()
    return list(rows)


def export_org_data(db: Session, org_id: int) -> dict[str, Any]:
    """Produce a GDPR-style JSON-serializable export of an org's data.

    Includes the organization, its members (email/role), workspaces, per-scan
    metadata (no raw logs/results blob to keep the export lean), findings, and
    assets. Timestamps are emitted as ISO-8601 strings. Returns an empty dict
    when the org does not exist.
    """
    org = get_org(db, org_id)
    if org is None:
        return {}

    def _iso(value: datetime | None) -> str | None:
        return value.isoformat() if isinstance(value, datetime) else None

    # Members (join membership -> user for email/name).
    member_rows = db.execute(
        select(models.Membership, models.User)
        .join(models.User, models.User.id == models.Membership.user_id)
        .where(models.Membership.org_id == org_id)
        .order_by(models.Membership.id)
    ).all()
    members = [
        {
            "user_id": m.user_id,
            "email": u.email,
            "full_name": u.full_name,
            "role": m.role,
            "joined_at": _iso(m.created_at),
        }
        for m, u in member_rows
    ]

    workspaces_out: list[dict[str, Any]] = []
    for ws in list_workspaces(db, org_id):
        scans = list_scans(db, ws.id, limit=100000)
        findings = list_findings(db, ws.id)
        assets = list_assets(db, ws.id)
        workspaces_out.append(
            {
                "id": ws.id,
                "name": ws.name,
                "slug": ws.slug,
                "description": ws.description,
                "scope": ws.scope or [],
                "created_at": _iso(ws.created_at),
                "assets": [
                    {
                        "id": a.id,
                        "value": a.value,
                        "atype": a.atype,
                        "verified": a.verified,
                        "verified_at": _iso(a.verified_at),
                        "created_at": _iso(a.created_at),
                    }
                    for a in assets
                ],
                "scans": [
                    {
                        "id": s.id,
                        "tool": s.tool,
                        "target": s.target,
                        "status": s.status,
                        "started_at": _iso(s.started_at),
                        "finished_at": _iso(s.finished_at),
                        "duration": s.duration,
                        "created_by": s.created_by,
                    }
                    for s in scans
                ],
                "findings": [
                    {
                        "id": f.id,
                        "scan_id": f.scan_id,
                        "source": f.source,
                        "severity": f.severity,
                        "name": f.name,
                        "location": f.location,
                        "description": f.description,
                        "cve": f.cve or [],
                        "cwe": f.cwe or [],
                        "cvss": f.cvss,
                        "status": f.status,
                        "created_at": _iso(f.created_at),
                    }
                    for f in findings
                ],
            }
        )

    return {
        "organization": {
            "id": org.id,
            "name": org.name,
            "slug": org.slug,
            "plan": org.plan,
            "license_tier": org.license_tier,
            "created_at": _iso(org.created_at),
        },
        "members": members,
        "workspaces": workspaces_out,
        "exported_at": _now().isoformat(),
    }


def purge_old_scans(db: Session, org_id: int, older_than_days: int) -> int:
    """Delete scans (and their cascaded findings) older than a retention window.

    Scans whose ``started_at`` (falling back to ``created_at`` semantics via
    ``started_at``) is older than ``older_than_days`` across all of the org's
    workspaces are deleted. ``older_than_days <= 0`` is a no-op (keep forever)
    and returns ``0``. Returns the number of scans deleted. The caller commits.
    """
    if not older_than_days or older_than_days <= 0:
        return 0

    from datetime import timedelta

    cutoff = _now() - timedelta(days=int(older_than_days))
    scans = db.scalars(
        select(models.Scan)
        .join(models.Workspace, models.Workspace.id == models.Scan.workspace_id)
        .where(
            models.Workspace.org_id == org_id,
            models.Scan.started_at.is_not(None),
            models.Scan.started_at < cutoff,
        )
    ).all()
    count = 0
    for scan in scans:
        db.delete(scan)  # findings cascade via the ORM relationship
        count += 1
    db.flush()
    return count


# --------------------------------------------------------------------------- #
# P0: automated pentest runs
# --------------------------------------------------------------------------- #
def create_pentest_run(
    db: Session,
    workspace_id: int,
    created_by: int | None,
    target: str,
) -> models.PentestRun:
    """Create a ``PentestRun`` envelope in the ``running`` state.

    Called at the start of an auto-pentest pipeline. ``started_at`` is stamped
    now; the aggregate risk/summary are filled in later by
    :func:`finish_pentest_run`. The caller commits.
    """
    run = models.PentestRun(
        workspace_id=workspace_id,
        created_by=created_by,
        target=target,
        status="running",
        risk_score=0,
        risk_label="",
        summary={},
        started_at=_now(),
    )
    db.add(run)
    db.flush()  # assign run.id
    return run


def finish_pentest_run(
    db: Session,
    run: models.PentestRun,
    status: str,
    risk_score: int,
    risk_label: str,
    summary: dict,
) -> models.PentestRun:
    """Finalize a ``PentestRun`` with its terminal status and aggregate risk.

    Sets ``finished_at`` to now and records the final ``risk_score`` /
    ``risk_label`` / ``summary`` produced by the pipeline's ``pipeline_done``
    event. The caller commits.
    """
    run.status = status or "done"
    run.risk_score = int(risk_score or 0)
    run.risk_label = risk_label or ""
    run.summary = summary or {}
    run.finished_at = _now()
    db.add(run)
    db.flush()
    return run


def reconcile_stale_pentest_runs(db: Session, older_than_seconds: int) -> int:
    """Mark orphaned ``running`` pentest runs terminal (startup reconciliation).

    A :class:`~app.models.PentestRun` is committed ``running`` when the pipeline
    starts and only finalized in a ``finally`` block. A HARD process death
    (SIGKILL / OOM / container redeploy) skips that finally, stranding the row
    ``running`` forever. This one-shot sweep marks such rows ``interrupted`` — but
    ONLY those whose ``started_at`` is older than ``older_than_seconds`` (chosen
    well beyond a run's max wall clock), so it can never touch a pipeline a sibling
    process is legitimately still streaming. The write is idempotent, so multiple
    workers running it concurrently at boot race harmlessly. Returns the count.
    """
    cutoff = _now() - timedelta(seconds=int(older_than_seconds))
    reconciled = 0
    for run in (
        db.query(models.PentestRun)
        .filter(models.PentestRun.status == "running")
        .all()
    ):
        started = run.started_at
        if started is None:
            continue
        if started.tzinfo is None:  # SQLite reads timestamps back naive
            started = started.replace(tzinfo=timezone.utc)
        if started < cutoff:
            run.status = "interrupted"
            run.finished_at = _now()
            db.add(run)
            reconciled += 1
    if reconciled:
        db.commit()
        logger.info(
            "startup: reconciled %d stale 'running' pentest run(s) -> interrupted",
            reconciled,
        )
    return reconciled


def list_pentest_runs(
    db: Session, workspace_id: int, limit: int = 50
) -> list[models.PentestRun]:
    """Return a workspace's most recent pentest runs (newest first)."""
    rows = db.scalars(
        select(models.PentestRun)
        .where(models.PentestRun.workspace_id == workspace_id)
        .order_by(models.PentestRun.id.desc())
        .limit(limit)
    ).all()
    return list(rows)


def get_pentest_run(db: Session, run_id: int) -> models.PentestRun | None:
    """Return a single pentest run by id, or ``None``."""
    return db.get(models.PentestRun, run_id)


def delete_pentest_run(db: Session, run: models.PentestRun) -> None:
    """Delete an auto-pentest run summary envelope. Caller commits.

    Only removes the run's summary record; the per-stage scans it produced live
    in the ``scans`` table and are managed from the recon scan history.
    """
    db.delete(run)


# --------------------------------------------------------------------------- #
# Purple-Team P2: SAFE ATT&CK emulation runs + per-technique results.
# --------------------------------------------------------------------------- #
def create_emulation_run(
    db: Session,
    workspace_id: int,
    created_by: int | None,
    target: str,
) -> models.EmulationRun:
    """Create an :class:`~app.models.EmulationRun` in the ``running`` state.

    Called after the router has enforced scope + netguard + billing, at the start
    of a SAFE emulation. ``started_at`` is stamped now; the aggregate tallies and
    ``summary`` are filled in later by :func:`finish_emulation_run`. The caller
    commits.
    """
    run = models.EmulationRun(
        workspace_id=workspace_id,
        created_by=created_by,
        target=target,
        status="running",
        executed=0,
        blocked=0,
        failed=0,
        summary={},
        started_at=_now(),
    )
    db.add(run)
    db.flush()  # assign run.id
    return run


def save_technique_result(
    db: Session, run_id: int, result: dict
) -> models.TechniqueResult:
    """Persist one emulated-technique outcome as a child of an emulation run.

    ``result`` is a single entry from :func:`app.emulation.run_emulation`'s
    ``results`` list (``{"technique_id","name","tactic","status","evidence",
    "detail", ...}``). The caller commits.
    """
    row = models.TechniqueResult(
        emulation_run_id=run_id,
        technique_id=result.get("technique_id", ""),
        technique_name=result.get("name", ""),
        tactic=result.get("tactic", ""),
        status=result.get("status", "failed"),
        evidence=result.get("evidence", "") or "",
        detail=result.get("detail", "") or "",
    )
    db.add(row)
    db.flush()
    return row


def finish_emulation_run(
    db: Session,
    run: models.EmulationRun,
    executed: int,
    blocked: int,
    failed: int,
    summary: dict,
) -> models.EmulationRun:
    """Finalize an :class:`~app.models.EmulationRun` with its tallies + summary.

    Sets ``status="done"`` and ``finished_at`` to now, and records the aggregate
    ``executed``/``blocked``/``failed`` counts plus the verbatim engine
    ``summary``. The caller commits.
    """
    run.executed = int(executed or 0)
    run.blocked = int(blocked or 0)
    run.failed = int(failed or 0)
    run.summary = summary or {}
    run.status = "done"
    run.finished_at = _now()
    db.add(run)
    db.flush()
    return run


def list_emulation_runs(
    db: Session, workspace_id: int, limit: int = 50
) -> list[models.EmulationRun]:
    """Return a workspace's most recent emulation runs (newest first)."""
    rows = db.scalars(
        select(models.EmulationRun)
        .where(models.EmulationRun.workspace_id == workspace_id)
        .order_by(models.EmulationRun.id.desc())
        .limit(limit)
    ).all()
    return list(rows)


def get_emulation_run(db: Session, run_id: int) -> models.EmulationRun | None:
    """Return a single emulation run by id (with its ordered technique results).

    The ``technique_results`` relationship is ordered by id at the ORM level, so
    accessing ``run.technique_results`` yields them in execution order.
    """
    return db.get(models.EmulationRun, run_id)


# --------------------------------------------------------------------------- #
# Purple-Team P3: detection connectors + correlated detection results.
# --------------------------------------------------------------------------- #
def create_detection_connector(
    db: Session,
    org_id: int,
    name: str,
    ctype: str,
    config: dict | None = None,
    enabled: bool = True,
) -> models.DetectionConnector:
    """Create an org-scoped :class:`~app.models.DetectionConnector`.

    ``ctype`` selects the connector implementation (validated by the router
    against :data:`app.connectors.CONNECTOR_TYPES`); ``config`` carries the
    type-specific settings and may contain secrets. The caller commits.
    """
    connector = models.DetectionConnector(
        org_id=org_id,
        name=name,
        ctype=ctype,
        config=config or {},
        enabled=enabled,
    )
    db.add(connector)
    db.flush()
    return connector


def list_detection_connectors(
    db: Session, org_id: int
) -> list[models.DetectionConnector]:
    """Return an org's detection connectors (newest first)."""
    rows = db.scalars(
        select(models.DetectionConnector)
        .where(models.DetectionConnector.org_id == org_id)
        .order_by(models.DetectionConnector.id.desc())
    ).all()
    return list(rows)


def get_detection_connector(
    db: Session, connector_id: int
) -> models.DetectionConnector | None:
    """Return a single detection connector by id, or ``None``."""
    return db.get(models.DetectionConnector, connector_id)


def default_detection_connector(
    db: Session, org_id: int
) -> models.DetectionConnector | None:
    """Return the org's *default* detection connector, or ``None``.

    The default is simply the oldest **enabled** connector (lowest id). Used by
    the scheduler (:func:`app.worker.check_schedules`) to resolve which connector
    a ``tool == "purple"`` schedule validates against when it doesn't name one
    explicitly in its ``config``.
    """
    return db.scalars(
        select(models.DetectionConnector)
        .where(
            models.DetectionConnector.org_id == org_id,
            models.DetectionConnector.enabled.is_(True),
        )
        .order_by(models.DetectionConnector.id)
        .limit(1)
    ).first()


def delete_detection_connector(
    db: Session, connector: models.DetectionConnector
) -> None:
    """Delete a detection connector.

    Historical :class:`~app.models.DetectionResult` rows survive: their
    ``connector_id`` FK is ``ON DELETE SET NULL``. The caller commits.
    """
    db.delete(connector)
    db.flush()


def save_detection_results(
    db: Session,
    run_id: int,
    connector_id: int | None,
    results: list[dict],
) -> list[models.DetectionResult]:
    """Persist correlated detection results for an emulation run.

    ``results`` is the per-technique list produced by
    :func:`app.detection.validate_emulation`. One
    :class:`~app.models.DetectionResult` row is written per entry. The caller
    commits.
    """
    rows: list[models.DetectionResult] = []
    for r in results or []:
        row = models.DetectionResult(
            emulation_run_id=run_id,
            connector_id=connector_id,
            technique_id=r.get("technique_id", "") or "",
            technique_name=r.get("technique_name", "") or "",
            tactic=r.get("tactic", "") or "",
            detected=bool(r.get("detected", False)),
            count=int(r.get("count", 0) or 0),
            source=r.get("source", "") or "",
            evidence=r.get("evidence", "") or "",
        )
        db.add(row)
        rows.append(row)
    db.flush()
    return rows


def list_detection_results(
    db: Session, run_id: int
) -> list[models.DetectionResult]:
    """Return the detection results recorded for an emulation run (in order)."""
    rows = db.scalars(
        select(models.DetectionResult)
        .where(models.DetectionResult.emulation_run_id == run_id)
        .order_by(models.DetectionResult.id)
    ).all()
    return list(rows)


# --------------------------------------------------------------------------- #
# Purple-Team P4: continuous-purple coverage dashboard.
# --------------------------------------------------------------------------- #
#: Emulated statuses that produced attributable telemetry (mirrors
#: :data:`app.detection._COUNTED_STATUSES`). Only these techniques are considered
#: "emulated" for coverage, so the dashboard's coverage math lines up with what
#: the detection engine actually scores.
_COVERAGE_COUNTED_STATUSES: frozenset[str] = frozenset({"executed", "blocked"})


def _iso_or_none(value: Any) -> str | None:
    """Render a datetime as an ISO-8601 string (pass through / None otherwise)."""
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, str):
        return value or None
    return None


def coverage_dashboard(db: Session, workspace_id: int) -> dict[str, Any]:
    """Build the continuous-purple detection-coverage dashboard for a workspace.

    Rolls every emulation run in ``workspace_id`` and its correlated detection
    results into the *current* posture — for each technique the latest run that
    emulated it and whether the SIEM/EDR has ever detected it — plus per-tactic
    rollups, a coverage trend, and the outstanding detection gaps.

    A technique counts as **emulated** only when it produced attributable
    telemetry (an ``executed``/``blocked`` :class:`~app.models.TechniqueResult`),
    matching the detection engine's scoring domain. Its ``detected`` verdict is
    the most recent :class:`~app.models.DetectionResult` for that technique, or
    ``None`` when it has never been validated.

    Returns a dict shaped as::

        {
          "summary": {"techniques_emulated", "detected", "missed",
                      "not_validated", "coverage_pct": int|None},
          "techniques": [{"technique_id","name","tactic","emulated","detected",
                          "last_run_id","last_at"}],   # latest per technique
          "tactics": [{"tactic","name","total","detected","missed"}],  # ATT&CK order
          "trend": [{"run_id","at","coverage_pct"}],   # runs with detections, last ~20
          "gaps": [{"technique_id","name","tactic"}],   # emulated but missed
        }

    ``coverage_pct`` (summary and trend) is a whole-percent integer over the
    *validated* techniques (detected + missed); the summary value is ``None`` when
    nothing has been validated yet.
    """
    # --- Emulated techniques (counted statuses only), joined to their runs. --- #
    tr_rows = db.execute(
        select(
            models.EmulationRun.id,
            models.EmulationRun.started_at,
            models.EmulationRun.finished_at,
            models.TechniqueResult.technique_id,
            models.TechniqueResult.technique_name,
            models.TechniqueResult.tactic,
            models.TechniqueResult.status,
        )
        .join(
            models.TechniqueResult,
            models.TechniqueResult.emulation_run_id == models.EmulationRun.id,
        )
        .where(models.EmulationRun.workspace_id == workspace_id)
        .order_by(models.EmulationRun.id)
    ).all()

    # --- Detection verdicts, joined to their runs (ordered so latest wins). --- #
    dr_rows = db.execute(
        select(
            models.EmulationRun.id,
            models.DetectionResult.technique_id,
            models.DetectionResult.detected,
        )
        .join(
            models.DetectionResult,
            models.DetectionResult.emulation_run_id == models.EmulationRun.id,
        )
        .where(models.EmulationRun.workspace_id == workspace_id)
        .order_by(models.EmulationRun.id, models.DetectionResult.id)
    ).all()

    # Latest emulating run per technique (rows are ascending by run id, so the
    # last assignment for a technique is its most recent run).
    tech_latest: dict[str, dict[str, Any]] = {}
    run_at: dict[int, Any] = {}
    for run_id, started, finished, tid, tname, tactic, status in tr_rows:
        at = finished or started
        run_at[run_id] = at
        if status not in _COVERAGE_COUNTED_STATUSES or not tid:
            continue
        meta = attack.TECHNIQUES.get(tid, {})
        tech_latest[tid] = {
            "technique_id": tid,
            "name": meta.get("name") or tname or tid,
            "tactic": tactic or meta.get("tactic", ""),
            "last_run_id": run_id,
            "last_at": _iso_or_none(at),
        }

    # Latest detection verdict per technique + per-run detection tallies (trend).
    det_latest: dict[str, bool] = {}
    run_det: dict[int, dict[str, int]] = {}
    for run_id, tid, detected in dr_rows:
        det_latest[tid] = bool(detected)
        tally = run_det.setdefault(run_id, {"total": 0, "detected": 0})
        tally["total"] += 1
        if detected:
            tally["detected"] += 1

    # --- Per-technique current status. ------------------------------------- #
    techniques: list[dict[str, Any]] = []
    for tid, info in tech_latest.items():
        techniques.append({**info, "emulated": True, "detected": det_latest.get(tid)})
    techniques.sort(
        key=lambda t: (attack.TACTIC_ORDER.get(t["tactic"], 999), t["technique_id"])
    )

    detected = sum(1 for t in techniques if t["detected"] is True)
    missed = sum(1 for t in techniques if t["detected"] is False)
    not_validated = sum(1 for t in techniques if t["detected"] is None)
    validated = detected + missed
    coverage_pct = round(100 * detected / validated) if validated else None
    summary = {
        "techniques_emulated": len(techniques),
        "detected": detected,
        "missed": missed,
        "not_validated": not_validated,
        "coverage_pct": coverage_pct,
    }

    # --- Per-tactic rollup (ATT&CK kill-chain order). ---------------------- #
    tactics_map: dict[str, dict[str, int]] = {}
    for t in techniques:
        entry = tactics_map.setdefault(
            t["tactic"] or "", {"total": 0, "detected": 0, "missed": 0}
        )
        entry["total"] += 1
        if t["detected"] is True:
            entry["detected"] += 1
        elif t["detected"] is False:
            entry["missed"] += 1
    tactics = [
        {
            "tactic": tac,
            "name": attack.TACTIC_NAMES.get(tac, tac or "unmapped"),
            "total": v["total"],
            "detected": v["detected"],
            "missed": v["missed"],
        }
        for tac, v in tactics_map.items()
    ]
    tactics.sort(key=lambda x: attack.TACTIC_ORDER.get(x["tactic"], 999))

    # --- Coverage trend over runs that were validated (chronological). ----- #
    trend: list[dict[str, Any]] = []
    for run_id in sorted(run_det):
        tally = run_det[run_id]
        cov = round(100 * tally["detected"] / tally["total"]) if tally["total"] else 0
        trend.append(
            {
                "run_id": run_id,
                "at": _iso_or_none(run_at.get(run_id)),
                "coverage_pct": cov,
            }
        )
    trend = trend[-20:]

    # --- Detection gaps: emulated but definitively missed. ----------------- #
    gaps = [
        {"technique_id": t["technique_id"], "name": t["name"], "tactic": t["tactic"]}
        for t in techniques
        if t["detected"] is False
    ]

    return {
        "summary": summary,
        "techniques": techniques,
        "tactics": tactics,
        "trend": trend,
        "gaps": gaps,
    }


# --------------------------------------------------------------------------- #
# Finding derivation — turn raw scan results into normalized findings.
# Ported verbatim from the original backend/app/db.py.
# --------------------------------------------------------------------------- #
# --------------------------------------------------------------------------- #
# Finding derivation — SIGNAL vs VALIDATED classification + evidence & dedup.
#
# Every derived finding now carries four extra fields that the persistence layer
# stores on the Finding row:
#   * ``detection_tier`` — "signal" (a scanner reported a possible issue),
#     "validated" (the platform safely verified it and holds evidence), or
#     "exploited" (reserved for the human-approved P5 path; never set here);
#   * ``kind``          — "vuln" | "hardening" | "recon" | "info" so that
#     informational/recon/hardening signal never inflates the vuln risk score;
#   * ``confidence``    — 0-100, weighted into the risk score;
#   * ``evidence``      — source-specific supporting data, NEVER invented.
# --------------------------------------------------------------------------- #

# (detection_tier, kind, confidence) for tools whose scanner emits a normalized
# ``findings`` list (injection/webaudit/waf). Injection tool-confirms its vulns
# and webaudit confirms a misconfiguration on a real response, so both are
# "validated"; a WAF-effectiveness result is a hardening signal, not a vuln.
_GENERIC_META = {
    "injection": ("validated", "vuln", 90),
    "webaudit": ("validated", "vuln", 80),
    "waf": ("signal", "hardening", 60),
    "waf_test": ("signal", "hardening", 60),
}

# Keys a scanner's finding dict may carry that are worth keeping as evidence.
_EVIDENCE_KEYS = (
    "evidence", "poc", "payload", "parameter", "param", "place", "technique",
    "types", "dbms", "matched", "observed", "status", "category",
    "baseline_status", "url", "header", "cookie",
)


def _aslist(v) -> list:
    """Coerce a bare cve/cwe scalar to a list so it can never 500 serializers."""
    if not v:
        return []
    return list(v) if isinstance(v, (list, tuple)) else [str(v)]


def _norm_location(loc: str) -> str:
    """Normalize a finding location for stable dedup (lowercase, strip trailing /)."""
    s = (loc or "").strip().lower()
    if len(s) > 1 and s.endswith("/"):
        s = s.rstrip("/")
    return s


def _dedupe_key(source: str, name: str, location: str, cwe) -> str:
    """Stable identity for a finding, used to deduplicate repeated scans.

    Deliberately specific — includes the tool, the finding name (vuln type), the
    normalized location and the sorted CWE set — so genuinely *different*
    findings never collapse together. Two scans that re-observe the SAME issue at
    the SAME place produce the same key and are merged rather than duplicated.
    """
    cwe_part = ",".join(sorted(str(c) for c in (cwe or [])))
    raw = "|".join(
        [
            (source or "").strip().lower(),
            (name or "").strip().lower(),
            _norm_location(location),
            cwe_part,
        ]
    )
    return hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()[:32]


def _extract_evidence(f: dict) -> dict:
    """Pull the evidence-bearing keys a scanner already emits (never invents)."""
    ev: dict[str, Any] = {}
    for k in _EVIDENCE_KEYS:
        v = f.get(k)
        if v not in (None, "", [], {}):
            ev[k] = v
    nested = f.get("evidence")
    if isinstance(nested, dict):
        ev.update(nested)
    return ev


def _secret_severity(stype: str) -> str:
    """Rate an exposed-secret signal by its type (conservative: high only for
    clearly high-impact credential families)."""
    t = (stype or "").lower()
    if any(
        k in t
        for k in ("aws", "private_key", "private-key", "stripe", "gcp", "google",
                  "slack", "azure", "rsa")
    ):
        return "high"
    return "medium"


def _mk(
    severity, name, location, description, *, cve=None, cwe=None, cvss=None,
    tier="signal", kind="vuln", confidence=50, evidence=None, tags=None,
) -> dict:
    """Build a normalized finding dict carrying the new classification fields."""
    d = {
        "severity": severity or "info",
        "name": name or "finding",
        "location": location or "",
        "description": description or "",
        "cve": _aslist(cve),
        "cwe": _aslist(cwe),
        "cvss": cvss,
        "detection_tier": tier,
        "kind": kind,
        "confidence": int(confidence),
        "evidence": evidence or {},
    }
    if tags is not None:
        # Transient: consumed by attack.map_finding for ATT&CK mapping, not
        # persisted as a column.
        d["tags"] = tags
    return d


def derive_findings(tool: str, result) -> list[dict]:
    if not result:
        return []
    if tool == "nuclei":
        out = []
        for f in result.get("findings", []):
            # Preserve template metadata + request/response (when nuclei was run
            # with -irr) as evidence. Never invent — only keep what is present.
            ev = {
                "template_id": f.get("template_id"),
                "matched_at": f.get("matched_at"),
                "tags": f.get("tags"),
                "type": f.get("type"),
                "reference": f.get("reference"),
                "extracted": f.get("extracted"),
                "request": f.get("request"),
                "response": f.get("response"),
            }
            ev = {k: v for k, v in ev.items() if v}
            out.append(_mk(
                f.get("severity", "info"),
                f.get("name", f.get("template_id", "finding")),
                f.get("matched_at", ""),
                f.get("description", ""),
                cve=f.get("cve"), cwe=f.get("cwe"), cvss=f.get("cvss"),
                # A raw nuclei template match is a SIGNAL — unverified until the
                # (P1) safe-validation layer re-checks it.
                tier="signal", kind="vuln", confidence=50,
                evidence=ev, tags=f.get("tags"),
            ))
        return out
    if tool == "nmap":
        out = []
        host = result.get("host", "")
        for p in result.get("ports", []):
            if p.get("state") == "open":
                svc = p.get("service", "")
                product = p.get("product", "")
                version = p.get("version", "")
                ver = " ".join(x for x in [product, version] if x)
                port_ev = {
                    k: v for k, v in {
                        "host": host, "port": p.get("port"),
                        "protocol": p.get("protocol"), "service": svc,
                        "product": product, "version": version,
                        "cpe": p.get("cpe"), "state": p.get("state"),
                    }.items() if v not in (None, "")
                }
                out.append(_mk(
                    "info",
                    f"Open port {p.get('port')}/{p.get('protocol')} ({svc or 'unknown'})",
                    f"{host}:{p.get('port')}",
                    ver,
                    # An open port is a real observation but NOT a vulnerability —
                    # recon, so it does not inflate the vuln risk score.
                    tier="signal", kind="recon", confidence=100, evidence=port_ev,
                ))
                # Version -> known-CVE enrichment. Emits a vuln finding ONLY when
                # the detected version falls inside a known-affected range (a
                # strong SIGNAL, not a validated exploit). The nmap observation is
                # preserved as evidence.
                for hit in vulndb.match(product, version, p.get("cpe")):
                    out.append(_mk(
                        hit["severity"],
                        f"Potentially vulnerable {product} {version}: {hit['cve']}",
                        f"{host}:{p.get('port')}",
                        (f"nmap fingerprinted {product} {version} on "
                         f"{host}:{p.get('port')}. This version matches the affected "
                         f"range ({hit['affected_range']}) for {hit['cve']} — "
                         f"{hit['title']}. Version-based inference; confirm the exact "
                         "build before treating as exploitable."),
                        cve=[hit["cve"]], cwe=hit.get("cwe"), cvss=hit.get("cvss"),
                        tier="signal", kind="vuln", confidence=60,
                        evidence={
                            "component": product, "version": version,
                            "cpe": p.get("cpe"), "affected_range": hit["affected_range"],
                            "matched_product": hit["matched_product"],
                            "matched_via": "nmap-version",
                            "nmap_service": svc, "location": f"{host}:{p.get('port')}",
                        },
                    ))
        return out
    if tool == "dirbuster":
        out = []
        for r in result.get("rows", []):
            ev = {
                k: v for k, v in {
                    "status": r.get("status"), "size": r.get("size"),
                    "words": r.get("words"), "lines": r.get("lines"),
                    "url": r.get("url"),
                }.items() if v is not None
            }
            out.append(_mk(
                "info",
                f"Discovered path /{r.get('path')}",
                r.get("url", ""),
                f"HTTP {r.get('status')}",
                # A discovered path is informational, not a vulnerability.
                tier="signal", kind="info", confidence=80, evidence=ev,
            ))
        return out
    if tool in ("dns_zt", "dns_zone_transfer"):
        # A SUCCESSFUL AXFR is a genuinely VALIDATED finding: the transfer really
        # happened and the returned records are hard evidence. (Previously this
        # confirmed critical was silently dropped.)
        if not (isinstance(result, dict) and result.get("vulnerable")):
            return []
        domain = result.get("domain", "")
        nss = result.get("vulnerable_nameservers") or []
        records = result.get("records") or []
        rec_count = result.get("record_count", len(records))
        return [_mk(
            "high",
            "DNS zone transfer (AXFR) permitted",
            domain,
            (f"A full DNS zone transfer succeeded from "
             f"{', '.join(nss) or 'a nameserver'}, exposing {rec_count} record(s). "
             "This leaks internal hostnames and infrastructure layout."),
            cwe=["CWE-200"], tier="validated", kind="vuln", confidence=95,
            evidence={
                k: v for k, v in {
                    "vulnerable_nameservers": nss,
                    "record_count": rec_count,
                    "records": records[:50],  # cap embedded evidence
                }.items() if v
            },
        )]
    if tool == "takeover":
        # The scanner already classifies each finding's tier/confidence (validated
        # when a provider fingerprint matched, signal for a dangling CNAME), so
        # carry those per-finding values through rather than a fixed default.
        out = []
        for f in (result.get("findings") or []):
            if not isinstance(f, dict):
                continue
            out.append(_mk(
                f.get("severity", "info"),
                f.get("name", "Subdomain takeover"),
                f.get("location", ""),
                f.get("description", ""),
                cwe=f.get("cwe"),
                tier=f.get("detection_tier", "signal"),
                kind="vuln",
                confidence=int(f.get("confidence", 50)),
                evidence=_extract_evidence(f),
            ))
        return out
    if tool in ("crawl", "auth_crawl"):
        # Secrets regexed out of client-side JS/HTML are a real detection but an
        # UNVERIFIED signal — surface them (previously dropped) without claiming
        # validation.
        out = []
        for s in (result.get("js_secrets") or []):
            stype = str(s.get("type", "secret"))
            out.append(_mk(
                _secret_severity(stype),
                f"Exposed secret in client-side code ({stype})",
                s.get("source", ""),
                (f"A string matching a {stype} pattern was found in the site's "
                 "JavaScript/HTML. This is an unverified signal — confirm whether "
                 "it is a live credential before treating it as exploitable."),
                cwe=["CWE-200"], tier="signal", kind="vuln", confidence=40,
                evidence={
                    k: v for k, v in {
                        "type": stype, "preview": s.get("preview"),
                        "source": s.get("source"),
                    }.items() if v
                },
            ))
        return out
    # Deep-scan modules (injection, webaudit, waf_test, …) return a pre-normalized
    # "findings" list. Classify by tool and preserve whatever evidence the scanner
    # already emitted.
    if isinstance(result, dict) and isinstance(result.get("findings"), list):
        meta_tier, meta_kind, meta_conf = _GENERIC_META.get(tool, ("signal", "vuln", 50))
        out = []
        for f in result["findings"]:
            if not isinstance(f, dict):
                continue
            # Honour a finding's OWN classification when the scanner set it (e.g.
            # ssrf/idor/jwt emit per-finding possible-vs-validated tiers); fall
            # back to the per-tool default otherwise. Existing scanners
            # (injection/webaudit/waf) don't set these, so their behaviour is
            # unchanged.
            out.append(_mk(
                f.get("severity") or "info",
                f.get("name", "finding"),
                f.get("location", ""),
                f.get("description", ""),
                cve=f.get("cve"), cwe=f.get("cwe"), cvss=f.get("cvss"),
                tier=f.get("detection_tier") or meta_tier,
                kind=f.get("kind") or meta_kind,
                confidence=int(f["confidence"]) if f.get("confidence") is not None else meta_conf,
                evidence=_extract_evidence(f),
            ))
        return out
    return []


# --------------------------------------------------------------------------- #
# Purple-Team P5: human-gated, non-destructive exploitation proposals.
# All helpers flush but do not commit — the caller (router) owns the txn.
# --------------------------------------------------------------------------- #
def create_exploit_proposal(
    db: Session,
    workspace_id: int,
    finding_id: int | None,
    technique_id: str | None,
    title: str,
    rationale: str,
    created_by: int | None,
) -> models.ExploitProposal:
    """Create (or return an existing) exploitation proposal — idempotent.

    If a proposal for the same ``(workspace_id, finding_id, technique_id)`` with a
    still-actionable status (``proposed`` or ``approved``) already exists it is
    returned unchanged rather than duplicated, so re-running
    :func:`app.exploit.propose` never fans out duplicate rows for the same finding.
    """
    existing = db.scalar(
        select(models.ExploitProposal)
        .where(
            models.ExploitProposal.workspace_id == workspace_id,
            models.ExploitProposal.finding_id.is_(finding_id)
            if finding_id is None
            else models.ExploitProposal.finding_id == finding_id,
            models.ExploitProposal.technique_id.is_(technique_id)
            if technique_id is None
            else models.ExploitProposal.technique_id == technique_id,
            models.ExploitProposal.status.in_(("proposed", "approved")),
        )
        .order_by(models.ExploitProposal.id.desc())
        .limit(1)
    )
    if existing is not None:
        return existing

    proposal = models.ExploitProposal(
        workspace_id=workspace_id,
        finding_id=finding_id,
        technique_id=technique_id,
        title=title or "",
        rationale=rationale or "",
        status="proposed",
        created_by=created_by,
    )
    db.add(proposal)
    db.flush()
    return proposal


def list_exploit_proposals(
    db: Session, workspace_id: int
) -> list[models.ExploitProposal]:
    """Return a workspace's exploitation proposals, newest-first."""
    rows = db.scalars(
        select(models.ExploitProposal)
        .where(models.ExploitProposal.workspace_id == workspace_id)
        .order_by(models.ExploitProposal.id.desc())
    ).all()
    return list(rows)


def get_exploit_proposal(
    db: Session, pid: int
) -> models.ExploitProposal | None:
    """Return one exploitation proposal by id, or ``None``."""
    return db.get(models.ExploitProposal, pid)


def set_exploit_status(
    db: Session,
    proposal: models.ExploitProposal,
    status: str,
    *,
    approved_by: int | None = None,
    result: dict | None = None,
) -> models.ExploitProposal:
    """Transition a proposal's ``status`` (and optionally record approver/result).

    ``approved_by`` is stamped when supplied (on the approve transition); ``result``
    is stored when supplied (on execute). Flushes but does not commit.
    """
    proposal.status = status
    if approved_by is not None:
        proposal.approved_by = approved_by
    if result is not None:
        proposal.result = result
    db.add(proposal)
    db.flush()
    return proposal

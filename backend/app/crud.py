"""Tenant-aware database operations used by the routers.

This module owns all persistence beyond the raw ORM: authentication, workspace
summaries, scan persistence, and finding derivation. The ``derive_findings``
and ``save_scan`` logic is a faithful port of the original single-user
``db.py`` (nuclei/nmap/dirbuster derivation), rewritten to target the new
``Finding`` model with a ``workspace_id`` and ``status="open"``.
"""

import re
import secrets
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import models, security

# Severity ordering used when listing findings (critical first).
_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


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
def save_scan(db: Session, record: dict) -> models.Scan:
    """Persist a completed scan and derive its findings.

    ``record`` keys mirror the original ``db.save_scan`` contract plus
    ``workspace_id`` and optional ``created_by``. The caller commits.
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
        options=record.get("options") or {},
        logs=record.get("logs") or [],
        result=record.get("result"),
        error=record.get("error"),
        started_at=started_dt,
        finished_at=finished_dt,
        duration=duration,
    )
    db.add(scan)
    db.flush()  # assign scan.id

    for f in derive_findings(record.get("tool"), record.get("result")):
        db.add(
            models.Finding(
                scan_id=scan.id,
                workspace_id=record["workspace_id"],
                source=record.get("tool") or "",
                severity=f["severity"],
                name=f["name"],
                location=f["location"],
                description=f.get("description", ""),
                cve=f.get("cve") or [],
                cwe=f.get("cwe") or [],
                cvss=f.get("cvss"),
                status="open",
            )
        )
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


def list_findings(db: Session, workspace_id: int) -> list[models.Finding]:
    """Return findings for a workspace, critical-first then newest-first."""
    rows = db.scalars(
        select(models.Finding).where(models.Finding.workspace_id == workspace_id)
    ).all()
    return sorted(rows, key=lambda f: (_SEV_RANK.get(f.severity, 5), -f.id))


def get_finding(db: Session, finding_id: int) -> models.Finding | None:
    return db.get(models.Finding, finding_id)


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
) -> models.Schedule:
    """Create a recurring scan schedule; ``next_run_at`` is derived from ``cron``."""
    sched = models.Schedule(
        workspace_id=workspace_id,
        tool=tool,
        target=target,
        cron=cron,
        options=options or {},
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
# Finding derivation — turn raw scan results into normalized findings.
# Ported verbatim from the original backend/app/db.py.
# --------------------------------------------------------------------------- #
def derive_findings(tool: str, result) -> list[dict]:
    if not result:
        return []
    if tool == "nuclei":
        out = []
        for f in result.get("findings", []):
            out.append({
                "severity": f.get("severity", "info"),
                "name": f.get("name", f.get("template_id", "finding")),
                "location": f.get("matched_at", ""),
                "description": f.get("description", ""),
                "cve": f.get("cve") or [],
                "cwe": f.get("cwe") or [],
                "cvss": f.get("cvss"),
            })
        return out
    if tool == "nmap":
        out = []
        for p in result.get("ports", []):
            if p.get("state") == "open":
                svc = p.get("service", "")
                ver = " ".join(x for x in [p.get("product", ""), p.get("version", "")] if x)
                out.append({
                    "severity": "info",
                    "name": f"Open port {p.get('port')}/{p.get('protocol')} ({svc or 'unknown'})",
                    "location": f"{result.get('host', '')}:{p.get('port')}",
                    "description": ver,
                    "cve": [], "cwe": [], "cvss": None,
                })
        return out
    if tool == "dirbuster":
        return [{
            "severity": "info",
            "name": f"Discovered path /{r.get('path')}",
            "location": r.get("url", ""),
            "description": f"HTTP {r.get('status')}",
            "cve": [], "cwe": [], "cvss": None,
        } for r in result.get("rows", [])]
    return []

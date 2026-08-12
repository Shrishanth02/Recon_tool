"""Alert dispatch for notification channels (Phase 4 — optional).

Delivers events (e.g. a new finding) to org-configured sinks:

* ``slack`` / ``webhook`` — HTTP ``POST`` of a JSON body to ``config["url"]``.
* ``email`` — SMTP send to ``config["email"]`` using ``settings.SMTP_*``.

Every entrypoint is **failure-safe**: network and SMTP errors are caught and
reported as ``{"ok": False, "detail": ...}`` rather than raised, so a broken
channel can never take down a scan or scheduler run. Network access is routed
through the module-level ``requests`` reference and the ``_send_email`` helper so
tests can monkeypatch delivery without touching the wire.
"""

import smtplib
from email.message import EmailMessage
from typing import Any

import requests

from .config import settings

# Sensible upper bound so a hung webhook cannot wedge a worker.
_HTTP_TIMEOUT = 10


def should_notify(channel: dict, event_type: str) -> bool:
    """Return whether ``channel`` is subscribed to ``event_type``.

    A channel matches when ``event_type`` is listed in its ``events`` array, or
    when the wildcard ``"*"`` is present. A channel with no ``events`` key
    subscribes to nothing.
    """
    events = channel.get("events") or []
    return event_type in events or "*" in events


def dispatch(channel: dict, event: dict) -> dict:
    """Deliver ``event`` to ``channel`` and report the outcome.

    Args:
        channel: ``{"ctype": ..., "config": {...}, "events": [...]}``.
        event: An arbitrary JSON-serializable event payload. When it carries a
            ``"type"`` key that type is honoured for subscription filtering.

    Returns:
        ``{"ok": bool, "detail": str}``. Never raises: transport and
        configuration errors are captured in ``detail`` with ``ok=False``.
    """
    ctype = str(channel.get("ctype") or "").strip().lower()
    config = channel.get("config") or {}

    try:
        if ctype in ("slack", "webhook"):
            return _dispatch_webhook(ctype, config, event)
        if ctype == "email":
            return _dispatch_email(config, event)
        return {"ok": False, "detail": f"unknown channel type: {ctype!r}"}
    except Exception as exc:  # defensive: dispatch must never raise
        return {"ok": False, "detail": f"dispatch error: {exc}"}


def _dispatch_webhook(ctype: str, config: dict, event: dict) -> dict:
    """POST the event as JSON to the channel's configured URL."""
    url = (config or {}).get("url")
    if not url:
        return {"ok": False, "detail": f"{ctype} channel missing config.url"}

    if ctype == "slack":
        body: dict[str, Any] = {"text": _event_text(event), "event": event}
    else:
        body = {"event": event}

    try:
        resp = requests.post(url, json=body, timeout=_HTTP_TIMEOUT)
    except Exception as exc:
        return {"ok": False, "detail": f"POST failed: {exc}"}

    ok = 200 <= getattr(resp, "status_code", 0) < 300
    return {"ok": ok, "detail": f"HTTP {getattr(resp, 'status_code', '?')}"}


def _dispatch_email(config: dict, event: dict) -> dict:
    """Send the event as an email to the channel's configured address."""
    to_addr = (config or {}).get("email")
    if not to_addr:
        return {"ok": False, "detail": "email channel missing config.email"}
    if not settings.SMTP_HOST:
        return {"ok": False, "detail": "SMTP not configured (SMTP_HOST empty)"}

    subject = f"[RECON-X] {event.get('type', 'notification')}"
    return _send_email(to_addr, subject, _event_text(event))


def _send_email(to_addr: str, subject: str, body: str) -> dict:
    """Send a plaintext email via SMTP using ``settings.SMTP_*``.

    Isolated so tests can monkeypatch it. Returns the standard
    ``{"ok": bool, "detail": str}`` shape and never raises.
    """
    msg = EmailMessage()
    msg["From"] = settings.SMTP_FROM or settings.SMTP_USER or "reconx@localhost"
    msg["To"] = to_addr
    msg["Subject"] = subject
    msg.set_content(body)

    try:
        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=_HTTP_TIMEOUT) as smtp:
            smtp.ehlo()
            try:
                smtp.starttls()
                smtp.ehlo()
            except smtplib.SMTPException:
                pass  # server without STARTTLS; proceed unencrypted
            if settings.SMTP_USER:
                smtp.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
            smtp.send_message(msg)
    except Exception as exc:
        return {"ok": False, "detail": f"SMTP send failed: {exc}"}

    return {"ok": True, "detail": f"emailed {to_addr}"}


def _event_text(event: dict) -> str:
    """Render a short human-readable line for an event payload."""
    etype = event.get("type", "notification")
    if "message" in event:
        return f"{etype}: {event['message']}"
    finding = event.get("finding")
    if isinstance(finding, dict):
        sev = finding.get("severity", "info")
        name = finding.get("name", "finding")
        loc = finding.get("location", "")
        return f"{etype}: [{sev}] {name} {loc}".strip()
    return etype

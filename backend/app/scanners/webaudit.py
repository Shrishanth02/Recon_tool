"""Pure-Python web-security audit scanner (RedOpsX P2).

Custom, read-only HTTP probes that catch common real-world issues nuclei
often misses: weak security headers, CORS misconfiguration, insecure cookie
flags, exposed sensitive files, clickjacking / directory-listing exposure,
and basic TLS certificate hygiene.

No external binaries — only ``requests`` (HTTP) and the ``ssl``/``socket``
stdlib (TLS). Every check is wrapped so one failure never aborts the rest,
and a structured ``result`` is always returned.
"""

import socket
import ssl
import threading
import urllib.parse
from datetime import datetime, timezone
from typing import Iterator, List, Optional

import requests

try:  # requests bundles urllib3; suppress the InsecureRequestWarning we opt into
    from urllib3.exceptions import InsecureRequestWarning

    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)  # type: ignore[attr-defined]
except Exception:  # noqa: BLE001 - best effort only
    pass

from .. import netguard, safe_http
from .base import ensure_url, error, log, result, reject_optionlike

USER_AGENT = "RedOpsX-WebAudit/1.0"
TIMEOUT = 8

# --- Security header catalogue -------------------------------------------------
# name -> (severity, human description of what a missing header means)
SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "low",
        "No Content-Security-Policy — the page has no policy limiting where "
        "scripts, styles and other resources may load from (XSS mitigation).",
    ),
    "Strict-Transport-Security": (
        "low",
        "No Strict-Transport-Security (HSTS) — browsers may fall back to "
        "plaintext HTTP, enabling SSL-stripping / downgrade attacks.",
    ),
    "X-Frame-Options": (
        "low",
        "No X-Frame-Options — the page can be framed by other origins "
        "(clickjacking) unless a CSP frame-ancestors directive is present.",
    ),
    "X-Content-Type-Options": (
        "info",
        "No X-Content-Type-Options: nosniff — browsers may MIME-sniff "
        "responses, which can turn benign files into executable content.",
    ),
    "Referrer-Policy": (
        "info",
        "No Referrer-Policy — full URLs (possibly with sensitive tokens) may "
        "leak to third-party sites via the Referer header.",
    ),
    "Permissions-Policy": (
        "info",
        "No Permissions-Policy — powerful browser features (camera, mic, "
        "geolocation, etc.) are not explicitly restricted.",
    ),
}

# --- Sensitive files: path -> content signature confirming a real hit ----------
# The signature guards against soft-404 pages that return HTTP 200 for anything.
SENSITIVE_FILES = [
    ("/.git/HEAD", "ref:", "high", "CWE-527"),
    ("/.git/config", "[core]", "high", "CWE-527"),
    ("/.env", "=", "high", "CWE-538"),
    ("/.svn/entries", None, "high", "CWE-527"),
    ("/.htpasswd", ":", "high", "CWE-538"),
    ("/wp-config.php.bak", "DB_", "high", "CWE-538"),
    ("/config.php.bak", "<?php", "high", "CWE-538"),
    ("/phpinfo.php", "phpinfo()", "medium", "CWE-200"),
    ("/server-status", "Apache Server Status", "medium", "CWE-200"),
    ("/backup.zip", None, "medium", "CWE-538"),
    ("/.DS_Store", "Bud1", "low", "CWE-527"),
]


def _finding(severity, name, location, description, cwe=None, evidence=None):
    f = {
        "severity": severity,
        "name": name,
        "location": location,
        "description": description,
    }
    if cwe:
        f["cwe"] = cwe
    if evidence:
        # The actual observed value(s) that caused the finding — never a secret
        # (cookie values are deliberately excluded; only names/attributes kept).
        f["evidence"] = {k: v for k, v in evidence.items() if v not in (None, "", [], {})}
    return f


def _cancelled(cancel: Optional[threading.Event]) -> bool:
    return cancel is not None and cancel.is_set()


def _get(url, method="GET", **kwargs):
    kwargs.setdefault("timeout", TIMEOUT)
    kwargs.setdefault("verify", False)
    headers = {"User-Agent": USER_AGENT}
    headers.update(kwargs.pop("headers", {}) or {})
    # P1-B1: route through safe_http so every redirect hop is netguard-validated.
    return safe_http.safe_request(method, url, headers=headers, **kwargs)


# ------------------------------------------------------------------------------
# Individual checks. Each is a generator yielding events and appending to
# ``findings``; each is wrapped by the caller so one failure is isolated.
# ------------------------------------------------------------------------------

def _check_headers_cookies_content(url, findings, header_report) -> Iterator[dict]:
    """Security headers, cookie flags, clickjacking / dir-listing — one GET."""
    yield log(f"Fetching {url} ...")
    resp = _get(url, allow_redirects=True)
    yield log(f"HTTP {resp.status_code} {resp.reason} ({len(resp.content)} bytes)")

    # --- Security headers ---
    hdr_lower = {k.lower(): v for k, v in resp.headers.items()}
    for name, (severity, desc) in SECURITY_HEADERS.items():
        present = name.lower() in hdr_lower
        header_report[name] = hdr_lower.get(name.lower()) if present else None
        if present:
            yield log(f"  present: {name}: {hdr_lower[name.lower()]}")
        else:
            yield log(f"  MISSING: {name}")
            findings.append(
                _finding(
                    severity, f"Missing security header: {name}", url, desc, "CWE-693",
                    evidence={
                        "header": name,
                        "observed": "absent",
                        "http_status": resp.status_code,
                        "server": hdr_lower.get("server"),
                    },
                )
            )

    # --- Clickjacking (no frame protection at all) ---
    csp = hdr_lower.get("content-security-policy", "") or ""
    if "x-frame-options" not in hdr_lower and "frame-ancestors" not in csp.lower():
        findings.append(
            _finding(
                "low",
                "Clickjacking: no frame protection",
                url,
                "Neither X-Frame-Options nor a CSP frame-ancestors directive is "
                "set, so the page can be embedded in a malicious iframe.",
                "CWE-1021",
                evidence={
                    "x_frame_options": hdr_lower.get("x-frame-options", "absent"),
                    "csp_frame_ancestors": ("present" if "frame-ancestors" in csp.lower() else "absent"),
                    "http_status": resp.status_code,
                },
            )
        )

    # --- Cookie flags ---
    # Use raw Set-Cookie headers so each cookie's attributes are inspected.
    raw_cookies = resp.raw.headers.getlist("Set-Cookie") if hasattr(resp.raw.headers, "getlist") else []
    if not raw_cookies and "set-cookie" in hdr_lower:
        raw_cookies = [hdr_lower["set-cookie"]]
    for cookie in raw_cookies:
        low = cookie.lower()
        cname = cookie.split("=", 1)[0].strip()
        missing = []
        if "secure" not in low:
            missing.append("Secure")
        if "httponly" not in low:
            missing.append("HttpOnly")
        if "samesite" not in low:
            missing.append("SameSite")
        if missing:
            yield log(f"  cookie '{cname}' missing: {', '.join(missing)}")
            findings.append(
                _finding(
                    "low",
                    f"Insecure cookie flags on '{cname}': missing {', '.join(missing)}",
                    url,
                    "Cookies without Secure may be sent over HTTP; without "
                    "HttpOnly are readable by JavaScript (XSS theft); without "
                    "SameSite are attachable in cross-site requests (CSRF).",
                    "CWE-614",
                    # Cookie NAME + missing flags only — never the value (which may
                    # be a session token).
                    evidence={"cookie": cname, "missing_flags": missing},
                )
            )

    # --- Directory listing / mixed content ---
    ctype = hdr_lower.get("content-type", "")
    if "text/html" in ctype:
        body = resp.text[:20000]
        low_body = body.lower()
        if "<title>index of" in low_body or ">index of /" in low_body:
            findings.append(
                _finding(
                    "medium",
                    "Directory listing enabled",
                    url,
                    "The server returned an auto-generated 'Index of' directory "
                    "listing, exposing the file structure.",
                    "CWE-548",
                )
            )
        if url.lower().startswith("https://") and "http://" in low_body:
            # Cheap mixed-content heuristic: absolute http:// resource refs.
            if 'src="http://' in low_body or "src='http://" in low_body:
                findings.append(
                    _finding(
                        "low",
                        "Mixed content",
                        url,
                        "An HTTPS page references resources over plaintext "
                        "http://, which browsers may block or which can be "
                        "tampered with in transit.",
                        "CWE-311",
                    )
                )


def _check_cors(url, findings) -> Iterator[dict]:
    """Reflected-origin CORS + credentials misconfiguration."""
    evil = "https://evil.example"
    yield log(f"Testing CORS with Origin: {evil} ...")
    resp = _get(url, headers={"Origin": evil}, allow_redirects=True)
    hdr = {k.lower(): v for k, v in resp.headers.items()}
    acao = hdr.get("access-control-allow-origin")
    acac = (hdr.get("access-control-allow-credentials") or "").strip().lower()
    if not acao:
        yield log("  no Access-Control-Allow-Origin header (CORS not enabled here).")
        return
    yield log(f"  Access-Control-Allow-Origin: {acao}  Allow-Credentials: {acac or '(none)'}")
    reflects = acao.strip() == evil
    _cors_ev = {
        "origin_sent": evil,
        "access_control_allow_origin": acao,
        "access_control_allow_credentials": acac or "(none)",
        "http_status": resp.status_code,
    }
    if reflects and acac == "true":
        findings.append(
            _finding(
                "high",
                "CORS misconfiguration: reflected origin with credentials",
                url,
                "The server reflects an arbitrary Origin in "
                "Access-Control-Allow-Origin AND sets Allow-Credentials: true. "
                "Any site can read authenticated responses from this origin.",
                "CWE-942",
                evidence=_cors_ev,
            )
        )
    elif reflects:
        findings.append(
            _finding(
                "medium",
                "CORS: arbitrary origin reflected",
                url,
                "The server reflects an arbitrary Origin in "
                "Access-Control-Allow-Origin, allowing any site to read "
                "responses (impact limited without credentials).",
                "CWE-942",
                evidence=_cors_ev,
            )
        )
    elif acao.strip() == "*" and acac == "true":
        # Browsers reject *+credentials, but this signals broken intent.
        findings.append(
            _finding(
                "medium",
                "CORS: wildcard origin with credentials",
                url,
                "Access-Control-Allow-Origin is '*' together with "
                "Allow-Credentials: true — a misconfiguration indicating an "
                "overly permissive CORS policy.",
                "CWE-942",
            )
        )


def _check_sensitive_files(base, findings, cancel) -> Iterator[dict]:
    """Probe a curated list of sensitive paths, confirming by signature."""
    yield log("Probing for exposed sensitive files ...")
    for path, signature, severity, cwe in SENSITIVE_FILES:
        if _cancelled(cancel):
            yield log("Cancelled — stopping file probes.")
            return
        target = urllib.parse.urljoin(base, path)
        try:
            resp = _get(target, allow_redirects=False)
        except requests.RequestException as exc:
            yield log(f"  {path}: request failed ({exc})")
            continue
        if resp.status_code != 200:
            continue
        sample = resp.text[:4096]
        # Confirm by signature to avoid soft-404s that 200 everything.
        if signature is not None and signature.lower() not in sample.lower():
            yield log(f"  {path}: HTTP 200 but signature not matched (likely soft-404) — skipped.")
            continue
        # For binary/no-signature files, require a non-HTML content-type.
        if signature is None:
            ctype = resp.headers.get("Content-Type", "").lower()
            if "text/html" in ctype:
                yield log(f"  {path}: HTTP 200 but HTML content — likely soft-404 — skipped.")
                continue
        yield log(f"  EXPOSED: {path} (HTTP 200)")
        findings.append(
            _finding(
                severity,
                f"Exposed sensitive file: {path}",
                target,
                f"{path} is publicly accessible (HTTP 200 with matching "
                "content signature), potentially leaking source, secrets or "
                "configuration.",
                cwe,
                evidence={
                    "path": path,
                    "http_status": resp.status_code,
                    "signature_matched": (signature if signature is not None
                                          else "(binary/no-signature)"),
                    "content_type": resp.headers.get("Content-Type", ""),
                    # A short proof snippet (bounded) that the resource really
                    # served matching content.
                    "sample": sample[:200],
                },
            )
        )


def _check_tls(url, findings) -> Iterator[dict]:
    """Certificate expiry, hostname match and negotiated TLS version."""
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https":
        yield log("Target is not HTTPS — skipping TLS checks.")
        return
    host = parsed.hostname
    port = parsed.port or 443
    if not host:
        return
    yield log(f"Inspecting TLS certificate for {host}:{port} ...")
    # SSRF/rebinding guard: resolve+vet the host ONCE and pin the raw TLS socket
    # to those IPs, so the handshake cannot be steered to a private/metadata
    # address between validation and connect (matches the HTTP path's pinning).
    _tls_ok, _tls_why, _tls_ips = netguard.resolve_and_validate(host)
    if not _tls_ok:
        yield log(f"  TLS check skipped — {_tls_why}.")
        return
    ctx = ssl.create_default_context()
    # First, a strict handshake to validate hostname + trust chain.
    try:
        with safe_http.pinned(host, _tls_ips), \
                socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                version = ssock.version()
        yield log(f"  TLS version: {version}")
        # Expiry
        not_after = cert.get("notAfter")
        if not_after:
            try:
                exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
                    tzinfo=timezone.utc
                )
                days = (exp - datetime.now(timezone.utc)).days
                yield log(f"  certificate expires {not_after} ({days} days).")
                if days < 0:
                    findings.append(
                        _finding(
                            "high",
                            "TLS certificate expired",
                            host,
                            f"The certificate expired on {not_after}.",
                            "CWE-298",
                            evidence={"not_after": not_after, "days_remaining": days,
                                      "tls_version": version},
                        )
                    )
                elif days < 15:
                    findings.append(
                        _finding(
                            "medium",
                            "TLS certificate expiring soon",
                            host,
                            f"The certificate expires on {not_after} ({days} days left).",
                            "CWE-298",
                            evidence={"not_after": not_after, "days_remaining": days,
                                      "tls_version": version},
                        )
                    )
            except ValueError:
                yield log(f"  could not parse certificate expiry: {not_after!r}")
        if version in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
            findings.append(
                _finding(
                    "medium",
                    f"Weak TLS version negotiated: {version}",
                    host,
                    f"The server negotiated {version}, which is deprecated and "
                    "considered insecure.",
                    "CWE-326",
                    evidence={"tls_version": version},
                )
            )
    except ssl.SSLCertVerificationError as exc:
        yield log(f"  certificate verification FAILED: {exc}")
        findings.append(
            _finding(
                "high",
                "TLS certificate verification failed",
                host,
                f"The certificate did not validate (hostname mismatch, "
                f"self-signed, or untrusted CA): {exc}",
                "CWE-295",
                evidence={"error": str(exc)[:200]},
            )
        )
    except (socket.timeout, socket.gaierror, ConnectionError, OSError) as exc:
        yield log(f"  TLS inspection could not connect: {exc}")


def stream(target, cancel: Optional[threading.Event] = None, **options) -> Iterator[dict]:
    """Run the full web-security audit against ``target``.

    Yields ``log``/``error`` events live and always ends with a single
    ``result`` event containing the structured findings.
    """
    findings: List[dict] = []
    header_report: dict = {}

    try:
        url = ensure_url(target)
        # ensure_url already rejects option-like hosts, but be explicit.
        reject_optionlike(urllib.parse.urlsplit(url).hostname or "")
    except ValueError as exc:
        yield error(f"Invalid target: {exc}")
        return
    if not url:
        yield error("A target URL is required.")
        return

    yield log(f"RedOpsX WebAudit starting on {url}")

    # Each check is isolated: a crash in one is logged and the audit continues.
    checks = [
        ("security headers / cookies / content", lambda: _check_headers_cookies_content(url, findings, header_report)),
        ("CORS", lambda: _check_cors(url, findings)),
        ("sensitive files", lambda: _check_sensitive_files(url, findings, cancel)),
        ("TLS", lambda: _check_tls(url, findings)),
    ]

    for label, make_gen in checks:
        if _cancelled(cancel):
            yield log("Scan cancelled by user.")
            break
        try:
            for event in make_gen():
                yield event
                if _cancelled(cancel):
                    yield log("Scan cancelled by user.")
                    break
        except requests.RequestException as exc:
            yield log(f"[{label}] request error: {exc}")
        except Exception as exc:  # noqa: BLE001 - never let one check abort the audit
            yield log(f"[{label}] check failed: {exc}")

    counts = {"total": len(findings)}
    for sev in ("high", "medium", "low", "info"):
        n = sum(1 for f in findings if f["severity"] == sev)
        if n:
            counts[sev] = n

    present = {k: v for k, v in header_report.items() if v is not None}
    missing = [k for k, v in header_report.items() if v is None]

    yield log(
        f"✔ WebAudit complete: {counts['total']} finding(s) "
        f"({counts.get('high', 0)} high, {counts.get('medium', 0)} medium)."
    )
    yield result(
        {
            "target": url,
            "headers": {"present": present, "missing": missing},
            "findings": findings,
            "counts": counts,
        }
    )

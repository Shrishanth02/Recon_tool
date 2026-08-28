"""Pure-Python web-security audit scanner (RedOpsX P2).

Custom, read-only HTTP probes that catch common real-world issues nuclei
often misses: weak security headers, CORS misconfiguration, insecure cookie
flags, exposed sensitive files, clickjacking / directory-listing exposure,
and basic TLS certificate hygiene.

No external binaries — only ``requests`` (HTTP) and the ``ssl``/``socket``
stdlib (TLS). Every check is wrapped so one failure never aborts the rest,
and a structured ``result`` is always returned.
"""

import re
import secrets
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

# --- Exposed / sensitive files & endpoints -------------------------------------
# Each probe is (path, family, signatures, severity, cwe):
#   * ``signatures`` is a list of case-insensitive regexes; a hit requires AT LEAST
#     ONE to match the response body (strong, specific patterns — NOT a bare "=").
#   * ``signatures is None`` marks a BINARY artifact confirmed by magic bytes
#     (see ``_BINARY_MAGIC``) plus a non-HTML content-type.
# A bare HTTP 200 is never sufficient: the content must actually look like the
# resource. This catalogue is intentionally site-agnostic (framework-neutral
# paths only) and is capped at scan time by ``max_file_probes`` so it can never
# explode on an arbitrary site.
_SENSITIVE_PROBES = [
    # --- Version-control metadata (source-code exposure), CWE-527 ---
    ("/.git/config", "vcs", [r"\[core\]", r"\[remote "], "high", "CWE-527"),
    ("/.git/HEAD", "vcs", [r"(?m)^ref:\s*refs/"], "high", "CWE-527"),
    ("/.svn/entries", "vcs", [r"(?m)^\d+\s*$", r"svn://", r"has-props"], "high", "CWE-527"),
    ("/.hg/requires", "vcs", [r"(?mi)^(revlogv1|dotencode|store|fncache)"], "high", "CWE-527"),
    # --- Secrets / credentials, CWE-538 / CWE-522 ---
    # Require a dotenv KEY=value assignment at line start (uppercase-anchored so
    # prose that merely mentions "password"/"secret" never matches).
    ("/.env", "secret", [r"(?m)^\s*[A-Z][A-Z0-9_]{2,}\s*=\S"], "high", "CWE-538"),
    ("/.env.local", "secret", [r"(?mi)^\s*[A-Z][A-Z0-9_]{2,}\s*="], "high", "CWE-538"),
    ("/.env.production", "secret", [r"(?mi)^\s*[A-Z][A-Z0-9_]{2,}\s*="], "high", "CWE-538"),
    ("/.htpasswd", "secret",
     [r"(?m)^[^:\s]+:\$(?:apr1|2[aby]|1|5|6)\$", r"(?m)^[^:\s]+:\{SHA\}"], "high", "CWE-538"),
    ("/.netrc", "secret", [r"(?mi)^\s*machine\s+\S+", r"(?mi)^\s*password\s+\S"], "high", "CWE-522"),
    ("/.git-credentials", "secret", [r"https?://[^:@/\s]+:[^@/\s]+@"], "high", "CWE-522"),
    ("/.npmrc", "secret", [r"_authToken\s*=", r"//[^/]+/:_authToken"], "high", "CWE-522"),
    ("/.aws/credentials", "secret", [r"(?i)aws_secret_access_key", r"(?mi)^\[default\]"], "high", "CWE-522"),
    ("/.ssh/id_rsa", "secret", [r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----"], "high", "CWE-522"),
    ("/id_rsa", "secret", [r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----"], "high", "CWE-522"),
    # --- Application config files, CWE-538 ---
    ("/wp-config.php.bak", "config", [r"DB_NAME", r"DB_PASSWORD", r"<\?php"], "high", "CWE-538"),
    ("/config.php.bak", "config", [r"<\?php", r"\bdefine\s*\(", r"\$config\b"], "high", "CWE-538"),
    ("/web.config", "config", [r"(?i)<configuration\b", r"(?i)<connectionStrings\b"], "medium", "CWE-538"),
    ("/appsettings.json", "config",
     [r'"ConnectionStrings"', r'"(?:Password|ClientSecret|ApiKey)"\s*:'], "high", "CWE-538"),
    ("/application.yml", "config",
     [r"(?mi)^\s*(?:spring|datasource|server|password)\s*:"], "medium", "CWE-538"),
    ("/docker-compose.yml", "config", [r"(?mi)^services\s*:", r"(?mi)^\s{2,}image\s*:"], "medium", "CWE-538"),
    ("/Dockerfile", "config", [r"(?mi)^\s*FROM\s+\S", r"(?mi)^\s*(?:RUN|ENV|COPY)\s+\S"], "low", "CWE-538"),
    # --- Database / archive backups & dumps, CWE-538 ---
    ("/backup.sql", "backup",
     [r"(?i)\b(?:CREATE TABLE|INSERT INTO|DROP TABLE|-- MySQL dump|-- Dumping data)"], "high", "CWE-538"),
    ("/db_backup.sql", "backup",
     [r"(?i)\b(?:CREATE TABLE|INSERT INTO|DROP TABLE|-- MySQL dump)"], "high", "CWE-538"),
    ("/dump.sql", "backup", [r"(?i)\b(?:CREATE TABLE|INSERT INTO|DROP TABLE)"], "high", "CWE-538"),
    ("/database.sql", "backup", [r"(?i)\b(?:CREATE TABLE|INSERT INTO|DROP TABLE)"], "high", "CWE-538"),
    ("/backup.zip", "backup", None, "medium", "CWE-538"),        # magic: PK\x03\x04
    ("/backup.tar.gz", "backup", None, "medium", "CWE-538"),     # magic: \x1f\x8b
    # --- Debug / info-disclosure endpoints, CWE-200 ---
    ("/phpinfo.php", "debug", [r"(?i)<title>\s*phpinfo\(\)", r"phpinfo\(\)", r"Zend Engine", r"PHP Credits"],
     "medium", "CWE-200"),
    ("/info.php", "debug", [r"(?i)<title>\s*phpinfo\(\)", r"Zend Engine", r"PHP Credits"], "medium", "CWE-200"),
    ("/server-status", "debug", [r"Apache Server Status", r"(?i)Server uptime", r"(?i)Total accesses"],
     "medium", "CWE-200"),
    ("/actuator", "debug", [r'(?i)"_links"\s*:', r'(?i)"(?:health|metrics|env|beans)"\s*:'],
     "medium", "CWE-200"),
    ("/actuator/env", "debug", [r'(?i)"activeProfiles"', r'(?i)"propertySources"'], "high", "CWE-200"),
    # Werkzeug/Flask interactive debugger left enabled in production (debug=True).
    # Its console is a potential REMOTE CODE EXECUTION surface, not mere info
    # disclosure — hence high + CWE-489 (Active Debug Code). ``__debugger__`` is a
    # Werkzeug-specific marker; the title/console strings corroborate.
    ("/console", "debug", [r"__debugger__", r"(?i)werkzeug\s+debugger",
                           r"(?i)interactive\s+console"], "high", "CWE-489"),
    # --- API documentation, CWE-200 ---
    ("/swagger.json", "apidoc", [r'"swagger"\s*:\s*"', r'"openapi"\s*:\s*"'], "low", "CWE-200"),
    ("/openapi.json", "apidoc", [r'"openapi"\s*:\s*"', r'"swagger"\s*:\s*"'], "low", "CWE-200"),
    ("/v2/api-docs", "apidoc", [r'"swagger"\s*:\s*"', r'"paths"\s*:'], "low", "CWE-200"),
    ("/api-docs", "apidoc", [r'"(?:swagger|openapi)"\s*:\s*"', r'"paths"\s*:\s*\{'], "low", "CWE-200"),
    # --- Auto-generated directory listings, CWE-548 (HTML expected) ---
    ("/backup/", "dirlist", None, "medium", "CWE-548"),
    ("/uploads/", "dirlist", None, "medium", "CWE-548"),
    ("/files/", "dirlist", None, "medium", "CWE-548"),
    ("/.git/", "dirlist", None, "medium", "CWE-548"),
    # --- OS / editor artifacts, CWE-527 (binary) ---
    ("/.DS_Store", "artifact", None, "low", "CWE-527"),          # magic: Bud1
]

# Binary probes (``signatures is None`` and family != dirlist) confirmed by a
# leading magic-byte signature so a soft-404 HTML page can never masquerade.
_BINARY_MAGIC = {
    "/backup.zip": b"PK\x03\x04",
    "/backup.tar.gz": b"\x1f\x8b",
    "/.DS_Store": b"\x00\x00\x00\x01Bud1",
}

# Auto-index (directory-listing) fingerprints — the Apache/nginx/Python patterns
# a hand-written page will not contain. Directory listings are legitimately HTML.
_DIRLIST_SIGNATURES = [
    r"(?i)<title>\s*Index of /",
    r"(?i)<h1>\s*Index of /",
    r"(?i)Directory listing for /",
    r'(?i)<a href="\?C=[NMSD];O=[AD]"',       # Apache mod_autoindex sort links
]

# Families whose real file is NEVER served as HTML — an HTML 200 is a soft-404 /
# login / error page, not the resource, so we reject it up front. (debug/apidoc
# are excluded: phpinfo & server-status are legitimately HTML.)
_NON_HTML_FAMILIES = {"vcs", "secret", "config", "backup", "artifact"}

# Human, secret-free confirmation labels for the finding evidence (never leaks
# response content — see ``_check_sensitive_files``).
_FAMILY_CONFIRM = {
    "vcs": "version-control metadata",
    "secret": "credential/secret content",
    "config": "application configuration content",
    "backup": "database/archive backup content",
    "debug": "debug/info-disclosure page",
    "apidoc": "API-documentation document",
    "dirlist": "auto-generated directory index",
    "artifact": "OS/editor metadata artifact",
}

_MAX_FILE_PROBES = 50      # default cap (clamped to the catalogue size); overridable
                           # via the ``max_file_probes`` option to shrink the sweep
_MIN_BODY_BYTES = 12       # responses smaller than this are treated as empty
_SAMPLE = 8192             # bytes of body inspected for a signature


def _finding(severity, name, location, description, cwe=None, evidence=None, kind=None):
    f = {
        "severity": severity,
        "name": name,
        "location": location,
        "description": description,
    }
    # ``kind="hardening"`` marks a best-practice / defense-in-depth observation
    # (a missing header, a cookie flag, a weak-but-working TLS config) rather than
    # a confirmed exploitable vulnerability. crud.derive_findings honours this and
    # risk scoring excludes non-"vuln" kinds, so these no longer inflate the vuln
    # risk score (they were previously stamped validated/vuln by the per-tool
    # default). Genuine confirmed findings (exposed files, CORS-with-credentials,
    # expired/invalid cert, directory listing) leave ``kind`` unset -> "vuln".
    if kind:
        f["kind"] = kind
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
                    kind="hardening",
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
                kind="hardening",
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
                    kind="hardening",
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
                        kind="hardening",
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


def _norm(text: str) -> str:
    """Normalise a body for soft-404 comparison: drop digits and collapse
    whitespace so a catch-all page that only differs by the echoed path/id
    compares equal to the baseline."""
    return re.sub(r"\s+", " ", re.sub(r"\d+", "", text or "")).strip().lower()[:2000]


def _baseline_404(base):
    """Learn the site's not-found behaviour by requesting a random, certainly
    non-existent path. Returns the normalised body IF the site answers 200 (a
    'soft-404' catch-all that 200s everything); otherwise None. A soft-404 body
    is later used to reject probe responses that are merely the catch-all page."""
    rand = "/%s.notfound" % secrets.token_hex(12)
    try:
        resp = _get(urllib.parse.urljoin(base, rand), allow_redirects=False)
    except requests.RequestException:
        return None
    if resp.status_code == 200:
        return _norm(resp.text[:_SAMPLE])
    return None


def _matched_signature(body: str, signatures) -> Optional[str]:
    """Return the first signature regex that matches, else None. The regex
    PATTERN (not the response content) is what gets surfaced as evidence, so no
    secret material is ever recorded."""
    for sig in signatures:
        if re.search(sig, body):
            return sig
    return None


def _finding_name(family: str, path: str) -> str:
    if family == "dirlist":
        return f"Directory listing exposed: {path}"
    if family in ("debug", "apidoc"):
        return f"Exposed {family} endpoint: {path}"
    return f"Exposed sensitive file: {path}"


def _check_sensitive_files(base, findings, cancel, max_probes=_MAX_FILE_PROBES) -> Iterator[dict]:
    """Probe a curated, site-agnostic set of sensitive paths/endpoints.

    Every hit must pass STRICT gates — a bare HTTP 200 never qualifies:
      1. status is exactly 200 (redirects, 401/403 login walls, 404s -> skip);
      2. body is non-empty;
      3. content-type sanity — a file that is never HTML (secrets/config/backups/
         VCS) served as ``text/html`` is a soft-404/login page -> skip;
      4. content confirmation — a specific signature regex (or, for binaries,
         leading magic bytes / for directories, an auto-index fingerprint);
      5. soft-404 differential — if the site 200s everything, the body must
         differ from the learned catch-all page.
    All requests are GET via ``_get`` (safe_http + netguard); nothing is executed.
    """
    yield log("Probing for exposed sensitive files / endpoints ...")
    soft404 = _baseline_404(base)
    if soft404 is not None:
        yield log("  note: site returns HTTP 200 for non-existent paths — "
                  "requiring content to differ from that catch-all page.")
    probed = 0
    for path, family, signatures, severity, cwe in _SENSITIVE_PROBES[:max_probes]:
        if _cancelled(cancel):
            yield log("Cancelled — stopping file probes.")
            return
        probed += 1
        target = urllib.parse.urljoin(base, path)
        try:
            resp = _get(target, allow_redirects=False)
        except requests.RequestException as exc:
            yield log(f"  {path}: request failed ({exc})")
            continue
        # Gate 1 — only a real 200 counts (a 3xx/redirect, 401/403 login wall or
        # 404 is never an exposure).
        if resp.status_code != 200:
            continue
        raw = resp.content or b""
        # Gate 2 — reject empty / near-empty responses.
        if len(raw) < _MIN_BODY_BYTES:
            yield log(f"  {path}: 200 but body too small ({len(raw)}B) — skipped.")
            continue
        ctype = (resp.headers.get("Content-Type", "") or "").lower()

        if signatures is None and family != "dirlist":
            # Binary artifact — require non-HTML + leading magic bytes.
            if "text/html" in ctype:
                yield log(f"  {path}: 200 but HTML content — not the real file — skipped.")
                continue
            magic = _BINARY_MAGIC.get(path)
            if magic and not raw.startswith(magic):
                yield log(f"  {path}: 200 but magic bytes not matched — skipped.")
                continue
            confirmed_by = "binary magic-byte signature"
        else:
            body = resp.text[:_SAMPLE]
            # Gate 3 — content-type sanity for families that are never HTML.
            if family in _NON_HTML_FAMILIES and "text/html" in ctype:
                yield log(f"  {path}: 200 but HTML content — soft-404/login page — skipped.")
                continue
            sigs = _DIRLIST_SIGNATURES if family == "dirlist" else signatures
            # Gate 4 — content signature confirmation.
            matched = _matched_signature(body, sigs)
            if not matched:
                yield log(f"  {path}: 200 but content signature not matched (soft-404?) — skipped.")
                continue
            # Gate 5 — soft-404 differential: reject the catch-all page itself.
            if soft404 is not None and _norm(body) == soft404:
                yield log(f"  {path}: 200 but body equals the site's catch-all page — skipped.")
                continue
            confirmed_by = matched

        yield log(f"  EXPOSED [{family}]: {path} (HTTP 200)")
        findings.append(
            _finding(
                severity,
                _finding_name(family, path),
                target,
                f"{path} is publicly accessible (HTTP 200) and its response "
                f"actually contains {_FAMILY_CONFIRM.get(family, 'sensitive content')} "
                "— confirmed by a content signature, not merely by the path "
                "existing. This can leak source code, secrets, configuration or "
                "internal structure.",
                cwe,
                # Evidence is deliberately content-free: the matched signature
                # PATTERN and response metadata prove the finding without
                # recording any secret value from the file.
                evidence={
                    "path": path,
                    "family": family,
                    "http_status": resp.status_code,
                    "content_type": ctype,
                    "bytes": len(raw),
                    "confirmed_by": confirmed_by,
                },
            )
        )
    yield log(f"  probed {probed} path(s).")


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
                            kind="hardening",
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
                    kind="hardening",
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

    # Configurable cap on how many sensitive-file paths are probed, so scanning
    # can never explode on an arbitrary site (each probe = one GET). Clamped to a
    # sane range regardless of the caller-supplied value.
    try:
        max_probes = int(options.get("max_file_probes", _MAX_FILE_PROBES))
    except (TypeError, ValueError):
        max_probes = _MAX_FILE_PROBES
    max_probes = max(0, min(max_probes, len(_SENSITIVE_PROBES)))

    # Each check is isolated: a crash in one is logged and the audit continues.
    checks = [
        ("security headers / cookies / content", lambda: _check_headers_cookies_content(url, findings, header_report)),
        ("CORS", lambda: _check_cors(url, findings)),
        ("sensitive files", lambda: _check_sensitive_files(url, findings, cancel, max_probes)),
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

"""SAFE ATT&CK technique-emulation library (Purple-Team P2).

This module is the registry of *atomic*, ATT&CK-mapped, **non-destructive**
technique tests RECON-X can fire at an authorized target to generate the
telemetry a real attack would — so a later phase (P3) can validate whether the
defender's controls detected them.

Every test is deliberately benign:

* HTTP tests use :mod:`requests` with a short 6-second timeout,
  ``allow_redirects=False``, a clear ``User-Agent``, and are wrapped so a single
  technique can never crash the whole run.
* No test sends a payload that could mutate, exfiltrate, or exploit anything on
  the target. The "SQLi/XSS" probes are canonical *detection* strings (``' OR
  '1'='1``, ``<script>alert(1)</script>``) submitted as read-only query params;
  they are the kind of input a WAF is expected to flag, not a working exploit.
* The network-discovery test is a plain TCP connect (``connect_ex``) that opens
  and immediately closes a socket — no banner grabbing, no payload.

Each registry entry is a dict::

    {
        "id":            "<emu id>",          # RECON-X emulation id, e.g. "E1"
        "technique_id":  "<ATT&CK Txxxx>",    # MITRE ATT&CK technique id
        "name":          "<display name>",
        "tactic":        "<ATT&CK tactic id>",
        "description":   "<what the safe action does>",
        "run":           callable(base_url, ctx) -> dict,
    }

The ``run`` callable returns a result dict::

    {
        "status":   "executed" | "blocked" | "failed" | "skipped",
        "evidence": "<short human string, e.g. 'HTTP 403'>",
        "detail":   "<longer free-form detail>",
    }

``"blocked"`` is a *useful* signal, not an error: it means the target or a WAF
refused the emulated action (typically an HTTP ``403``), which is exactly the
kind of detection P3 wants to confirm.
"""

from __future__ import annotations

import socket
from typing import Any
from urllib.parse import urlsplit

import requests

# --------------------------------------------------------------------------- #
# Constants shared by every technique.
# --------------------------------------------------------------------------- #
#: Short per-request timeout (seconds). Keeps a run bounded even against a slow
#: or tar-pitting target.
HTTP_TIMEOUT: float = 6.0

#: Default, honest User-Agent so blue-team logs clearly attribute the traffic to
#: RECON-X's emulation engine rather than something covert.
DEFAULT_UA: str = "RECON-X-Emulation/1.0 (+purple-team; safe-attack-emulation)"

#: Marker header stamped on beacon/exfil-shaped requests so a defender (and P3)
#: can positively identify emulated traffic.
MARKER_HEADER: str = "X-RECONX-EMULATION"

#: Ports probed by the network-service-discovery test (E4).
COMMON_PORTS: tuple[int, ...] = (80, 443, 22, 3389)

#: An HTTP status at/above this from a probe is read as the target/WAF blocking
#: the emulated action ("blocked" is a positive detection signal).
_BLOCK_STATUSES: frozenset[int] = frozenset({401, 403, 406, 429})


def _result(status: str, evidence: str = "", detail: str = "") -> dict[str, str]:
    """Build a normalized technique-result dict."""
    return {"status": status, "evidence": evidence, "detail": detail}


def _classify_http(resp: requests.Response) -> str:
    """Map an HTTP response to an emulation status.

    A block-family status (403/401/406/429) is reported as ``"blocked"`` — the
    target/WAF refused the action, which is the detection signal we want. Any
    other completed response counts as ``"executed"`` (the benign action reached
    the app and produced telemetry).
    """
    return "blocked" if resp.status_code in _BLOCK_STATUSES else "executed"


# --------------------------------------------------------------------------- #
# E1 — T1595.002 Active Scanning: Vulnerability Scanning
# --------------------------------------------------------------------------- #
def _e1_active_scanning(base_url: str, ctx: dict[str, Any]) -> dict[str, str]:
    """GET ``/`` with a well-known scanner User-Agent; record the status.

    Emulates the fingerprint an automated vulnerability scanner leaves in access
    logs. Entirely read-only — a single GET of the site root.
    """
    headers = {
        "User-Agent": "Nuclei - Open-source project (github.com/projectdiscovery/nuclei)",
        MARKER_HEADER: "T1595.002",
    }
    try:
        resp = requests.get(
            base_url + "/",
            headers=headers,
            timeout=HTTP_TIMEOUT,
            allow_redirects=False,
        )
    except requests.RequestException as exc:
        return _result("failed", "", f"request error: {exc}")
    return _result(
        _classify_http(resp),
        f"HTTP {resp.status_code}",
        f"Scanner UA GET / -> {resp.status_code} ({resp.reason})",
    )


# --------------------------------------------------------------------------- #
# E2 — T1190 Exploit Public-Facing Application
# --------------------------------------------------------------------------- #
def _e2_exploit_public_app(base_url: str, ctx: dict[str, Any]) -> dict[str, str]:
    """GET with BENIGN sqli/xss detection strings in a query param.

    Sends two canonical WAF-detection probes (a quoted boolean-tautology string
    and a ``<script>`` string) as read-only ``?q=`` query parameters. These are
    *signatures*, not exploits: nothing is submitted to a form, no state is
    mutated. A ``403`` here means the WAF caught the probe — the whole point.
    """
    probes = [
        ("sqli", "1' OR '1'='1"),
        ("xss", "<script>alert(1)</script>"),
    ]
    blocked_any = False
    seen: list[str] = []
    last_exc: str | None = None
    for label, value in probes:
        try:
            resp = requests.get(
                base_url + "/",
                params={"q": value},
                headers={"User-Agent": DEFAULT_UA, MARKER_HEADER: "T1190"},
                timeout=HTTP_TIMEOUT,
                allow_redirects=False,
            )
        except requests.RequestException as exc:
            last_exc = f"{label}: {exc}"
            continue
        seen.append(f"{label}=HTTP {resp.status_code}")
        if resp.status_code in _BLOCK_STATUSES:
            blocked_any = True

    if not seen:
        return _result("failed", "", f"request error: {last_exc}")
    detail = "Benign SQLi/XSS probes in ?q=: " + ", ".join(seen)
    if blocked_any:
        return _result("blocked", "WAF blocked probe", detail)
    return _result("executed", seen[0].split("=", 1)[1], detail)


# --------------------------------------------------------------------------- #
# E3 — T1071.001 Application Layer Protocol: Web Protocols
# --------------------------------------------------------------------------- #
def _e3_app_layer_web(base_url: str, ctx: dict[str, Any]) -> dict[str, str]:
    """Benign beacon-shaped HTTP POST to ``/`` carrying the marker header.

    Emulates the periodic, small HTTP check-in a C2 implant makes. The body is a
    tiny fixed marker (no host data), and the request is explicitly tagged with
    ``X-RECONX-EMULATION`` so it is trivially attributable.
    """
    try:
        resp = requests.post(
            base_url + "/",
            data={"beacon": "reconx-emulation"},
            headers={
                "User-Agent": DEFAULT_UA,
                MARKER_HEADER: "T1071.001",
            },
            timeout=HTTP_TIMEOUT,
            allow_redirects=False,
        )
    except requests.RequestException as exc:
        return _result("failed", "", f"request error: {exc}")
    return _result(
        _classify_http(resp),
        f"HTTP {resp.status_code}",
        f"Beacon-shaped POST / -> {resp.status_code} ({resp.reason})",
    )


# --------------------------------------------------------------------------- #
# E4 — T1046 Network Service Discovery
# --------------------------------------------------------------------------- #
def _e4_network_discovery(base_url: str, ctx: dict[str, Any]) -> dict[str, str]:
    """TCP-connect probe of a few common ports; record the open set.

    Emulates a lightweight port sweep using :func:`socket.socket.connect_ex` —
    each socket is opened and immediately closed with no data sent. The host is
    taken from ``ctx["host"]`` (already scope/netguard validated by the router).
    """
    host = ctx.get("host") or ""
    if not host:
        return _result("skipped", "", "no host to probe")

    open_ports: list[int] = []
    for port in COMMON_PORTS:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2.0)
        try:
            if sock.connect_ex((host, port)) == 0:
                open_ports.append(port)
        except OSError:
            pass
        finally:
            try:
                sock.close()
            except OSError:
                pass

    if not open_ports:
        return _result(
            "executed",
            "0 open",
            f"TCP-connect sweep of {list(COMMON_PORTS)} on {host}: none open",
        )
    return _result(
        "executed",
        f"open: {','.join(str(p) for p in open_ports)}",
        f"TCP-connect sweep of {host} found open ports {open_ports}",
    )


# --------------------------------------------------------------------------- #
# E5 — T1048 Exfiltration Over Alternative Protocol
# --------------------------------------------------------------------------- #
def _e5_exfil_alt_protocol(base_url: str, ctx: dict[str, Any]) -> dict[str, str]:
    """Benign HTTP POST ``/`` with a small marker body (no real data).

    Emulates the shape of an exfiltration check-in over HTTP without moving any
    actual data: the body is a fixed, obviously-synthetic marker string. Tagged
    with the marker header so the defender can attribute it.
    """
    try:
        resp = requests.post(
            base_url + "/",
            data={"exfil": "RECONX-EMULATION-NO-REAL-DATA"},
            headers={
                "User-Agent": DEFAULT_UA,
                MARKER_HEADER: "T1048",
            },
            timeout=HTTP_TIMEOUT,
            allow_redirects=False,
        )
    except requests.RequestException as exc:
        return _result("failed", "", f"request error: {exc}")
    return _result(
        _classify_http(resp),
        f"HTTP {resp.status_code}",
        f"Marker exfil POST / -> {resp.status_code} ({resp.reason})",
    )


# --------------------------------------------------------------------------- #
# The registry.
# --------------------------------------------------------------------------- #
#: The ordered list of SAFE emulation techniques. Each ``run`` is a callable
#: ``(base_url, ctx) -> {"status","evidence","detail"}``.
TECHNIQUES: list[dict[str, Any]] = [
    {
        "id": "E1",
        "technique_id": "T1595.002",
        "name": "Active Scanning: Vulnerability Scanning",
        "tactic": "reconnaissance",
        "description": "GET / with a recognizable scanner User-Agent (Nuclei) "
        "and record the response status.",
        "run": _e1_active_scanning,
    },
    {
        "id": "E2",
        "technique_id": "T1190",
        "name": "Exploit Public-Facing Application",
        "tactic": "initial-access",
        "description": "GET with benign SQLi/XSS detection strings in a "
        "read-only ?q= param; a 403 means the WAF blocked it.",
        "run": _e2_exploit_public_app,
    },
    {
        "id": "E3",
        "technique_id": "T1071.001",
        "name": "Application Layer Protocol: Web Protocols",
        "tactic": "command-and-control",
        "description": "Benign beacon-shaped HTTP POST to / carrying the "
        "X-RECONX-EMULATION marker header.",
        "run": _e3_app_layer_web,
    },
    {
        "id": "E4",
        "technique_id": "T1046",
        "name": "Network Service Discovery",
        "tactic": "discovery",
        "description": "TCP-connect probe of common ports (80,443,22,3389) "
        "and record the open set. No data sent.",
        "run": _e4_network_discovery,
    },
    {
        "id": "E5",
        "technique_id": "T1048",
        "name": "Exfiltration Over Alternative Protocol",
        "tactic": "exfiltration",
        "description": "Benign HTTP POST / with a small synthetic marker body "
        "(no real data) to emulate an exfil check-in.",
        "run": _e5_exfil_alt_protocol,
    },
]

#: Fast lookup of a technique entry by its emulation id (``"E1"`` ...).
TECHNIQUES_BY_ID: dict[str, dict[str, Any]] = {t["id"]: t for t in TECHNIQUES}


# --------------------------------------------------------------------------- #
# Target normalization helpers (shared with the engine).
# --------------------------------------------------------------------------- #
def normalize_base_url(target: str) -> str:
    """Reduce an arbitrary target to a ``scheme://host[:port]`` base URL.

    A bare host/IP gets an ``http://`` scheme; any supplied path/query/fragment
    is dropped so techniques control their own request path. IPv6 literals keep
    their brackets.

    Examples
    --------
    >>> normalize_base_url("example.com")
    'http://example.com'
    >>> normalize_base_url("https://example.com:8443/app?x=1")
    'https://example.com:8443'
    """
    raw = (target or "").strip()
    if not raw:
        return ""
    if "://" not in raw:
        raw = "http://" + raw
    parts = urlsplit(raw)
    scheme = parts.scheme or "http"
    netloc = parts.netloc or parts.path.split("/")[0]
    return f"{scheme}://{netloc}" if netloc else ""


def host_from_base_url(base_url: str) -> str:
    """Extract the bare hostname (no scheme, port, or brackets) from a base URL."""
    if not base_url:
        return ""
    host = urlsplit(base_url).hostname or ""
    return host

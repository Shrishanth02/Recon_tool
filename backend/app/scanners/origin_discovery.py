"""Origin discovery — find the real server behind a CDN/WAF.

When a target is fronted by a CDN/WAF (Cloudflare, Hostinger hCDN, Akamai,
Fastly, Sucuri, …), scanning the hostname only tests the *edge*. This module
locates candidate **origin** IPs so an authorized engagement can point the deep
scan at the actual application instead of the WAF. It is pure-Python (DNS +
Certificate Transparency + a Host-header validation probe) — no external binary.

Techniques (passive/lightweight, no evasion):
  1. Detect whether the apex is behind a known CDN (response headers + CNAME).
  2. Certificate Transparency (crt.sh) → historical subdomains.
  3. DNS records: MX / A of mail-style + common "direct" subdomains (mail, ftp,
     cpanel, webmail, direct, origin, server, dev, staging) — these frequently
     resolve straight to the origin, not the CDN.
  4. For every candidate IP that ISN'T the CDN edge, validate it by requesting
     ``/`` with the target's Host header and checking it serves the same site.

Result shape:
  {domain, behind_cdn, cdn, edge_ips, candidate_origins:[{ip,source}],
   confirmed_origins:[{ip,status,title,confidence}], recommendation}
"""

from __future__ import annotations

import socket
import threading
from typing import Iterator, Optional

import requests

from .. import netguard, safe_http
from .base import clean_target, error, log, result

# Response-header / CNAME signatures for common CDNs & WAFs.
_CDN_SIGNS = {
    "cloudflare": ["cloudflare", "cf-ray"],
    "hostinger hcdn": ["hcdn", "hostinger"],
    "akamai": ["akamai", "x-akamai"],
    "fastly": ["fastly", "x-served-by"],
    "sucuri": ["sucuri", "x-sucuri"],
    "imperva/incapsula": ["incapsula", "imperva", "x-iinfo"],
    "amazon cloudfront": ["cloudfront", "x-amz-cf-id"],
    "google cloud": ["gws", "x-goog"],
}

# Subdomains that commonly resolve directly to the origin (not the CDN edge).
_DIRECT_SUBS = [
    "mail", "webmail", "cpanel", "ftp", "direct", "direct-connect", "origin",
    "server", "srv", "host", "dev", "staging", "test", "vpn", "portal", "cpcalendars",
]

_UA = "RedOpsX-OriginDiscovery/1.0 (+authorized-assessment)"
_HTTP_TIMEOUT = 8.0


def _resolve(host: str, rtype: str = "A") -> list[str]:
    """Resolve a DNS record type, tolerant of missing deps / NXDOMAIN."""
    out: list[str] = []
    try:
        import dns.resolver  # dnspython

        r = dns.resolver.Resolver()
        r.lifetime = 5.0
        for rec in r.resolve(host, rtype):
            out.append(rec.to_text().strip().rstrip("."))
    except Exception:
        if rtype == "A":  # fall back to the stdlib for plain A lookups
            try:
                out = list({ai[4][0] for ai in socket.getaddrinfo(host, None)})
            except OSError:
                pass
    return out


def _fingerprint_cdn(url: str) -> tuple[bool, str, str, dict]:
    """Return (behind_cdn, cdn_name, edge_ip, headers) for the apex URL."""
    try:
        resp = safe_http.safe_request(
            "GET", url, headers={"User-Agent": _UA}, timeout=_HTTP_TIMEOUT,
            allow_redirects=True,
        )
        blob = " ".join(
            [resp.headers.get("Server", ""), resp.headers.get("Via", "")]
            + list(resp.headers.keys())
        ).lower()
        for name, sigs in _CDN_SIGNS.items():
            if any(s in blob for s in sigs):
                return True, name, "", dict(resp.headers)
        return False, "", "", dict(resp.headers)
    except Exception:
        return False, "", "", {}


def _crtsh_subdomains(domain: str, cap: int = 60) -> list[str]:
    """Historical subdomains from Certificate Transparency (crt.sh), best-effort."""
    subs: set[str] = set()
    try:
        r = safe_http.safe_request(
            "GET", f"https://crt.sh/?q=%25.{domain}&output=json",
            headers={"User-Agent": _UA}, timeout=15,
        )
        if r.ok:
            for row in r.json():
                for name in str(row.get("name_value", "")).splitlines():
                    name = name.strip().lstrip("*.").lower()
                    if name.endswith(domain) and "@" not in name:
                        subs.add(name)
    except Exception:
        pass
    return sorted(subs)[:cap]


def _validate_origin(ip: str, domain: str, edge_ips: set[str]) -> Optional[dict]:
    """Probe a candidate IP with the target's Host header; is it the real origin?"""
    if ip in edge_ips:
        return None
    # P1-B2: candidate IPs come from DNS history / crt.sh / SPF — untrusted. Gate
    # every one through the existing SSRF guard IMMEDIATELY before any connection;
    # a private / loopback / link-local / metadata / reserved / malformed (or
    # otherwise blocked) candidate is never probed.
    allowed, _reason = netguard.validate_target(ip)
    if not allowed:
        return None
    for scheme in ("https", "http"):
        try:
            resp = requests.get(
                f"{scheme}://{ip}/",
                headers={"User-Agent": _UA, "Host": domain},
                timeout=_HTTP_TIMEOUT, allow_redirects=False, verify=False,
            )
            title = ""
            if "text/html" in resp.headers.get("Content-Type", ""):
                body = resp.text[:4000]
                m = body.lower().find("<title")
                if m != -1:
                    end = body.find("</title>", m)
                    title = body[body.find(">", m) + 1:end].strip()[:120]
            # A real origin answers the vhost (not a generic 403/404 from the host).
            confident = resp.status_code in (200, 301, 302, 401, 403) and (
                bool(title) or resp.status_code in (200, 301, 302)
            )
            return {
                "ip": ip,
                "scheme": scheme,
                "status": resp.status_code,
                "title": title,
                "confidence": "high" if confident and resp.status_code == 200 else "medium",
            }
        except Exception:
            continue
    return None


def stream(target: str, cancel: Optional[threading.Event] = None, **_) -> Iterator[dict]:
    domain = clean_target(target)
    yield log(f"Origin discovery for {domain}")

    # 1) CDN/WAF fingerprint on the apex.
    behind_cdn, cdn_name, _edge, _hdrs = _fingerprint_cdn(f"https://{domain}")
    edge_ips = set(_resolve(domain, "A"))
    if behind_cdn:
        yield log(f"⚠ Behind CDN/WAF: {cdn_name} (edge IPs: {', '.join(edge_ips) or 'n/a'})")
    else:
        yield log(f"No CDN signature detected; edge IPs: {', '.join(edge_ips) or 'n/a'}")

    candidates: dict[str, str] = {}  # ip -> source

    # 2) MX / mail infrastructure (rarely behind the web CDN).
    for mx in _resolve(domain, "MX"):
        host = mx.split()[-1] if " " in mx else mx
        for ip in _resolve(host, "A"):
            if ip not in edge_ips:
                candidates.setdefault(ip, f"MX:{host}")
    yield log(f"Checked MX records → {sum(1 for v in candidates.values() if v.startswith('MX'))} candidate(s)")

    # 3) Common direct subdomains + Certificate Transparency history.
    if cancel and cancel.is_set():
        yield result({"domain": domain, "cancelled": True}); return
    probes = list(_DIRECT_SUBS)
    ct = _crtsh_subdomains(domain)
    yield log(f"Certificate Transparency (crt.sh) → {len(ct)} historical name(s)")
    probe_hosts = [f"{s}.{domain}" for s in probes] + ct
    seen_hosts = set()
    for host in probe_hosts:
        if cancel and cancel.is_set():
            break
        if host in seen_hosts:
            continue
        seen_hosts.add(host)
        for ip in _resolve(host, "A"):
            if ip not in edge_ips:
                candidates.setdefault(ip, host)

    yield log(f"✔ {len(candidates)} non-edge candidate IP(s) collected — validating…")

    # 4) Validate candidates by vhost probe.
    confirmed: list[dict] = []
    for ip, src in list(candidates.items()):
        if cancel and cancel.is_set():
            break
        v = _validate_origin(ip, domain, edge_ips)
        if v:
            v["source"] = src
            confirmed.append(v)
            yield log(f"  ➜ {ip} answers {domain} (HTTP {v['status']}, {v['confidence']}) via {src}")

    if confirmed:
        best = sorted(confirmed, key=lambda x: 0 if x["confidence"] == "high" else 1)[0]
        rec = (
            f"Likely origin: {best['ip']}. Point the deep scan at this IP "
            f"(Host: {domain}) to test the app directly instead of the CDN edge."
        )
        yield log(f"✔ {len(confirmed)} confirmed origin candidate(s). {rec}")
    else:
        rec = (
            "No origin confirmed. The origin may be firewalled to CDN-only, or "
            "allow-list your scanner IP at the CDN to scan through the front door."
        )
        yield log("✔ No origin confirmed via passive methods.")

    yield result({
        "domain": domain,
        "behind_cdn": behind_cdn,
        "cdn": cdn_name,
        "edge_ips": sorted(edge_ips),
        "candidate_origins": [{"ip": ip, "source": src} for ip, src in candidates.items()],
        "confirmed_origins": confirmed,
        "recommendation": rec,
    })

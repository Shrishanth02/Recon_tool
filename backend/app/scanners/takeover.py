"""Subdomain-takeover detection — safe, non-exploitative.

Determines whether a hostname points (via CNAME) at an external service whose
backing resource appears UNCLAIMED, which would let an attacker register it and
serve content from the victim's subdomain. It NEVER attempts to claim or exploit
anything — it only observes DNS + a single read-only HTTP GET.

Conservative by design:
  * a bare CNAME is never a takeover;
  * a finding is only produced when the CNAME points at a KNOWN provider AND
    either the provider's "unclaimed" body fingerprint is present (-> VALIDATED)
    or the CNAME target does not resolve, i.e. dangling (-> SIGNAL);
  * a provider that is serving normally is not reported.

DNS is pure-Python (dnspython, imported lazily so the module is import-safe).
Egress safety (scope + netguard) is enforced by the caller (execution / pipeline)
before this scanner runs, exactly like every other scanner.

Result shape::

    {
      "target": str, "cname": str|None, "provider": str|None,
      "dns_status": str, "http_status": int|None, "dangling": bool,
      "findings": [ {severity,name,location,description,cwe,detection_tier,
                     confidence,evidence}, ... ]
    }
"""

import threading
from typing import Iterator, Optional

import requests

from .. import safe_http
from .base import clean_target, error, log, result

_HTTP_TIMEOUT = 8
_BODY_CAP = 8192
_UA = "RedOpsX-Takeover/1.0"

# Curated provider fingerprints (subset of the community "can-i-take-over-xyz"
# reference). ``dangling_vulnerable`` is True for providers where a
# non-resolving CNAME target is itself a strong takeover indicator.
_PROVIDERS = [
    {"name": "AWS/S3", "cnames": ["s3.amazonaws.com", "s3-website", "amazonaws.com"],
     "fingerprints": ["NoSuchBucket", "The specified bucket does not exist"],
     "dangling_vulnerable": False},
    {"name": "GitHub Pages", "cnames": ["github.io"],
     "fingerprints": ["There isn't a GitHub Pages site here.",
                      "For root URLs (like http://example.com/) you must provide an index.html file"],
     "dangling_vulnerable": True},
    {"name": "Heroku", "cnames": ["herokudns.com", "herokuapp.com", "herokussl.com"],
     "fingerprints": ["No such app", "herokucdn.com/error-pages/no-such-app.html"],
     "dangling_vulnerable": True},
    {"name": "Fastly", "cnames": ["fastly.net"],
     "fingerprints": ["Fastly error: unknown domain"], "dangling_vulnerable": False},
    {"name": "Shopify", "cnames": ["myshopify.com"],
     "fingerprints": ["Sorry, this shop is currently unavailable"], "dangling_vulnerable": False},
    {"name": "Zendesk", "cnames": ["zendesk.com"],
     "fingerprints": ["Help Center Closed"], "dangling_vulnerable": False},
    {"name": "Ghost", "cnames": ["ghost.io"],
     "fingerprints": ["The thing you were looking for is no longer here"], "dangling_vulnerable": True},
    {"name": "Surge.sh", "cnames": ["surge.sh"],
     "fingerprints": ["project not found"], "dangling_vulnerable": True},
    {"name": "Pantheon", "cnames": ["pantheonsite.io"],
     "fingerprints": ["The gods are wise, but do not know of the site which you seek"],
     "dangling_vulnerable": True},
    {"name": "Tumblr", "cnames": ["domains.tumblr.com"],
     "fingerprints": ["Whatever you were looking for doesn't currently exist at this address"],
     "dangling_vulnerable": False},
]


# --------------------------------------------------------------------------- #
# DNS + HTTP helpers (module-level so tests can monkeypatch them)
# --------------------------------------------------------------------------- #
def _resolve_cname(host: str) -> tuple[Optional[str], str]:
    """Return ``(cname_target, status)``; status in ok/no-cname/host-nxdomain/error."""
    try:
        import dns.resolver  # lazy
    except Exception:  # noqa: BLE001
        return None, "dnspython-missing"
    try:
        ans = dns.resolver.resolve(host, "CNAME")
        return str(ans[0].target).rstrip("."), "ok"
    except dns.resolver.NoAnswer:
        return None, "no-cname"
    except dns.resolver.NXDOMAIN:
        return None, "host-nxdomain"
    except Exception:  # noqa: BLE001 — timeout / no-nameservers / lib error
        return None, "error"


def _target_nxdomain(name: str) -> Optional[bool]:
    """True if *name* does not resolve (dangling), False if it does, None if unknown."""
    try:
        import dns.resolver  # lazy
    except Exception:  # noqa: BLE001
        return None
    try:
        dns.resolver.resolve(name, "A")
        return False
    except dns.resolver.NXDOMAIN:
        return True
    except Exception:  # noqa: BLE001
        return None


def _fetch(host: str) -> tuple[str, Optional[int], Optional[str]]:
    """Read-only GET of the host (https, then http). Returns (body, status, err)."""
    for scheme in ("https", "http"):
        try:
            resp = safe_http.safe_request(
                "GET", f"{scheme}://{host}", headers={"User-Agent": _UA},
                timeout=_HTTP_TIMEOUT, verify=False, allow_redirects=True,
            )
            return (resp.text or "")[:_BODY_CAP], resp.status_code, None
        except requests.RequestException as exc:
            last = f"{exc}"
    return "", None, last


def _match_provider_by_cname(cname: Optional[str]):
    if not cname:
        return None
    low = cname.lower()
    for p in _PROVIDERS:
        if any(pat in low for pat in p["cnames"]):
            return p
    return None


def _match_provider_by_body(body: str):
    if not body:
        return None
    for p in _PROVIDERS:
        if any(fp in body for fp in p["fingerprints"]):
            return p
    return None


def _fingerprint_hit(provider: dict, body: str) -> Optional[str]:
    for fp in provider["fingerprints"]:
        if fp in (body or ""):
            return fp
    return None


# --------------------------------------------------------------------------- #
# Public entrypoint
# --------------------------------------------------------------------------- #
def stream(target: str, cancel: Optional[threading.Event] = None, **options) -> Iterator[dict]:
    try:
        host = clean_target(target)
    except ValueError as exc:
        yield error(str(exc))
        return
    if not host:
        yield error("A hostname is required.")
        return

    yield log(f"Subdomain-takeover check for {host}")
    cname, dns_status = _resolve_cname(host)
    if cname:
        yield log(f"  CNAME {host} -> {cname}")
    else:
        yield log(f"  no CNAME ({dns_status})")

    provider = _match_provider_by_cname(cname)
    body, http_status, fetch_err = ("", None, None)
    # Only make an HTTP request when there is a CNAME worth confirming.
    if cname:
        if cancel is not None and cancel.is_set():
            yield result(_empty(host, cname, dns_status))
            return
        body, http_status, fetch_err = _fetch(host)
    if provider is None:
        provider = _match_provider_by_body(body)

    findings: list[dict] = []
    dangling = False
    if provider is not None:
        fp_hit = _fingerprint_hit(provider, body)
        # The CNAME target dangles when it explicitly does not resolve.
        if cname:
            dangling = _target_nxdomain(cname) is True
        remediation = (
            f"Remove the dangling DNS record for {host} or re-claim the "
            f"resource at {provider['name']}."
        )
        if fp_hit:
            yield log(f"  🚨 provider {provider['name']} unclaimed-fingerprint matched")
            findings.append({
                "severity": "high",
                "name": f"Subdomain takeover: {host} ({provider['name']})",
                "location": host,
                "description": (
                    f"{host} has a CNAME to {provider['name']} ({cname}) and the "
                    f"live response contains {provider['name']}'s unclaimed-resource "
                    f"fingerprint — the backing resource appears unregistered and "
                    f"claimable. {remediation}"
                ),
                "cwe": ["CWE-350"],
                "detection_tier": "validated",
                "confidence": 90,
                "evidence": {
                    "hostname": host, "cname": cname, "target": cname,
                    "provider": provider["name"], "fingerprint": fp_hit,
                    "http_status": http_status, "dns_record": "CNAME",
                },
            })
        elif dangling and provider["dangling_vulnerable"]:
            yield log(f"  ⚠ dangling CNAME to {provider['name']} (target does not resolve)")
            findings.append({
                "severity": "high",
                "name": f"Potential subdomain takeover: {host} ({provider['name']})",
                "location": host,
                "description": (
                    f"{host} has a CNAME to {provider['name']} ({cname}) whose target "
                    f"does not resolve (dangling). The external resource may be "
                    f"unclaimed and registrable. Unverified — confirm before acting. "
                    f"{remediation}"
                ),
                "cwe": ["CWE-350"],
                "detection_tier": "signal",
                "confidence": 70,
                "evidence": {
                    "hostname": host, "cname": cname, "target": cname,
                    "provider": provider["name"], "dangling": True,
                    "http_status": http_status, "dns_record": "CNAME",
                },
            })
        else:
            yield log(f"  provider {provider['name']} appears to be serving normally — not reported")

    yield result({
        "target": host,
        "cname": cname,
        "provider": provider["name"] if provider else None,
        "dns_status": dns_status,
        "http_status": http_status,
        "dangling": dangling,
        "findings": findings,
    })


def _empty(host: str, cname: Optional[str], dns_status: str) -> dict:
    return {"target": host, "cname": cname, "provider": None,
            "dns_status": dns_status, "http_status": None, "dangling": False,
            "findings": []}

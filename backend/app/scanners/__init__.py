"""Scanner registry and tool catalogue.

``REGISTRY`` maps a tool id to its streaming generator. ``TOOLS`` is the
front-end-facing catalogue describing each tool (label, target hint, and any
extra options) so the UI can render itself dynamically.
"""

from . import (
    dirbuster,
    httpx_probe,
    nmap_scan,
    nuclei_scan,
    reverseip,
    subdomain,
    techdetect,
    whois_lookup,
)

REGISTRY = {
    "subdomains": subdomain.stream,
    "nmap": nmap_scan.stream,
    "httpx": httpx_probe.stream,
    "nuclei": nuclei_scan.stream,
    "whois": whois_lookup.stream,
    "reverse": reverseip.stream,
    "tech": techdetect.stream,
    "dirbuster": dirbuster.stream,
}

TOOLS = [
    {
        "id": "subdomains",
        "name": "Subdomain Enum",
        "description": "Discover subdomains with subfinder",
        "icon": "globe",
        "target_label": "Domain",
        "placeholder": "example.com",
    },
    {
        "id": "nmap",
        "name": "Port Scan",
        "description": "Map open ports & services with nmap",
        "icon": "radar",
        "target_label": "Host / IP",
        "placeholder": "scanme.nmap.org",
        "options": [
            {
                "key": "scan_type",
                "label": "Scan profile",
                "default": "quick",
                "choices": [
                    {"value": "quick", "label": "Quick (top ports)"},
                    {"value": "service", "label": "Service / version"},
                    {"value": "full", "label": "Full (all ports)"},
                    {"value": "aggressive", "label": "Aggressive (-A)"},
                    {"value": "os", "label": "OS detection"},
                    {"value": "udp", "label": "UDP top 20"},
                ],
            }
        ],
    },
    {
        "id": "httpx",
        "name": "HTTP Probe",
        "description": "Find live hosts & fingerprint them (httpx)",
        "icon": "pulse",
        "target_label": "Host(s) / URL(s)",
        "placeholder": "example.com, sub.example.com",
    },
    {
        "id": "nuclei",
        "name": "Vuln Scan",
        "description": "CVE / misconfig detection (nuclei)",
        "icon": "bug",
        "target_label": "Target(s)",
        "placeholder": "https://example.com",
        "options": [
            {
                "key": "severity",
                "label": "Min severity",
                "default": "low,medium,high,critical",
                "choices": [
                    {"value": "low,medium,high,critical", "label": "Low → Critical"},
                    {"value": "medium,high,critical", "label": "Medium → Critical"},
                    {"value": "high,critical", "label": "High & Critical"},
                    {"value": "critical", "label": "Critical only"},
                    {"value": "all", "label": "Everything (incl. info)"},
                ],
            }
        ],
    },
    {
        "id": "dirbuster",
        "name": "Content Discovery",
        "description": "Brute-force paths with ffuf",
        "icon": "folder",
        "target_label": "URL",
        "placeholder": "https://example.com",
    },
    {
        "id": "tech",
        "name": "Tech Detect",
        "description": "Fingerprint the technology stack",
        "icon": "cpu",
        "target_label": "URL",
        "placeholder": "https://example.com",
    },
    {
        "id": "whois",
        "name": "WHOIS",
        "description": "Registration & ownership records",
        "icon": "id",
        "target_label": "Domain",
        "placeholder": "example.com",
    },
    {
        "id": "reverse",
        "name": "Reverse IP",
        "description": "Find domains sharing an IP",
        "icon": "swap",
        "target_label": "IP / Host",
        "placeholder": "8.8.8.8",
    },
]


def get_scanner(tool_id: str):
    return REGISTRY.get(tool_id)

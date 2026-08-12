"""Nmap scanner — streams live nmap output, returns parsed port/service data."""

import os
import tempfile
import threading
import xml.etree.ElementTree as ET
from typing import Iterator, Optional

from .base import clean_target, error, log, result, stream_command

SCAN_PROFILES = {
    "quick": ["-T4", "-F"],
    "service": ["-sV", "-T4"],
    "full": ["-p-", "-sV", "--min-rate", "1000", "-T4", "-Pn", "--stats-every", "2s"],
    "aggressive": [
        "-A", "-sV", "--version-intensity", "5", "-O",
        "--script=default,safe", "-T4", "-Pn", "--stats-every", "2s",
    ],
    "os": ["-O"],
    "udp": ["-sU", "--top-ports", "20", "--max-retries", "1", "-T4", "-Pn"],
}


def _parse_xml(xml_text: str, scan_type: str) -> dict:
    root = ET.fromstring(xml_text)
    host_node = root.find("host")
    if host_node is None:
        return {"error": "Host appears to be down or no results were returned."}

    address = host_node.find("address")
    ip = address.attrib.get("addr") if address is not None else "unknown"

    if scan_type == "os":
        os_node = host_node.find("os")
        match = os_node.find("osmatch") if os_node is not None else None
        return {
            "host": ip,
            "scan_type": "os",
            "os": match.attrib.get("name") if match is not None else "Not detected",
        }

    ports = []
    ports_node = host_node.find("ports")
    if ports_node is not None:
        for port in ports_node.findall("port"):
            state = port.find("state")
            service = port.find("service")
            item = {
                "port": port.attrib.get("portid"),
                "protocol": port.attrib.get("protocol"),
                "state": state.attrib.get("state") if state is not None else "",
                "service": service.attrib.get("name") if service is not None else "",
            }
            if scan_type in ("service", "full", "aggressive"):
                item["product"] = (
                    service.attrib.get("product", "") if service is not None else ""
                )
                item["version"] = (
                    service.attrib.get("version", "") if service is not None else ""
                )
            ports.append(item)

    extra = {}
    if scan_type == "aggressive":
        hostnames_node = host_node.find("hostnames")
        if hostnames_node is not None:
            names = [h.attrib.get("name") for h in hostnames_node.findall("hostname")]
            if names:
                extra["hostnames"] = names
        os_node = host_node.find("os")
        match = os_node.find("osmatch") if os_node is not None else None
        if match is not None:
            extra["os"] = match.attrib.get("name")

    open_count = sum(1 for p in ports if p["state"] == "open")
    return {
        "host": ip,
        "scan_type": scan_type,
        "open_ports": open_count,
        **extra,
        "ports": ports,
    }


def stream(target: str, scan_type: str = "quick", cancel: Optional[threading.Event] = None, **_) -> Iterator[dict]:
    host = clean_target(target)
    if not host:
        yield error("A target host is required.")
        return

    args = SCAN_PROFILES.get(scan_type, SCAN_PROFILES["quick"])
    yield log(f"Starting nmap '{scan_type}' scan against {host}")

    fd, xml_path = tempfile.mkstemp(suffix=".xml", prefix="reconx_nmap_")
    os.close(fd)
    try:
        cmd = ["nmap", *args, "-oX", xml_path, host]
        rc = 0
        for ev in stream_command(cmd, cancel=cancel):
            if ev["type"] == "returncode":
                rc = ev["data"]
            else:
                yield ev

        if cancel is not None and cancel.is_set():
            return

        try:
            with open(xml_path, "r", encoding="utf-8", errors="replace") as fh:
                xml_text = fh.read()
        except OSError:
            xml_text = ""

        if not xml_text.strip():
            yield error(f"nmap returned no parseable output (exit code {rc}).")
            return

        try:
            data = _parse_xml(xml_text, scan_type)
        except ET.ParseError as exc:
            yield error(f"Could not parse nmap XML: {exc}")
            return

        if "error" in data:
            yield error(data["error"])
            return

        yield log(f"✔ Parsed {data.get('open_ports', 0)} open port(s).")
        yield result(data)
    finally:
        try:
            os.unlink(xml_path)
        except OSError:
            pass

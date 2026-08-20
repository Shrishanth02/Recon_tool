"""P0 tests for the dnspython-backed DNS zone-transfer scanner.

These exercise :func:`app.scanners.dns_zone_transfer.stream` fully offline by
monkeypatching dnspython so no real DNS/AXFR ever leaves the machine:

* every nameserver *refusing* the transfer  -> ``vulnerable`` is ``False``
* a nameserver *allowing* the transfer       -> ``vulnerable`` is ``True`` and
  the flattened zone records are returned.

The whole module is skipped if dnspython is not importable (the scanner itself
degrades gracefully in that case, which is covered by the guard below).
"""

import pytest

# The scanner imports dnspython lazily and degrades gracefully without it, but
# these tests drive the *success* path, which needs the real library present.
pytest.importorskip("dns")

import dns.query  # noqa: E402
import dns.rdataclass  # noqa: E402
import dns.rdatatype  # noqa: E402
import dns.zone  # noqa: E402

from app.scanners import dns_zone_transfer as dzt  # noqa: E402


# --------------------------------------------------------------------------- #
# Fake dnspython zone objects (shape mirrors what stream() flattens).
# --------------------------------------------------------------------------- #
class _FakeRdataset(list):
    """A list of rdata that also carries ttl/rdclass/rdtype like dnspython's."""

    def __init__(self, ttl, rdclass, rdtype, rdatas):
        super().__init__(rdatas)
        self.ttl = ttl
        self.rdclass = rdclass
        self.rdtype = rdtype


class _FakeNode:
    def __init__(self, rdatasets):
        self.rdatasets = rdatasets


class _FakeZone:
    def __init__(self, nodes):
        self.nodes = nodes


def _drain(target="example.com"):
    """Run the scanner and return ``(events, result_data)``."""
    events = list(dzt.stream(target))
    result = next(e["data"] for e in events if e["type"] == "result")
    return events, result


# --------------------------------------------------------------------------- #
# Refusal path -> not vulnerable.
# --------------------------------------------------------------------------- #
def test_refused_zone_transfer_is_not_vulnerable(monkeypatch):
    monkeypatch.setattr(dzt, "_get_nameservers", lambda domain: ["ns1.example.com"])
    monkeypatch.setattr(dzt, "_resolve_ips", lambda ns: ["192.0.2.1"])

    # Every AXFR attempt is refused (the healthy, expected server behavior).
    def _refuse(*args, **kwargs):
        raise Exception("REFUSED")

    monkeypatch.setattr(dns.query, "xfr", _refuse)

    events, result = _drain("example.com")

    assert result["vulnerable"] is False
    assert result["vulnerable_nameservers"] == []
    assert result["records"] == []
    assert result["record_count"] == 0
    assert result["nameservers"] == ["ns1.example.com"]
    # The reassuring "no nameserver allowed zone transfer" log is emitted.
    logs = " ".join(e["data"] for e in events if e["type"] == "log")
    assert "No nameserver allowed zone transfer" in logs


def test_no_nameservers_is_not_vulnerable(monkeypatch):
    # Domain has no NS records (or does not resolve) -> nothing to try.
    monkeypatch.setattr(dzt, "_get_nameservers", lambda domain: [])

    _events, result = _drain("example.com")

    assert result["vulnerable"] is False
    assert result["nameservers"] == []
    assert result["records"] == []


# --------------------------------------------------------------------------- #
# Success path -> vulnerable, with records.
# --------------------------------------------------------------------------- #
def test_successful_zone_transfer_is_vulnerable_with_records(monkeypatch):
    monkeypatch.setattr(dzt, "_get_nameservers", lambda domain: ["ns1.example.com"])
    monkeypatch.setattr(dzt, "_resolve_ips", lambda ns: ["192.0.2.1"])

    nodes = {
        "@": _FakeNode(
            [
                _FakeRdataset(
                    3600, dns.rdataclass.IN, dns.rdatatype.A, ["192.0.2.10"]
                )
            ]
        ),
        "www": _FakeNode(
            [
                _FakeRdataset(
                    3600, dns.rdataclass.IN, dns.rdatatype.A, ["192.0.2.11"]
                )
            ]
        ),
    }

    # xfr's return value is fed straight into from_xfr, which we stub out.
    monkeypatch.setattr(dns.query, "xfr", lambda *a, **k: object())
    monkeypatch.setattr(dns.zone, "from_xfr", lambda *a, **k: _FakeZone(nodes))

    events, result = _drain("example.com")

    assert result["vulnerable"] is True
    assert result["vulnerable_nameservers"] == ["ns1.example.com"]
    assert result["record_count"] == 2
    assert len(result["records"]) == 2
    # Records are flattened to printable strings carrying name + type + rdata.
    joined = " ".join(result["records"])
    assert "192.0.2.10" in joined
    assert "192.0.2.11" in joined
    assert " A " in joined

    # The CRITICAL alert log line is preserved for detection/alerting.
    logs = "\n".join(e["data"] for e in events if e["type"] == "log")
    assert "ZONE TRANSFER SUCCEEDED" in logs
    assert "CRITICAL" in logs


def test_empty_target_yields_error(monkeypatch):
    events = list(dzt.stream("   "))
    assert any(e["type"] == "error" for e in events)
    assert not any(e["type"] == "result" for e in events)

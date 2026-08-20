"""Feature 1 tests: nmap/version -> known-CVE enrichment.

Covers the offline version-range matcher (positive / negative / boundary /
malformed) and the nmap derive branch that turns a version match into a SIGNAL
vuln finding — never a false positive from a version merely "looking old".
"""

from app import crud, vulndb


# --------------------------------------------------------------------------- #
# Version comparator
# --------------------------------------------------------------------------- #
def test_version_comparator_orders_correctly():
    assert vulndb._cmp("1.0.1", "1.0.1f") < 0
    assert vulndb._cmp("1.0.1f", "1.0.1g") < 0
    assert vulndb._cmp("9.5p1", "9.6") < 0
    assert vulndb._cmp("9.6", "9.6p1") < 0        # 9.6p1 is a later build than 9.6
    assert vulndb._cmp("2.4.49", "2.4.9") > 0     # numeric, not lexical (49 > 9)
    assert vulndb._cmp("2.3.4", "2.3.4") == 0


# --------------------------------------------------------------------------- #
# Matcher — positive
# --------------------------------------------------------------------------- #
def test_openssh_terrapin_positive():
    hits = vulndb.match("OpenSSH", "8.2p1")
    assert len(hits) == 1
    assert hits[0]["cve"] == "CVE-2023-48795"
    assert hits[0]["severity"] == "medium"        # cvss 5.9
    assert hits[0]["affected_range"] == "< 9.6"


def test_openssl_heartbleed_inclusive_boundary():
    assert vulndb.match("OpenSSL", "1.0.1")        # ge boundary
    assert vulndb.match("OpenSSL", "1.0.1f")       # le boundary
    assert vulndb.match("OpenSSL", "1.0.1c")


def test_vsftpd_backdoor_is_critical():
    hits = vulndb.match("vsftpd", "2.3.4")
    assert hits and hits[0]["cve"] == "CVE-2011-2523"
    assert hits[0]["severity"] == "critical"       # cvss 9.8


# --------------------------------------------------------------------------- #
# Matcher — negative (no false positives)
# --------------------------------------------------------------------------- #
def test_fixed_versions_do_not_match():
    assert vulndb.match("OpenSSH", "9.6p1") == []   # fixed (not < 9.6)
    assert vulndb.match("OpenSSH", "9.7") == []
    assert vulndb.match("OpenSSL", "1.0.1g") == []  # fixed (> 1.0.1f)
    assert vulndb.match("OpenSSL", "1.0.0") == []   # older than affected range
    assert vulndb.match("Apache httpd", "2.4.48") == []
    assert vulndb.match("Apache httpd", "2.4.50") == []  # eq 2.4.49 only
    assert vulndb.match("vsftpd", "3.0.3") == []


def test_product_mismatch_is_not_a_match():
    # Same version that WOULD match OpenSSL, but a different product -> no match.
    assert vulndb.match("nginx", "1.0.1f") == []


def test_missing_version_or_product_returns_empty():
    assert vulndb.match("OpenSSH", "") == []
    assert vulndb.match("", "8.2p1") == []
    assert vulndb.match("OpenSSH", None) == []


def test_malformed_version_does_not_crash():
    assert vulndb.match("OpenSSH", "unknown") == []
    assert vulndb.match("OpenSSL", "n/a") == []


# --------------------------------------------------------------------------- #
# derive_findings — nmap CVE enrichment
# --------------------------------------------------------------------------- #
def _nmap_result(product, version, port="22", service="ssh", cpe=None):
    p = {"port": port, "protocol": "tcp", "state": "open", "service": service,
         "product": product, "version": version}
    if cpe:
        p["cpe"] = cpe
    return {"host": "10.0.0.5", "ports": [p]}


def test_nmap_derive_emits_recon_and_cve_finding():
    out = crud.derive_findings("nmap", _nmap_result("OpenSSH", "8.2p1",
                                                    cpe=["cpe:/a:openbsd:openssh:8.2p1"]))
    recon = [f for f in out if f["kind"] == "recon"]
    vulns = [f for f in out if f["kind"] == "vuln"]
    assert len(recon) == 1                          # open-port recon still emitted
    assert len(vulns) == 1
    v = vulns[0]
    assert v["detection_tier"] == "signal"          # version inference, not validated
    assert v["confidence"] == 60
    assert v["cve"] == ["CVE-2023-48795"]
    assert v["evidence"]["version"] == "8.2p1"
    assert v["evidence"]["affected_range"] == "< 9.6"
    assert v["evidence"]["matched_via"] == "nmap-version"
    assert v["evidence"]["cpe"] == ["cpe:/a:openbsd:openssh:8.2p1"]


def test_nmap_derive_no_cve_for_fixed_version():
    out = crud.derive_findings("nmap", _nmap_result("OpenSSH", "9.7"))
    assert all(f["kind"] != "vuln" for f in out)     # only the recon finding


def test_nmap_derive_no_cve_without_version():
    out = crud.derive_findings("nmap", _nmap_result("OpenSSH", ""))
    assert [f for f in out if f["kind"] == "recon"]
    assert all(f["kind"] != "vuln" for f in out)


def test_nmap_derive_handles_malformed_result():
    # Missing/empty ports must not crash derivation.
    assert crud.derive_findings("nmap", {"host": "h"}) == []
    assert crud.derive_findings("nmap", {"host": "h", "ports": []}) == []

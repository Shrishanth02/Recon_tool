"""Unit tests for :mod:`app.diffing` — the pure finding differ.

Verifies the new/resolved/unchanged partition, identity by
``(severity, name, location)``, count correctness, key normalization, and the
empty/None edge cases. No DB / network.
"""

from app import diffing


def _f(severity, name, location, **extra):
    d = {"severity": severity, "name": name, "location": location}
    d.update(extra)
    return d


def test_partition_new_resolved_unchanged():
    shared = _f("high", "XSS", "https://a/x")
    only_prev = _f("low", "Info Leak", "https://a/old")
    only_cur = _f("critical", "RCE", "https://a/new")

    previous = [shared, only_prev]
    current = [shared, only_cur]

    out = diffing.diff_findings(previous, current)

    assert out["new"] == [only_cur]
    assert out["resolved"] == [only_prev]
    assert out["unchanged"] == [shared]
    assert out["counts"] == {"new": 1, "resolved": 1, "unchanged": 1}


def test_counts_match_lists():
    previous = [_f("high", "A", "1"), _f("high", "B", "2")]
    current = [_f("high", "B", "2"), _f("high", "C", "3"), _f("medium", "D", "4")]

    out = diffing.diff_findings(previous, current)

    assert out["counts"]["new"] == len(out["new"]) == 2   # C, D
    assert out["counts"]["resolved"] == len(out["resolved"]) == 1  # A
    assert out["counts"]["unchanged"] == len(out["unchanged"]) == 1  # B


def test_identity_uses_severity_name_location_triple():
    # Same name+location but a different severity is a distinct finding:
    # the old one is "resolved" and the new one is "new".
    previous = [_f("low", "Open Port", "host:80")]
    current = [_f("high", "Open Port", "host:80")]

    out = diffing.diff_findings(previous, current)

    assert out["counts"] == {"new": 1, "resolved": 1, "unchanged": 0}
    assert out["new"][0]["severity"] == "high"
    assert out["resolved"][0]["severity"] == "low"


def test_key_normalization_collapses_case_and_whitespace():
    previous = [_f("HIGH", "  SQL Injection ", "HTTPS://A/X")]
    current = [_f("high", "sql injection", "https://a/x")]

    out = diffing.diff_findings(previous, current)

    # Despite different rendering, they're the same finding -> unchanged.
    assert out["counts"] == {"new": 0, "resolved": 0, "unchanged": 1}
    # The current copy is the one retained in `unchanged`.
    assert out["unchanged"][0] is current[0]


def test_all_new_when_previous_empty():
    current = [_f("high", "A", "1"), _f("low", "B", "2")]
    out = diffing.diff_findings([], current)
    assert out["counts"] == {"new": 2, "resolved": 0, "unchanged": 0}
    assert out["new"] == current


def test_all_resolved_when_current_empty():
    previous = [_f("high", "A", "1")]
    out = diffing.diff_findings(previous, [])
    assert out["counts"] == {"new": 0, "resolved": 1, "unchanged": 0}
    assert out["resolved"] == previous


def test_both_empty_and_none_inputs():
    assert diffing.diff_findings([], [])["counts"] == {
        "new": 0,
        "resolved": 0,
        "unchanged": 0,
    }
    # None is tolerated (treated as empty).
    out = diffing.diff_findings(None, None)  # type: ignore[arg-type]
    assert out["new"] == [] and out["resolved"] == [] and out["unchanged"] == []


def test_original_objects_are_preserved_not_keys():
    cur = _f("high", "A", "1", description="detail", cve=["CVE-1"])
    out = diffing.diff_findings([], [cur])
    # The returned list holds the original dict, not the identity tuple.
    assert out["new"][0] is cur
    assert out["new"][0]["cve"] == ["CVE-1"]

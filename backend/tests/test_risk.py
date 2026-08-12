"""Unit tests for :mod:`app.risk` — the pure workspace risk scorer.

These exercise the dependency-free scoring logic directly (no DB / network):
empty input, severity weighting, rating bands, monotonicity, the 100 cap, and
correct per-severity counts.
"""

from app import risk


def test_empty_findings_score_zero_informational():
    out = risk.workspace_risk([])
    assert out["score"] == 0
    assert out["rating"] == "Informational"
    assert out["total"] == 0
    # Every canonical bucket present and zero.
    assert out["counts"] == {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }


def test_none_findings_treated_as_empty():
    # `findings or []` guards a None input.
    out = risk.workspace_risk(None)  # type: ignore[arg-type]
    assert out["score"] == 0
    assert out["rating"] == "Informational"
    assert out["total"] == 0


def test_single_critical_lands_in_medium_band():
    # One critical == weight 40 -> score 40 -> "Medium" band (>=25, <50).
    out = risk.workspace_risk([{"severity": "critical"}])
    assert out["score"] == 40
    assert out["rating"] == "Medium"
    assert out["counts"]["critical"] == 1
    assert out["total"] == 1


def test_multiple_criticals_reach_high_score_and_critical_rating():
    # Two criticals == 80 -> "Critical" (>=75); many criticals cap at 100.
    two = risk.workspace_risk([{"severity": "critical"}, {"severity": "critical"}])
    assert two["score"] == 80
    assert two["rating"] == "Critical"
    assert two["counts"]["critical"] == 2

    many = risk.workspace_risk([{"severity": "critical"}] * 5)
    assert many["score"] == 100  # capped
    assert many["rating"] == "Critical"


def test_score_is_capped_at_100():
    out = risk.workspace_risk([{"severity": "high"}] * 100)
    assert out["score"] == 100
    assert out["rating"] == "Critical"


def test_counts_reflect_severity_distribution():
    findings = [
        {"severity": "critical"},
        {"severity": "high"},
        {"severity": "high"},
        {"severity": "medium"},
        {"severity": "low"},
        {"severity": "low"},
        {"severity": "low"},
        {"severity": "info"},
    ]
    out = risk.workspace_risk(findings)
    assert out["counts"] == {
        "critical": 1,
        "high": 2,
        "medium": 1,
        "low": 3,
        "info": 1,
    }
    assert out["total"] == 8
    # 40 + 2*18 + 7 + 3*2 + 0 == 89
    assert out["score"] == 89
    assert out["rating"] == "Critical"


def test_unknown_and_missing_severity_collapse_to_info():
    findings = [
        {"severity": "wat"},   # unknown -> info
        {"severity": ""},      # empty -> info
        {},                    # missing -> info
        {"severity": None},    # None -> info
    ]
    out = risk.workspace_risk(findings)
    assert out["counts"]["info"] == 4
    assert out["score"] == 0
    assert out["rating"] == "Informational"
    assert out["total"] == 4


def test_score_is_monotonic_when_adding_findings():
    base = [{"severity": "low"}]
    worse = base + [{"severity": "critical"}]
    worst = worse + [{"severity": "high"}]
    s_base = risk.workspace_risk(base)["score"]
    s_worse = risk.workspace_risk(worse)["score"]
    s_worst = risk.workspace_risk(worst)["score"]
    # Adding a (worse) finding never lowers the score.
    assert s_base <= s_worse <= s_worst
    assert s_base == 2
    assert s_worse == 42


def test_accepts_objects_with_severity_attribute():
    class F:
        def __init__(self, severity):
            self.severity = severity

    out = risk.workspace_risk([F("critical"), F("high")])
    assert out["counts"]["critical"] == 1
    assert out["counts"]["high"] == 1
    assert out["score"] == 58

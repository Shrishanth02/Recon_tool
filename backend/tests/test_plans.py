"""Static plan-catalog tests (:mod:`app.plans`).

These are pure-data assertions: the catalog is stdlib-only and has no DB or
network dependency, so they never touch fixtures. They pin the shape of
``plan_limits`` and the concrete free/starter/pro/mssp values, the unknown-plan
fallback to ``free``, and the ``feature_enabled`` helper.
"""

from app import plans

# Every limits mapping must carry exactly these keys.
_LIMIT_KEYS = {
    "assets",
    "seats",
    "scans_per_month",
    "ai",
    "continuous",
    "integrations",
    "white_label",
}


def test_all_plans_share_the_same_limits_shape():
    for plan_id in ("free", "starter", "pro", "mssp"):
        limits = plans.plan_limits(plan_id)
        assert set(limits.keys()) == _LIMIT_KEYS, plan_id
        # Numeric quotas are int or None (unlimited); features are bools.
        for key in ("assets", "seats", "scans_per_month"):
            assert limits[key] is None or isinstance(limits[key], int)
        for key in ("ai", "continuous", "integrations", "white_label"):
            assert isinstance(limits[key], bool)


def test_free_plan_values():
    limits = plans.plan_limits("free")
    assert limits["assets"] == 1
    assert limits["seats"] == 2
    assert limits["scans_per_month"] == 20
    assert limits["ai"] is False
    assert limits["continuous"] is False
    assert limits["integrations"] is False
    assert limits["white_label"] is False


def test_starter_plan_values():
    limits = plans.plan_limits("starter")
    assert limits["assets"] == 3
    assert limits["seats"] == 3
    assert limits["scans_per_month"] == 200
    assert limits["ai"] is False
    assert limits["continuous"] is True
    assert limits["integrations"] is False
    assert limits["white_label"] is False


def test_pro_plan_values():
    limits = plans.plan_limits("pro")
    assert limits["assets"] == 25
    assert limits["seats"] == 10
    assert limits["scans_per_month"] == 2000
    assert limits["ai"] is True
    assert limits["continuous"] is True
    assert limits["integrations"] is True
    assert limits["white_label"] is False


def test_mssp_plan_is_unlimited_and_white_label():
    limits = plans.plan_limits("mssp")
    assert limits["assets"] is None
    assert limits["seats"] is None
    assert limits["scans_per_month"] is None
    assert limits["ai"] is True
    assert limits["continuous"] is True
    assert limits["integrations"] is True
    assert limits["white_label"] is True


def test_unknown_plan_falls_back_to_free():
    free = plans.plan_limits("free")
    assert plans.plan_limits("does-not-exist") == free
    assert plans.plan_limits("") == free
    assert plans.plan_limits(None) == free
    # Case/whitespace are normalized.
    assert plans.plan_limits("  PRO  ") == plans.plan_limits("pro")


def test_plan_limits_returns_a_copy_not_the_catalog():
    limits = plans.plan_limits("free")
    limits["assets"] = 9999
    # Mutating the returned dict must not corrupt the shared catalog.
    assert plans.plan_limits("free")["assets"] == 1


def test_feature_enabled():
    assert plans.feature_enabled("pro", "ai") is True
    assert plans.feature_enabled("free", "ai") is False
    assert plans.feature_enabled("starter", "continuous") is True
    assert plans.feature_enabled("mssp", "white_label") is True
    # Unknown feature -> False; unknown plan -> free semantics.
    assert plans.feature_enabled("pro", "teleportation") is False
    assert plans.feature_enabled("nonsense", "ai") is False

"""Feature 3 unit tests: authenticated-session gating + config sanitization.

The pipeline-integration tests (auth crawl -> injection, scope/netguard gating,
cap, evidence annotation, unauth unchanged) live in ``test_pipeline_p0.py`` where
the stubbed-pipeline fixture is defined.
"""

from app.pipeline import _has_auth
from app.routers.pipeline_ws import _extract_auth


def test_has_auth_requires_a_usable_session():
    assert _has_auth(None) is False
    assert _has_auth({}) is False
    assert _has_auth({"cookie": ""}) is False
    assert _has_auth({"cookie": "  "}) is False
    assert _has_auth({"cookie": "session=abc"}) is True
    assert _has_auth({"auth_header": "Bearer x"}) is True
    assert _has_auth({"username": "u", "password": "p"}) is True
    assert _has_auth({"username": "u"}) is False        # both required
    assert _has_auth({"password": "p"}) is False


def test_extract_auth_keeps_only_known_nonempty_fields():
    assert _extract_auth(None) is None
    assert _extract_auth("nope") is None
    assert _extract_auth({}) is None
    assert _extract_auth({"cookie": "   ", "password": ""}) is None
    out = _extract_auth({
        "cookie": " c=1 ", "username": "u", "password": "p",
        "unknown": "drop-me", "auth_header": "",
    })
    assert out == {"cookie": "c=1", "username": "u", "password": "p"}
    assert "unknown" not in out
    assert "auth_header" not in out                     # empty dropped

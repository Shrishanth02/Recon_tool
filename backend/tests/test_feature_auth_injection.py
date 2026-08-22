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


def test_extract_auth_keeps_token_for_jwt_stage():
    # #3 regression: a standalone JWT must survive sanitization so the pipeline's
    # JWT/API stage (which reads config.auth["token"]) actually receives it.
    assert _extract_auth({"token": " eyJ.a.b "}) == {"token": "eyJ.a.b"}


def test_extract_auth_keeps_scanner_native_login_selectors():
    # #2 regression: auth_crawl reads user_sel / pass_sel / submit_sel. The prior
    # allowlist kept *_selector instead, so custom selectors were dropped and the
    # crawler always fell back to its defaults. THOSE keys must pass; the mismatched
    # *_selector names must not (they are not what the scanner reads).
    out = _extract_auth({
        "user_sel": "#u", "pass_sel": "#p", "submit_sel": "#go",
        "login_url": "https://x/login",
        "user_selector": "wrong", "pass_selector": "wrong", "submit_selector": "wrong",
    })
    assert out["user_sel"] == "#u" and out["pass_sel"] == "#p" and out["submit_sel"] == "#go"
    assert out["login_url"] == "https://x/login"
    for wrong in ("user_selector", "pass_selector", "submit_selector", "login_selector"):
        assert wrong not in out


def test_extract_auth_allowlist_covers_scanner_option_reads():
    # Contract guard against re-introducing a sanitizer<->scanner key mismatch:
    # every credential/selector option auth_crawl & jwt_audit READ must survive
    # _extract_auth. (auth_crawl: cookie/auth_header/username/password/login_url/
    # user_sel/pass_sel/submit_sel ; jwt_audit: token.)
    consumed = ("cookie", "auth_header", "username", "password", "login_url",
                "user_sel", "pass_sel", "submit_sel", "token")
    out = _extract_auth({k: "v" for k in consumed})
    for k in consumed:
        assert k in out, f"sanitizer must pass {k!r} through to the scanners"

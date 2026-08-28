"""Role-matrix authorization scanning (broken access control / privilege
escalation, CWE-285/862) — read-only, HTTP monkeypatched.

Positive: a lower-privilege principal reaching a higher one's resource on a
privileged path, behind-auth endpoint, or where a boundary is demonstrably
enforced. Negative / FP guards: proper enforcement, public pages, per-user
resources that only differ by data, login pages, and missing identities. Also
checks the finding is CWE-285/862 vuln and that evidence leaks no body/credential.
"""

import json

from app import crud
from app.scanners import role_matrix as rm

ADMIN = "<html><body><h1>Admin Panel</h1> user management console, 42 accounts</body></html>"
LOGIN = "<html><form>Please sign in <input type=password></form></html>"
REPORT = "<html><body>Quarterly financial report Q3 revenue 1200000 usd</body></html>"
HOME_A = "<html><body>Welcome Alice, balance 500, 12 orders here today</body></html>"
HOME_B = "<html><body>Welcome Bob, balance 900, 34 orders here today</body></html>"

USER = [{"label": "user", "cookie": "u=1"}]
USER_ADMIN = [{"label": "user", "cookie": "u=1", "privilege": 0},
              {"label": "admin", "cookie": "a=1", "privilege": 1}]


def _run(monkeypatch, url, identities, probe, authenticated=False):
    monkeypatch.setattr(rm, "_probe", lambda u, h: probe(h))
    events = list(rm.stream(url, identities=identities, authenticated=authenticated))
    return next(e["data"] for e in events if e["type"] == "result")


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def test_classify():
    assert rm._classify(200, ADMIN) == "allowed"
    assert rm._classify(403, "forbidden") == "denied"
    assert rm._classify(401, "") == "denied"
    assert rm._classify(302, "") == "denied"            # redirect (login) not access
    assert rm._classify(200, LOGIN) == "denied"         # 200 login page
    assert rm._classify(200, "hi") == "denied"          # too small to be substantive
    assert rm._classify(404, "x") == "missing"


def test_equivalent_and_privilege():
    assert rm._equivalent(ADMIN, ADMIN)
    assert rm._equivalent(ADMIN, "  " + ADMIN.replace("> ", ">  ") + "  ")  # whitespace-insensitive
    assert not rm._equivalent(HOME_A, HOME_B)           # per-user data differs
    assert rm._privilege({"privilege": 5}, 0) == 5
    # List POSITION is NOT a privilege signal — an identity with no explicit rank
    # is an equal peer (0), never "lower" because it was listed first. This was
    # the list-order false positive.
    assert rm._privilege({}, 3) == 0
    assert rm._privilege({"privilege": True}, 2) == 0   # bool is not a valid rank -> peer


# --------------------------------------------------------------------------- #
# Positive detections
# --------------------------------------------------------------------------- #
def test_privileged_path_anon_reaches_admin_flagged(monkeypatch):
    r = _run(monkeypatch, "https://x/admin", USER, lambda h: (200, ADMIN))
    f = r["findings"]
    assert len(f) == 1
    assert f[0]["severity"] == "high" and f[0]["cwe"] == ["CWE-285", "CWE-862"]
    assert f[0]["detection_tier"] == "validated"
    assert "anonymous" in f[0]["evidence"]["escalating_principals"]
    assert f[0]["evidence"]["privileged_signal"] is True


def test_behind_auth_endpoint_anon_reaches_flagged(monkeypatch):
    # not a privileged path, but discovered behind authentication
    r = _run(monkeypatch, "https://x/dashboard/data", USER,
             lambda h: (200, ADMIN), authenticated=True)
    f = r["findings"]
    assert len(f) == 1
    assert f[0]["evidence"]["discovered_behind_auth"] is True


def test_differential_boundary_flagged(monkeypatch):
    def p(h):
        if h.get("Cookie") == "a=1":
            return (200, REPORT)                 # admin allowed
        if h.get("Cookie") == "u=1":
            return (403, "forbidden")            # low-priv user denied -> boundary
        return (200, REPORT)                     # anon allowed same as admin!

    r = _run(monkeypatch, "https://x/reports/q3", USER_ADMIN, p)
    f = r["findings"]
    assert len(f) == 1
    assert f[0]["evidence"]["authorization_boundary_observed"] is True
    assert f[0]["confidence"] == 80


# --------------------------------------------------------------------------- #
# Negative / false-positive guards
# --------------------------------------------------------------------------- #
def test_enforced_admin_not_flagged(monkeypatch):
    r = _run(monkeypatch, "https://x/admin", USER,
             lambda h: (200, ADMIN) if h else (403, "forbidden"))
    assert r["findings"] == []


def test_public_page_not_flagged(monkeypatch):
    # non-privileged path, no principal denied -> no boundary, no signal
    r = _run(monkeypatch, "https://x/home", USER, lambda h: (200, ADMIN))
    assert r["findings"] == []


def test_per_user_resources_not_flagged(monkeypatch):
    def p(h):
        if h.get("Cookie") == "a=1":
            return (200, HOME_B)
        if h.get("Cookie") == "u=1":
            return (200, HOME_A)
        return (403, "forbidden")

    r = _run(monkeypatch, "https://x/account", USER_ADMIN, p, authenticated=True)
    assert r["findings"] == []


# --------------------------------------------------------------------------- #
# List-order-as-privilege false positive (P1) + explicit-rank detection kept.
# --------------------------------------------------------------------------- #
PEERS = [{"label": "alice", "cookie": "a=1"}, {"label": "bob", "cookie": "b=1"}]


def test_peer_identities_no_explicit_privilege_not_flagged(monkeypatch):
    """Two SAME-ROLE peers (no explicit privilege) both viewing the same shared
    page, with anon redirected to login, must NOT be a privilege escalation. The
    old code treated the earlier-listed identity as strictly lower privilege and
    false-flagged it."""
    def p(h):
        if h.get("Cookie"):
            return (200, ADMIN)          # both peers see the same shared page
        return (302, "")                 # anon -> login -> denied (boundary exists)

    r = _run(monkeypatch, "https://x/dashboard", PEERS, p, authenticated=True)
    assert r["findings"] == []


def test_explicit_privilege_escalation_still_flagged(monkeypatch):
    """DETECTION PRESERVED: when the operator DECLARES ranks, a strictly
    lower-privilege identity reaching the higher one's resource is still a
    validated finding."""
    ids = [{"label": "low", "cookie": "l=1", "privilege": 0},
           {"label": "high", "cookie": "h=1", "privilege": 5}]

    def p(h):
        if h.get("Cookie"):
            return (200, ADMIN)          # both authenticated see the admin resource
        return (302, "")                 # anon denied -> boundary

    r = _run(monkeypatch, "https://x/admin/users", ids, p)
    f = r["findings"]
    assert len(f) == 1
    assert f[0]["detection_tier"] == "validated"
    assert "low" in f[0]["evidence"]["escalating_principals"]
    assert "high" not in f[0]["evidence"]["escalating_principals"]


def test_login_page_not_counted_allowed(monkeypatch):
    r = _run(monkeypatch, "https://x/admin", USER, lambda h: (200, LOGIN))
    assert r["findings"] == []


def test_no_identity_skips(monkeypatch):
    r = _run(monkeypatch, "https://x/admin", [], lambda h: (200, ADMIN))
    assert r["findings"] == [] and r["principals"] == []


def test_malformed_target_errors():
    events = list(rm.stream("-oX", identities=USER))
    assert any(e["type"] == "error" for e in events)


# --------------------------------------------------------------------------- #
# Schema / evidence safety
# --------------------------------------------------------------------------- #
def test_derive_role_matrix_is_vuln():
    result = {"findings": [{
        "severity": "high", "name": "Broken access control at /admin",
        "location": "https://x/admin", "cwe": ["CWE-285", "CWE-862"],
        "detection_tier": "validated", "confidence": 80,
        "evidence": {"endpoint": "https://x/admin", "escalating_principals": ["anonymous"]}}]}
    out = crud.derive_findings("role_matrix", result)
    assert out and out[0]["kind"] == "vuln" and out[0]["detection_tier"] == "validated"
    assert out[0]["confidence"] == 80 and "CWE-285" in str(out[0]["cwe"])


def test_evidence_leaks_no_body_or_credential(monkeypatch):
    r = _run(monkeypatch, "https://x/admin", USER, lambda h: (200, ADMIN))
    blob = json.dumps(r["findings"][0]["evidence"])
    assert "Admin Panel" not in blob and "console" not in blob   # no response body
    assert "u=1" not in blob and "Cookie" not in blob            # no credential

"""P1-B1 regression tests — redirect-safe HTTP (per-hop netguard validation).

The security invariant under test: a destination that fails scope/netguard is
NEVER contacted. Every test that expects a block asserts the blocked URL is
absent from the recording session's ``calls`` — i.e. no connection was made, not
merely that the response wasn't parsed.

A ``FakeSession`` records every URL the helper actually requests and returns
scripted responses, so redirects are simulated with zero network I/O. Blocked
hosts are literal IPs (no DNS) so netguard's decision is deterministic; the test
suite forces ``BLOCK_PRIVATE_TARGETS=true`` (conftest).
"""

import pytest
import requests

from app.safe_http import BlockedDestination, check_destination, safe_request

# Public literal IPs (pass netguard, no DNS) and blocked ones (fail netguard).
PUB = "http://1.1.1.1/"
PUB2 = "http://93.184.216.34/"
PUB6 = "http://[2606:4700:4700::1111]/"

BLOCKED_TARGETS = [
    "http://127.0.0.1/",            # loopback
    "http://localhost/",            # localhost name
    "http://10.0.0.5/",             # RFC1918 private
    "http://192.168.1.10/",         # RFC1918 private
    "http://169.254.1.1/",          # link-local
    "http://169.254.169.254/",      # cloud metadata (IPv4)
    "http://[::1]/",                # IPv6 loopback
    "http://[fe80::1]/",            # IPv6 link-local
    "http://[fd00::1]/",            # IPv6 unique-local (private)
]


class FakeResp:
    def __init__(self, status_code=200, location=None):
        self.status_code = status_code
        self.headers = {}
        if location is not None:
            self.headers["Location"] = location
        self.url = None
        self.text = ""
        self.content = b""


class FakeSession:
    """Records every URL requested; returns scripted responses. No network I/O."""

    def __init__(self, script=None):
        self.script = script or {}
        self.calls = []

    def request(self, method, url, allow_redirects=False, **kwargs):
        # The helper must NEVER let the underlying client auto-follow.
        assert allow_redirects is False, "safe_http let the client auto-follow!"
        self.calls.append(url)
        resp = self.script.get(url) or FakeResp(200)
        resp.url = url
        return resp


# --------------------------------------------------------------------------- #
# Legitimate redirects are followed
# --------------------------------------------------------------------------- #
def test_same_host_absolute_redirect_followed():
    fs = FakeSession({PUB: FakeResp(302, location="http://1.1.1.1/next"),
                      "http://1.1.1.1/next": FakeResp(200)})
    resp = safe_request("GET", PUB, session=fs)
    assert resp.status_code == 200
    assert fs.calls == [PUB, "http://1.1.1.1/next"]


def test_relative_redirect_followed():
    fs = FakeSession({PUB: FakeResp(302, location="/deep/path"),
                      "http://1.1.1.1/deep/path": FakeResp(200)})
    resp = safe_request("GET", PUB, session=fs)
    assert resp.status_code == 200
    assert fs.calls == [PUB, "http://1.1.1.1/deep/path"]


def test_cross_host_public_redirect_followed_without_scope():
    fs = FakeSession({PUB: FakeResp(302, location=PUB2), PUB2: FakeResp(200)})
    resp = safe_request("GET", PUB, session=fs)
    assert resp.status_code == 200
    assert fs.calls == [PUB, PUB2]


def test_public_ipv6_redirect_followed():
    fs = FakeSession({PUB: FakeResp(302, location=PUB6), PUB6: FakeResp(200)})
    resp = safe_request("GET", PUB, session=fs)
    assert resp.status_code == 200
    assert PUB6 in fs.calls


# --------------------------------------------------------------------------- #
# Blocked redirects: raised AND never contacted
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("blocked", BLOCKED_TARGETS)
def test_redirect_to_blocked_target_is_never_contacted(blocked):
    fs = FakeSession({PUB: FakeResp(302, location=blocked)})
    with pytest.raises(BlockedDestination):
        safe_request("GET", PUB, session=fs)
    assert blocked not in fs.calls           # THE invariant: no connection made
    assert fs.calls == [PUB]                  # only the (validated) initial URL


def test_scheme_relative_redirect_to_metadata_blocked():
    fs = FakeSession({PUB: FakeResp(302, location="//169.254.169.254/latest/meta-data/")})
    with pytest.raises(BlockedDestination):
        safe_request("GET", PUB, session=fs)
    assert all("169.254.169.254" not in u for u in fs.calls)


def test_out_of_scope_redirect_blocked_and_not_contacted():
    # scope allows the 1.1.1.1 host but not 93.184.216.34.
    def scope_check(url):
        return ("1.1.1.1" in url, "out of engagement scope")

    fs = FakeSession({PUB: FakeResp(302, location=PUB2), PUB2: FakeResp(200)})
    with pytest.raises(BlockedDestination):
        safe_request("GET", PUB, session=fs, scope_check=scope_check)
    assert PUB2 not in fs.calls
    assert fs.calls == [PUB]


# --------------------------------------------------------------------------- #
# Loops, excess, malformed
# --------------------------------------------------------------------------- #
def test_redirect_loop_detected_and_not_re_contacted():
    fs = FakeSession({PUB: FakeResp(302, location=PUB2),
                      PUB2: FakeResp(302, location=PUB)})
    with pytest.raises(BlockedDestination):
        safe_request("GET", PUB, session=fs)
    assert fs.calls == [PUB, PUB2]           # PUB not requested a second time


def test_excessive_redirects_raises():
    hosts = [f"http://1.1.1.{i}/" for i in range(1, 9)]  # all public
    script = {hosts[i]: FakeResp(302, location=hosts[i + 1]) for i in range(len(hosts) - 1)}
    script[hosts[-1]] = FakeResp(200)
    fs = FakeSession(script)
    with pytest.raises(requests.exceptions.TooManyRedirects):
        safe_request("GET", hosts[0], session=fs, max_redirects=5)
    assert len(fs.calls) <= 6                 # initial + at most 5 follows


@pytest.mark.parametrize("loc", ["javascript:alert(1)", "ftp://1.1.1.1/",
                                 "file:///etc/passwd", "gopher://1.1.1.1/"])
def test_non_http_redirect_scheme_blocked(loc):
    fs = FakeSession({PUB: FakeResp(302, location=loc)})
    with pytest.raises(BlockedDestination):
        safe_request("GET", PUB, session=fs)
    assert fs.calls == [PUB]                  # never followed the odd scheme


def test_redirect_with_empty_location_stops_gracefully():
    fs = FakeSession({PUB: FakeResp(302, location=None)})  # 3xx, no Location
    resp = safe_request("GET", PUB, session=fs)
    assert resp.status_code == 302
    assert fs.calls == [PUB]


# --------------------------------------------------------------------------- #
# allow_redirects=False + initial-URL blocking
# --------------------------------------------------------------------------- #
def test_allow_redirects_false_does_not_follow():
    fs = FakeSession({PUB: FakeResp(302, location=PUB2), PUB2: FakeResp(200)})
    resp = safe_request("GET", PUB, session=fs, allow_redirects=False)
    assert resp.status_code == 302
    assert fs.calls == [PUB]                  # PUB2 never contacted


@pytest.mark.parametrize("blocked", BLOCKED_TARGETS)
def test_blocked_initial_url_makes_no_request(blocked):
    fs = FakeSession()
    with pytest.raises(BlockedDestination):
        safe_request("GET", blocked, session=fs)
    assert fs.calls == []                     # nothing was ever requested


# --------------------------------------------------------------------------- #
# check_destination delegates to netguard (+ optional scope)
# --------------------------------------------------------------------------- #
def test_check_destination_uses_netguard():
    assert check_destination(PUB)[0] is True
    assert check_destination("http://127.0.0.1/")[0] is False
    assert check_destination("http://169.254.169.254/")[0] is False


def test_check_destination_scope_predicate():
    ok, _ = check_destination(PUB, scope_check=lambda u: (False, "nope"))
    assert ok is False
    # a scope hook that raises must fail closed, not propagate.
    ok, reason = check_destination(PUB, scope_check=lambda u: (_ for _ in ()).throw(RuntimeError("x")))
    assert ok is False

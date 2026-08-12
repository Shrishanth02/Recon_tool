"""Phase 5: global session revocation via ``token_version``.

``/auth/logout-all`` bumps the caller's ``token_version`` and returns a fresh
*versioned* token pair (carrying the new ``"ver"`` claim). A subsequent bump
revokes any earlier versioned token -> 401 "session revoked", while the newest
versioned token keeps working. Tokens minted WITHOUT a ``"ver"`` claim (all
pre-Phase-5 tokens) skip the check entirely and still authorize.

Note: the register/login tokens carry no ``"ver"`` claim, so to demonstrate
revocation we first obtain a versioned token (from ``logout-all``), then bump
again and show the now-stale versioned token is rejected.
"""

from app import security


def test_login_token_works(client, auth):
    resp = client.get("/auth/me", headers=auth["headers"])
    assert resp.status_code == 200, resp.text


def test_logout_all_revokes_prior_versioned_token(client, auth):
    # First logout-all: bumps version -> 1 and returns a versioned pair.
    first = client.post("/auth/logout-all", headers=auth["headers"])
    assert first.status_code == 200, first.text
    tok_v1 = first.json()["access_token"]
    hdr_v1 = {"Authorization": f"Bearer {tok_v1}"}

    # The freshly issued versioned token works.
    assert client.get("/auth/me", headers=hdr_v1).status_code == 200

    # Second logout-all (using the v1 token): bumps version -> 2, returns v2.
    second = client.post("/auth/logout-all", headers=hdr_v1)
    assert second.status_code == 200, second.text
    tok_v2 = second.json()["access_token"]
    hdr_v2 = {"Authorization": f"Bearer {tok_v2}"}

    # The now-stale v1 token is revoked...
    stale = client.get("/auth/me", headers=hdr_v1)
    assert stale.status_code == 401
    assert stale.json()["detail"] == "session revoked"

    # ...while the newest versioned token keeps working.
    assert client.get("/auth/me", headers=hdr_v2).status_code == 200


def test_unversioned_token_still_authorizes_after_bump(client, auth):
    # Revoke everything for this user (token_version now > 0).
    assert client.post("/auth/logout-all", headers=auth["headers"]).status_code == 200

    # A token minted WITHOUT a version (no "ver" claim) skips the revocation
    # check and still authorizes — backward compatibility with pre-Phase-5 tokens.
    legacy = security.create_access_token(auth["user_id"])
    resp = client.get("/auth/me", headers={"Authorization": f"Bearer {legacy}"})
    assert resp.status_code == 200, resp.text
    assert resp.json()["user"]["id"] == auth["user_id"]

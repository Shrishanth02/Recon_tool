"""Phase 5: global session revocation via ``token_version``.

``/auth/logout-all`` bumps the caller's ``token_version`` and returns a fresh
token pair carrying the new ``"ver"`` claim. A subsequent bump revokes any
earlier token -> 401 "session revoked", while the newest keeps working.

STEP 2 made this FAIL-CLOSED: a token whose ``"ver"`` (missing => 0) does not
equal the user's current ``token_version`` is rejected — so even a ver-LESS
token no longer bypasses revocation once the version has been bumped.
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


def test_unversioned_token_is_rejected_after_bump(client, auth):
    # Revoke everything for this user (token_version now > 0).
    assert client.post("/auth/logout-all", headers=auth["headers"]).status_code == 200

    # STEP 2 fail-closed: a token minted WITHOUT a "ver" claim is treated as
    # version 0, so after the bump it is REJECTED — it no longer bypasses
    # revocation (this test previously enshrined the fail-OPEN behavior).
    legacy = security.create_access_token(auth["user_id"])
    resp = client.get("/auth/me", headers={"Authorization": f"Bearer {legacy}"})
    assert resp.status_code == 401
    assert resp.json()["detail"] == "session revoked"


def test_versionless_token_works_when_no_bump(client, auth):
    # Compatibility: with no revocation bump (token_version stays 0), a ver-less
    # token (== version 0) still authorizes — un-revoked sessions are unaffected.
    legacy = security.create_access_token(auth["user_id"])
    resp = client.get("/auth/me", headers={"Authorization": f"Bearer {legacy}"})
    assert resp.status_code == 200, resp.text

"""Authentication endpoint tests: register, login, /auth/me, and failure modes."""


def test_register_returns_full_payload(client):
    resp = client.post(
        "/auth/register",
        json={"email": "ada@example.com", "password": "password123", "full_name": "Ada"},
    )
    assert resp.status_code == 201, resp.text
    data = resp.json()
    # Token pair + user/org/workspace convenience payload.
    assert data["token_type"] == "bearer"
    assert data["access_token"] and data["refresh_token"]
    assert data["user"]["email"] == "ada@example.com"
    assert data["user"]["full_name"] == "Ada"
    assert data["org"]["id"] > 0
    assert data["workspace"]["org_id"] == data["org"]["id"]
    # Fresh workspace starts empty & unrestricted.
    assert data["workspace"]["scope"] == []
    assert data["workspace"]["scan_count"] == 0
    assert data["workspace"]["finding_count"] == 0


def test_login_succeeds_with_correct_credentials(client):
    client.post(
        "/auth/register",
        json={"email": "grace@example.com", "password": "password123", "full_name": "Grace"},
    )
    resp = client.post(
        "/auth/login",
        json={"email": "grace@example.com", "password": "password123"},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["access_token"]
    assert data["user"]["email"] == "grace@example.com"
    assert data["workspace"]["id"] > 0


def test_auth_me_returns_current_user(client, auth):
    resp = client.get("/auth/me", headers=auth["headers"])
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["user"]["id"] == auth["user_id"]
    assert data["user"]["email"] == auth["email"]
    # The registering user is the owner of exactly one org/membership.
    assert len(data["orgs"]) == 1
    assert len(data["memberships"]) == 1
    assert data["memberships"][0]["role"] == "owner"


def test_duplicate_email_is_rejected(client):
    body = {"email": "dupe@example.com", "password": "password123", "full_name": "Dupe"}
    first = client.post("/auth/register", json=body)
    assert first.status_code == 201
    second = client.post("/auth/register", json=body)
    assert second.status_code == 409, second.text


def test_login_wrong_password_is_401(client):
    client.post(
        "/auth/register",
        json={"email": "wrongpw@example.com", "password": "password123"},
    )
    resp = client.post(
        "/auth/login",
        json={"email": "wrongpw@example.com", "password": "not-the-password"},
    )
    assert resp.status_code == 401, resp.text


def test_login_unknown_email_is_401(client):
    resp = client.post(
        "/auth/login",
        json={"email": "nobody@example.com", "password": "password123"},
    )
    assert resp.status_code == 401, resp.text


def test_me_without_token_is_401(client):
    resp = client.get("/auth/me")
    assert resp.status_code == 401, resp.text


def test_me_with_garbage_token_is_401(client):
    resp = client.get("/auth/me", headers={"Authorization": "Bearer not-a-jwt"})
    assert resp.status_code == 401, resp.text


def test_refresh_rotates_tokens(client, auth):
    resp = client.post("/auth/refresh", json={"refresh_token": auth["refresh_token"]})
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["token_type"] == "bearer"
    assert data["access_token"] and data["refresh_token"]
    # The new access token is accepted by a protected endpoint.
    me = client.get("/auth/me", headers={"Authorization": f"Bearer {data['access_token']}"})
    assert me.status_code == 200


def test_refresh_rejects_access_token(client, auth):
    # Passing an *access* token where a refresh token is required must 401.
    resp = client.post("/auth/refresh", json={"refresh_token": auth["access_token"]})
    assert resp.status_code == 401, resp.text

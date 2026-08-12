"""Shared pytest fixtures for the RECON-X Phase 0/1 suite.

The one job that MUST happen before anything else is pointing ``DATABASE_URL``
at a throwaway SQLite file. ``app.config`` builds its ``settings`` singleton at
import time and ``app.database`` builds the engine from it, so the environment
variable has to be set *before* the first ``import app.*`` anywhere in the
process. Doing it at the top of this module (pytest imports conftest before
collecting test modules) guarantees that ordering.
"""

import os
import tempfile
import uuid

# --------------------------------------------------------------------------- #
# 1. Redirect the database to a temp SQLite file BEFORE importing the app.
# --------------------------------------------------------------------------- #
_TMP_DIR = tempfile.mkdtemp(prefix="reconx-tests-")
_DB_PATH = os.path.join(_TMP_DIR, "test.db").replace("\\", "/")
os.environ["DATABASE_URL"] = f"sqlite:///{_DB_PATH}"
# Keep the JWT secret deterministic and MFA/bootstrap out of the way.
os.environ.setdefault("JWT_SECRET", "test-secret")
os.environ.pop("BOOTSTRAP_ADMIN_EMAIL", None)
os.environ.pop("BOOTSTRAP_ADMIN_PASSWORD", None)

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

# Importing app.main is now safe: the engine binds to the temp SQLite file.
from app.main import app  # noqa: E402
from app.database import Base, engine  # noqa: E402
from app import netguard, scanners  # noqa: E402


# --------------------------------------------------------------------------- #
# 2. Fresh schema per test for isolation (lets tests reuse the same emails).
# --------------------------------------------------------------------------- #
@pytest.fixture(autouse=True)
def _reset_database():
    """Drop & recreate every table around each test so state never leaks."""
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


# --------------------------------------------------------------------------- #
# 3. TestClient.
# --------------------------------------------------------------------------- #
@pytest.fixture()
def client():
    """A FastAPI TestClient bound to the app (tables managed by _reset_database)."""
    return TestClient(app)


# --------------------------------------------------------------------------- #
# 4. Registration helper -> auth headers + ids.
# --------------------------------------------------------------------------- #
def _register(client: TestClient, email: str, password: str = "password123", **kw):
    """Register a user and return the raw RegisterOut payload."""
    body = {"email": email, "password": password, "full_name": kw.get("full_name", "Test User")}
    if "org_name" in kw:
        body["org_name"] = kw["org_name"]
    resp = client.post("/auth/register", json=body)
    assert resp.status_code == 201, resp.text
    return resp.json()


def _auth_context(client: TestClient, payload: dict) -> dict:
    """Turn a RegisterOut payload into a convenient context dict."""
    access = payload["access_token"]
    return {
        "access_token": access,
        "refresh_token": payload["refresh_token"],
        "headers": {"Authorization": f"Bearer {access}"},
        "user_id": payload["user"]["id"],
        "email": payload["user"]["email"],
        "org_id": payload["org"]["id"],
        "ws_id": payload["workspace"]["id"],
    }


@pytest.fixture()
def auth(client):
    """Register a fresh user+org+workspace; return auth headers + ids.

    Returns a dict with ``headers``, ``access_token``, ``refresh_token``,
    ``user_id``, ``email``, ``org_id`` and ``ws_id`` (the default workspace).
    """
    email = f"user-{uuid.uuid4().hex[:10]}@example.com"
    payload = _register(client, email)
    return _auth_context(client, payload)


@pytest.fixture()
def make_user(client):
    """Factory that registers additional isolated users on demand."""

    def _factory(**kw):
        email = kw.pop("email", f"user-{uuid.uuid4().hex[:10]}@example.com")
        payload = _register(client, email, **kw)
        return _auth_context(client, payload)

    return _factory


# --------------------------------------------------------------------------- #
# 5. Fake scanner so scan tests never touch external tools / the network.
# --------------------------------------------------------------------------- #
def _fake_nuclei_stream(target, **_options):
    """A stand-in for a real scanner generator.

    Yields the same event dict shape the engine emits (``{"type","data"}``)
    and produces a nuclei-shaped result so ``crud.derive_findings`` turns it
    into exactly one persisted finding.
    """
    yield {"type": "log", "data": f"fake scan of {target}"}
    yield {
        "type": "result",
        "data": {
            "targets": [target],
            "total": 1,
            "counts": {"high": 1},
            "findings": [
                {
                    "template_id": "fake-template",
                    "name": "Fake High Severity Finding",
                    "severity": "high",
                    "matched_at": target,
                    "description": "Injected by the test fake scanner.",
                    "cve": ["CVE-2024-0001"],
                    "cwe": ["CWE-79"],
                    "cvss": 7.5,
                }
            ],
        },
    }


@pytest.fixture()
def fake_scanner(monkeypatch):
    """Patch the ``nuclei`` entry in the scanner REGISTRY with the fake.

    ``scanners.get_scanner`` reads ``REGISTRY`` at call time, so patching the
    dict entry redirects both the REST and (would-be) WS paths. We patch
    ``nuclei`` specifically because ``crud.derive_findings`` knows how to turn a
    nuclei result into findings.
    """
    monkeypatch.setitem(scanners.REGISTRY, "nuclei", _fake_nuclei_stream)
    # Scan-orchestration tests use fake, non-resolvable targets, so neutralize
    # the SSRF DNS guard to keep them hermetic (no real network). netguard's own
    # blocking behavior is covered directly in test_netguard.py, and the
    # dedicated SSRF tests in test_execution.py use private literal IPs without
    # this fixture, so they still exercise the real guard.
    monkeypatch.setattr(netguard, "validate_target", lambda target: (True, "ok"))
    monkeypatch.setattr(netguard, "validate_targets", lambda raw: (True, "ok"))
    return _fake_nuclei_stream

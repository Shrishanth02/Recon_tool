"""P1-H4 — Alembic migration & schema-integrity tests.

These prove the PRODUCTION schema mechanism (Alembic migrations), independently
of the app's SQLite ``create_all`` bootstrap. Each check runs against a fresh,
empty database driven entirely by the real ``alembic`` CLI (as production and CI
do) — NEVER via ``create_all``.

Backends
--------
* **sqlite**  — a throwaway temp file. Runs locally with no Docker / no Postgres.
* **postgres** — the same checks against a live PostgreSQL. Requires
  ``RECONX_PG_TEST_URL`` (set by the CI Postgres job). When it is absent — i.e.
  locally, where PostgreSQL is unavailable without Docker — the Postgres
  parametrisation is SKIPPED and reported as *PENDING CI POSTGRES VERIFICATION*;
  it is never faked.

The SQLite variants give fast local coverage; the Postgres variants close the
"SQLite compatibility != PostgreSQL compatibility" gap in CI.
"""

import os
import subprocess
import sys
from pathlib import Path

import pytest
from sqlalchemy import create_engine, inspect, text

BACKEND = Path(__file__).resolve().parents[1]
HEAD_REVISION = "0019_user_email_verified"
INITIAL_REVISION = "0001_initial"


# --------------------------------------------------------------------------- #
# Helpers — run the real alembic CLI against an explicit DATABASE_URL, exactly
# like entrypoint.sh / CI do. Subprocess isolation means the migration never
# touches the app's own engine (bound to the conftest test DB).
# --------------------------------------------------------------------------- #
def _sub_env(url: str, **extra) -> dict:
    env = dict(os.environ)
    env["DATABASE_URL"] = url
    # A strong, clearly-fake secret so `import app.config` passes the non-DEBUG
    # JWT guard in the child process regardless of the parent's DEBUG state.
    env.setdefault("JWT_SECRET", "reconx-test-secret-not-for-production-0123456789")
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUTF8"] = "1"
    env.update({k: str(v) for k, v in extra.items()})
    return env


def _run_alembic(url: str, *args: str, **extra):
    """Invoke ``alembic <args>`` against ``url``; assert success."""
    proc = subprocess.run(
        [sys.executable, "-m", "alembic", *args],
        cwd=str(BACKEND),
        env=_sub_env(url, **extra),
        capture_output=True,
        text=True,
        check=False,  # we assert on returncode ourselves for a clearer message
    )
    assert proc.returncode == 0, (
        f"`alembic {' '.join(args)}` failed (exit {proc.returncode})\n"
        f"--- stdout ---\n{proc.stdout}\n--- stderr ---\n{proc.stderr}"
    )
    return proc


def _engine(url: str):
    return create_engine(url, future=True)


# --------------------------------------------------------------------------- #
# Target matrix: sqlite always; postgres only when a live DB is provided.
# --------------------------------------------------------------------------- #
def _migration_targets():
    _pg = os.environ.get("RECONX_PG_TEST_URL")
    return [
        pytest.param("sqlite", id="sqlite"),
        pytest.param(
            "postgres",
            id="postgres",
            marks=[
                pytest.mark.postgres,
                pytest.mark.skipif(
                    not _pg,
                    reason="PENDING CI POSTGRES VERIFICATION — RECONX_PG_TEST_URL unset "
                    "(PostgreSQL is unavailable locally without Docker).",
                ),
            ],
        ),
    ]


_TARGETS = _migration_targets()


@pytest.fixture
def target_url(request, tmp_path):
    """Yield a URL for an EMPTY database of the requested backend."""
    if request.param == "sqlite":
        yield f"sqlite:///{(tmp_path / 'migration.db').as_posix()}"
        return
    # postgres: hard-reset the shared CI database to a truly empty schema so the
    # migration chain always runs from scratch (step 4).
    url = os.environ["RECONX_PG_TEST_URL"]
    eng = _engine(url)
    with eng.begin() as conn:
        conn.exec_driver_sql("DROP SCHEMA IF EXISTS public CASCADE")
        conn.exec_driver_sql("CREATE SCHEMA public")
    eng.dispose()
    yield url


# --------------------------------------------------------------------------- #
# 1. Revision graph integrity (metadata only — no DB, always local).
# --------------------------------------------------------------------------- #
def test_alembic_single_linear_head():
    from alembic.config import Config
    from alembic.script import ScriptDirectory

    cfg = Config()
    cfg.set_main_option("script_location", str(BACKEND / "migrations"))
    script = ScriptDirectory.from_config(cfg)
    assert script.get_heads() == [HEAD_REVISION], script.get_heads()
    assert len(script.get_bases()) == 1, f"expected one base, got {script.get_bases()}"
    # Strictly linear: every revision has at most a single (string) down_revision.
    for rev in script.walk_revisions():
        assert not isinstance(rev.down_revision, (list, tuple)), (
            f"branch/merge at {rev.revision}: {rev.down_revision}"
        )


# --------------------------------------------------------------------------- #
# 2. Fresh DB -> `alembic upgrade head` -> current == head (steps 3, 4).
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("target_url", _TARGETS, indirect=True)
def test_upgrade_from_empty_reaches_head(target_url):
    _run_alembic(target_url, "upgrade", "head")
    current = _run_alembic(target_url, "current")
    out = current.stdout + current.stderr
    assert HEAD_REVISION in out and "(head)" in out, out


# --------------------------------------------------------------------------- #
# 3. Schema-drift guard: migrations reproduce the ORM WITHOUT create_all
#    (steps 5). A model added without a parity migration fails here.
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("target_url", _TARGETS, indirect=True)
def test_migrations_reproduce_orm_schema_without_create_all(target_url):
    _run_alembic(target_url, "upgrade", "head")

    from app import models  # noqa: F401  (register mappers)
    from app.database import Base

    eng = _engine(target_url)
    try:
        insp = inspect(eng)
        migrated = set(insp.get_table_names()) - {"alembic_version"}
        orm = set(Base.metadata.tables)

        missing = orm - migrated
        assert not missing, f"tables defined by the ORM but NOT created by migrations: {sorted(missing)}"

        for table in sorted(orm & migrated):
            mig_cols = {c["name"] for c in insp.get_columns(table)}
            orm_cols = set(Base.metadata.tables[table].columns.keys())
            drift = orm_cols - mig_cols
            assert not drift, f"{table}: columns in ORM missing from the migrated schema: {sorted(drift)}"
    finally:
        eng.dispose()


@pytest.mark.parametrize("target_url", _TARGETS, indirect=True)
def test_email_verified_column_present_and_not_null(target_url):
    """0019 adds users.email_verified as a NOT NULL boolean (the SSO
    pre-hijacking defense). Guards the specific column end to end on the real
    migrated schema, on both SQLite and PostgreSQL."""
    _run_alembic(target_url, "upgrade", "head")
    eng = _engine(target_url)
    try:
        cols = {c["name"]: c for c in inspect(eng).get_columns("users")}
        assert "email_verified" in cols, "0019 did not add users.email_verified"
        assert cols["email_verified"]["nullable"] is False
    finally:
        eng.dispose()


# --------------------------------------------------------------------------- #
# 4. Application boots against the migrated schema, create_all disabled (steps 5,3.7).
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("target_url", _TARGETS, indirect=True)
def test_app_starts_against_migrated_db(target_url):
    _run_alembic(target_url, "upgrade", "head")
    # RECONX_DB_AUTO_CREATE=false => init_models() will NOT create_all, so the app
    # depends entirely on the migrated schema. Registration writes across
    # organizations/users/workspaces/memberships — a real end-to-end schema probe.
    boot = (
        "import uuid\n"
        "from fastapi.testclient import TestClient\n"
        "from app.main import app\n"
        "with TestClient(app) as c:\n"
        "    email = 'boot-%s@example.com' % uuid.uuid4().hex[:8]\n"
        "    r = c.post('/auth/register', json={'email': email,"
        " 'password': 'password123', 'full_name': 'Boot'})\n"
        "    assert r.status_code == 201, (r.status_code, r.text)\n"
        "print('APP_STARTS_OK')\n"
    )
    proc = subprocess.run(
        [sys.executable, "-c", boot],
        cwd=str(BACKEND),
        env=_sub_env(
            target_url,
            RECONX_DB_AUTO_CREATE="false",
            RECONX_RATE_LIMIT_ENABLED="false",
        ),
        capture_output=True,
        text=True,
        check=False,  # asserted on stdout below
    )
    assert "APP_STARTS_OK" in proc.stdout, (
        "app failed to start / register against the migrated DB\n"
        f"--- stdout ---\n{proc.stdout}\n--- stderr ---\n{proc.stderr}"
    )


# --------------------------------------------------------------------------- #
# 5. Existing data survives the full migration chain (step 6).
#    Seed a tenant graph at the INITIAL revision, then upgrade the remaining
#    twelve migrations OVER the pre-existing rows. A later migration that added a
#    NOT NULL column without a default (or an incompatible constraint/type change)
#    would fail here on real data.
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("target_url", _TARGETS, indirect=True)
def test_existing_data_survives_full_upgrade(target_url):
    _run_alembic(target_url, "upgrade", INITIAL_REVISION)

    eng = _engine(target_url)
    try:
        with eng.begin() as c:
            c.execute(text("INSERT INTO organizations (id, name, slug) VALUES (1, 'Legacy Org', 'legacy-org')"))
            c.execute(text("INSERT INTO users (id, email, password_hash) VALUES (1, 'legacy@example.com', 'x')"))
            c.execute(text("INSERT INTO workspaces (id, org_id, name, slug, scope) VALUES (1, 1, 'WS', 'ws', '{}')"))
            c.execute(text("INSERT INTO scans (id, workspace_id, tool, target, options, logs) "
                           "VALUES (1, 1, 'nuclei', 'example.com', '{}', '[]')"))
            c.execute(text("INSERT INTO findings (id, scan_id, workspace_id, name, cve, cwe) "
                           "VALUES (1, 1, 1, 'Legacy Finding', '[]', '[]')"))
        cols_before = {col["name"] for col in inspect(eng).get_columns("findings")}
    finally:
        eng.dispose()

    # Apply migrations 0002..head over the existing rows.
    _run_alembic(target_url, "upgrade", "head")

    eng = _engine(target_url)
    try:
        with eng.connect() as c:
            assert c.execute(text("SELECT COUNT(*) FROM findings")).scalar() == 1
            assert c.execute(text("SELECT name FROM findings WHERE id = 1")).scalar() == "Legacy Finding"
            assert c.execute(text("SELECT COUNT(*) FROM organizations")).scalar() == 1
            assert c.execute(text("SELECT COUNT(*) FROM users WHERE email = 'legacy@example.com'")).scalar() == 1
            assert c.execute(text("SELECT COUNT(*) FROM scans")).scalar() == 1
        cols_after = {col["name"] for col in inspect(eng).get_columns("findings")}
    finally:
        eng.dispose()

    # The chain genuinely evolved the table the data lives in (columns were added),
    # and the pre-existing row survived every one of those changes.
    assert cols_after > cols_before, (sorted(cols_before), sorted(cols_after))


# --------------------------------------------------------------------------- #
# 6. Drift-guard unit tests for the create_all policy (no DB — always local).
#    These lock in the P1-H4 behaviour: create_all is OFF for Postgres by default.
# --------------------------------------------------------------------------- #
def test_db_auto_create_policy(monkeypatch):
    from app.config import settings

    monkeypatch.setattr(settings, "DB_AUTO_CREATE", "auto")
    monkeypatch.setattr(settings, "DATABASE_URL", "postgresql+psycopg://u:p@h/db")
    assert settings.db_auto_create is False  # auto => OFF for Postgres

    monkeypatch.setattr(settings, "DATABASE_URL", "sqlite:///x.db")
    assert settings.db_auto_create is True  # auto => ON for SQLite

    monkeypatch.setattr(settings, "DB_AUTO_CREATE", "true")
    monkeypatch.setattr(settings, "DATABASE_URL", "postgresql+psycopg://u:p@h/db")
    assert settings.db_auto_create is True  # forced ON

    monkeypatch.setattr(settings, "DB_AUTO_CREATE", "false")
    monkeypatch.setattr(settings, "DATABASE_URL", "sqlite:///x.db")
    assert settings.db_auto_create is False  # forced OFF


def test_init_models_skips_create_all_when_disabled(monkeypatch):
    from app import database

    monkeypatch.setattr(database.settings, "DB_AUTO_CREATE", "false")

    def _boom(*a, **k):
        raise AssertionError("create_all must NOT run when auto-create is disabled")

    monkeypatch.setattr(database.Base.metadata, "create_all", _boom)
    database.init_models()  # must return without calling create_all


def test_init_models_runs_create_all_when_enabled(monkeypatch):
    from app import database

    monkeypatch.setattr(database.settings, "DB_AUTO_CREATE", "true")
    called = {}
    monkeypatch.setattr(database.Base.metadata, "create_all", lambda *a, **k: called.setdefault("ran", True))
    database.init_models()
    assert called.get("ran") is True

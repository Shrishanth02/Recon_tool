"""P0-1 & P0-3 regression tests — deployment/build-context hardening.

These are static checks over the repository's Docker + ignore + compose files so
the fixed problems cannot silently return:

* P0-1 — no credential/DB/report artifact can be baked into an image
  (Dockerfiles use an explicit allow-list, ignore files cover the patterns, and
  no such artifact is left sitting in the backend build context).
* P0-3 — the production compose never publishes an unauthenticated Redis.

They read files only (no Docker needed), so they run anywhere CI does.
"""

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
BACKEND = REPO_ROOT / "backend"


def _read(p: Path) -> str:
    return p.read_text(encoding="utf-8", errors="ignore") if p.exists() else ""


# --------------------------------------------------------------------------- #
# P0-1 — build-context hygiene
# --------------------------------------------------------------------------- #
def test_backend_dockerfiles_never_copy_whole_context():
    """`COPY . .` is what baked the credential DB in; it must not come back.

    We flag only an *active* instruction line (ignoring comments, which may
    legitimately mention the anti-pattern in an explanatory note).
    """
    for name in ("Dockerfile", "Dockerfile.worker"):
        text = _read(BACKEND / name)
        assert text, f"{name} missing"
        active_copy_all = [
            ln for ln in text.splitlines()
            if not ln.lstrip().startswith("#") and ln.strip() == "COPY . ."
        ]
        assert not active_copy_all, (
            f"{name} has an active `COPY . .` instruction, which bakes the whole "
            "context into the image. Use an explicit allow-list instead."
        )
        assert "COPY app ./app" in text, f"{name} must allow-list the app package"


def test_backend_dockerignore_covers_sensitive_patterns():
    di = _read(BACKEND / ".dockerignore")
    for pat in ("*.db", "*.bak", "*.bak-*", "*.sql", "*.html", ".env"):
        assert pat in di, f"backend/.dockerignore missing pattern: {pat}"


def test_root_gitignore_blocks_sensitive_and_external():
    gi = _read(REPO_ROOT / ".gitignore")
    for pat in ("*.bak", "*.bak-*", "*.sql", "_purple_report.html", "/SOC Tool/"):
        assert pat in gi, f"root .gitignore missing pattern: {pat}"


def test_no_credential_or_report_artifacts_in_backend_context():
    """No *.bak / *.sql / generated report / scratch DB left in backend/.

    The live dev DB (reconx.db) is allowed — it is never copied by the allow-list
    and is ignored by both git and docker. We only flag backups, dumps, reports
    and the known scratch DBs that must never ship.
    """
    skip_dirs = {".git", ".venv", "venv", "node_modules", "__pycache__",
                 ".pytest_cache", ".mypy_cache", ".ruff_cache"}
    offenders: list[str] = []
    for p in BACKEND.rglob("*"):
        if not p.is_file():
            continue
        rel = p.relative_to(BACKEND).as_posix()
        if any(part in skip_dirs for part in p.relative_to(BACKEND).parts):
            continue
        name = p.name
        if (
            name.endswith(".bak")
            or ".bak-" in name
            or name.endswith(".backup")
            or name.endswith(".sql")
            or name == "_purple_report.html"
            or name.endswith("_report.html")
            or name == "_p3.db"
        ):
            offenders.append(rel)
    assert not offenders, f"sensitive artifacts present in backend build context: {offenders}"


# --------------------------------------------------------------------------- #
# P0-3 — Redis is authenticated and not publicly published
# --------------------------------------------------------------------------- #
def _compose_text() -> str:
    text = _read(REPO_ROOT / "docker-compose.yml")
    assert text, "docker-compose.yml missing"
    return text


def test_compose_does_not_publish_redis_to_host():
    """No uncommented `6379:6379` host port mapping."""
    for line in _compose_text().splitlines():
        if "6379:6379" in line:
            assert line.lstrip().startswith("#"), (
                "docker-compose.yml publishes Redis to the host uncommented: "
                f"{line.strip()!r}"
            )


def test_compose_requires_redis_password():
    text = _compose_text()
    assert "--requirepass" in text, "redis service must set --requirepass"
    assert "REDIS_PASSWORD" in text, "redis auth must come from REDIS_PASSWORD env"


def test_compose_redis_url_is_authenticated():
    """Every REDIS_URL the app services use must carry credentials."""
    urls = [
        ln.strip()
        for ln in _compose_text().splitlines()
        if "REDIS_URL:" in ln and not ln.lstrip().startswith("#")
    ]
    assert urls, "expected REDIS_URL entries for backend/worker"
    for url in urls:
        assert "${REDIS_PASSWORD}" in url or "redis://:" in url, (
            f"REDIS_URL is unauthenticated: {url!r}"
        )


def test_env_example_documents_redis_password():
    env = _read(REPO_ROOT / ".env.example")
    assert "REDIS_PASSWORD=" in env, ".env.example must document REDIS_PASSWORD"

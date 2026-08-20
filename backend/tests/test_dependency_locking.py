"""P1-H3 regression tests — reproducible, hash-verified dependencies.

These assert the dependency-management *configuration* (locks fully pinned +
hashed, sources present, Docker/CI/frontend install reproducibly, security audit
wired, scanner versions pinned). They check structure, not exact versions or
lockfile text formatting, so they don't break on a routine `make lock`.
"""

import re
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
REPO = BACKEND.parent


def _read(p: Path) -> str:
    return p.read_text(encoding="utf-8", errors="ignore") if p.exists() else ""


# A top-level requirement line: a package name (optionally with an extra) at the
# start of a line, followed by a version specifier. Hash lines and comments start
# with whitespace / '#', so they are excluded.
_PINNED = re.compile(r"(?m)^([A-Za-z0-9][\w.\-]*(?:\[[\w,]+\])?)==")
_RANGE = re.compile(r"(?m)^([A-Za-z0-9][\w.\-]*(?:\[[\w,]+\])?)\s*(>=|<=|~=|!=|>|<)")


def _direct_names(in_text: str) -> set[str]:
    names = set()
    for line in in_text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r"^([A-Za-z0-9][\w.\-]*)", line)
        if m:
            names.add(m.group(1).lower())
    return names


# --------------------------------------------------------------------------- #
# Locks are fully pinned + hashed; sources exist
# --------------------------------------------------------------------------- #
def test_source_and_lock_files_exist():
    for f in ("requirements.in", "requirements.txt",
              "requirements-dev.in", "requirements-dev.txt"):
        assert (BACKEND / f).exists(), f"missing {f}"


def test_production_lock_is_fully_pinned():
    lock = _read(BACKEND / "requirements.txt")
    assert _PINNED.findall(lock), "no pinned packages found in the prod lock"
    # No requirement may use a range operator — every one is '=='.
    ranges = [f"{n}{op}" for n, op in _RANGE.findall(lock)]
    assert ranges == [], f"unpinned production dependencies: {ranges}"


def test_production_lock_is_hash_verified():
    lock = _read(BACKEND / "requirements.txt")
    hashes = lock.count("--hash=sha256:")
    pins = len(_PINNED.findall(lock))
    assert pins >= 20 and hashes >= pins, f"lock has {pins} pins but only {hashes} hashes"


def test_dev_lock_is_pinned_and_hashed():
    lock = _read(BACKEND / "requirements-dev.txt")
    assert _RANGE.findall(lock) == []
    assert lock.count("--hash=sha256:") >= len(_PINNED.findall(lock)) >= 3


def test_every_direct_prod_dependency_is_locked():
    # Normalize away extras ("redis[hiredis]" -> "redis") on both sides, since the
    # lock pins packages with their extras while the .in may list them either way.
    def base(n):
        return re.sub(r"\[.*?\]", "", n).lower()

    direct = {base(d) for d in _direct_names(_read(BACKEND / "requirements.in"))}
    locked = {base(n) for n in _PINNED.findall(_read(BACKEND / "requirements.txt"))}
    missing = {d for d in direct if d not in locked}
    assert not missing, f"direct deps not present in the lock: {missing}"


def test_legitimate_bcrypt_constraint_preserved():
    # bcrypt<4.1 exists for a real reason (passlib 1.7.4 backend probe); keep it.
    assert re.search(r"(?m)^bcrypt<4\.1", _read(BACKEND / "requirements.in"))
    m = re.search(r"(?m)^bcrypt==(\d+)\.(\d+)", _read(BACKEND / "requirements.txt"))
    assert m and (int(m.group(1)), int(m.group(2))) < (4, 1)


def test_dev_only_tools_not_in_production_lock():
    prod = {n.lower() for n in _PINNED.findall(_read(BACKEND / "requirements.txt"))}
    for tool in ("pytest", "ruff", "fakeredis", "pytest-asyncio"):
        assert tool not in prod, f"dev tool {tool} leaked into the production lock"


# --------------------------------------------------------------------------- #
# Reproducible install: Docker + CI use the locks with --require-hashes
# --------------------------------------------------------------------------- #
def test_images_install_with_require_hashes():
    for name in ("Dockerfile", "Dockerfile.worker"):
        d = _read(BACKEND / name)
        assert "--require-hashes" in d and "requirements.txt" in d, name


def test_ci_installs_locked_and_hash_verified():
    ci = _read(REPO / ".github" / "workflows" / "ci.yml")
    assert "--require-hashes" in ci
    assert "requirements.txt" in ci and "requirements-dev.txt" in ci


def test_ci_runs_dependency_security_audit():
    ci = _read(REPO / ".github" / "workflows" / "ci.yml")
    assert "pip-audit" in ci, "CI must run a dependency-security audit"


def test_audit_baseline_is_documented_and_wired():
    # A reviewed baseline exists and CI gates on NEW advisories via it.
    assert (BACKEND / ".pip-audit-ignores").exists()
    ci = _read(REPO / ".github" / "workflows" / "ci.yml")
    assert ".pip-audit-ignores" in ci and "--ignore-vuln" in ci


# --------------------------------------------------------------------------- #
# Frontend uses its lockfile (npm ci, not npm install)
# --------------------------------------------------------------------------- #
def test_frontend_lockfile_used():
    assert (REPO / "frontend" / "package-lock.json").exists()
    assert "npm ci" in _read(REPO / "frontend" / "Dockerfile")
    ci = _read(REPO / ".github" / "workflows" / "ci.yml")
    assert "npm ci" in ci and "npm install" not in ci


# --------------------------------------------------------------------------- #
# External scanner binaries: pinned versions + checksum verification
# --------------------------------------------------------------------------- #
def test_scanner_binaries_are_version_pinned_and_verified():
    script = _read(BACKEND / "install-scanners.sh")
    assert "sha256sum -c" in script          # integrity verification (P0-6)
    for var in ("SUBFINDER_VERSION", "HTTPX_VERSION", "NUCLEI_VERSION", "FFUF_VERSION"):
        assert var in _read(BACKEND / "Dockerfile.worker"), f"{var} not pinned"

"""P1-B3 regression tests — container / runtime hardening (static + runtime).

Docker is NOT required. These assert the compose + Dockerfile *configuration*
(non-root, dropped caps, no-new-privileges, resource limits, healthchecks) and
validate the runtime assumptions the hardening relies on (which paths must be
writable, that report generation needs no disk, that the DB is reached over the
network). Actually building an image and starting a container is a separate
manual/CI step — see the report's "PENDING DOCKER VERIFICATION" section.
"""

import tempfile
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[2]
BACKEND = REPO / "backend"
APP = BACKEND / "app"


def _read(p: Path) -> str:
    return p.read_text(encoding="utf-8", errors="ignore") if p.exists() else ""


def _compose() -> dict:
    d = yaml.safe_load(_read(REPO / "docker-compose.yml"))
    assert d and "services" in d
    return d


# --------------------------------------------------------------------------- #
# Compose hardening — backend + worker
# --------------------------------------------------------------------------- #
HARDENED_SERVICES = ["backend", "worker"]


def test_services_drop_all_capabilities():
    svcs = _compose()["services"]
    for name in HARDENED_SERVICES:
        assert svcs[name].get("cap_drop") == ["ALL"], f"{name} must cap_drop: [ALL]"


def test_services_forbid_privilege_escalation():
    svcs = _compose()["services"]
    for name in HARDENED_SERVICES:
        assert "no-new-privileges:true" in (svcs[name].get("security_opt") or []), name


def test_services_have_resource_limits():
    svcs = _compose()["services"]
    for name in HARDENED_SERVICES:
        s = svcs[name]
        assert s.get("mem_limit"), f"{name} missing mem_limit"
        assert s.get("cpus"), f"{name} missing cpus"
        assert s.get("pids_limit"), f"{name} missing pids_limit"


def test_resource_limits_are_env_configurable():
    raw = _read(REPO / "docker-compose.yml")
    for var in ("BACKEND_MEM_LIMIT", "BACKEND_CPUS", "BACKEND_PIDS_LIMIT",
                "WORKER_MEM_LIMIT", "WORKER_CPUS", "WORKER_PIDS_LIMIT"):
        assert var in raw, f"{var} should be an env-overridable limit"
        assert var in _read(REPO / ".env.example"), f"{var} should be documented in .env.example"


def test_services_have_healthchecks():
    svcs = _compose()["services"]
    for name in HARDENED_SERVICES:
        hc = svcs[name].get("healthcheck")
        assert hc and hc.get("test"), f"{name} missing a healthcheck"


def test_backend_healthcheck_probes_real_readiness():
    hc = _compose()["services"]["backend"]["healthcheck"]["test"]
    joined = " ".join(hc)
    assert "/ready" in joined  # verifies DB connectivity, not just a live process


def test_worker_healthcheck_probes_queue_backend():
    hc = _compose()["services"]["worker"]["healthcheck"]["test"]
    joined = " ".join(hc)
    assert "redis" in joined.lower() and "ping" in joined.lower()


def test_healthchecks_do_not_embed_the_redis_password():
    # The worker check must reference REDIS_URL via env, not inline the password.
    hc = " ".join(_compose()["services"]["worker"]["healthcheck"]["test"])
    assert "REDIS_URL" in hc
    assert "CHANGE_ME" not in hc and "@redis" not in hc  # no literal credential


def test_services_restart_unless_stopped():
    svcs = _compose()["services"]
    for name in HARDENED_SERVICES:
        assert svcs[name].get("restart") == "unless-stopped", name


def test_worker_publishes_no_host_ports():
    assert _compose()["services"]["worker"].get("ports") in (None, [])


def test_redis_still_not_host_published():
    # Regression guard for the P0-3 fix.
    assert _compose()["services"]["redis"].get("ports") in (None, [])


# --------------------------------------------------------------------------- #
# Dockerfiles — non-root, writable HOME
# --------------------------------------------------------------------------- #
def _last_user(dockerfile_text: str) -> str | None:
    users = [ln.split(maxsplit=1)[1].strip()
             for ln in dockerfile_text.splitlines()
             if ln.strip().startswith("USER ")]
    return users[-1] if users else None


def test_images_run_as_non_root():
    for name in ("Dockerfile", "Dockerfile.worker"):
        txt = _read(BACKEND / name)
        user = _last_user(txt)
        assert user, f"{name} has no USER directive (would run as root)"
        assert user not in ("root", "0"), f"{name} runs as {user}"
        assert "useradd" in txt, f"{name} must create a non-root user"
        assert "-u 10001" in txt, f"{name} should use a fixed non-root uid"


def test_images_set_writable_home_for_scanner_caches():
    for name in ("Dockerfile", "Dockerfile.worker"):
        txt = _read(BACKEND / name)
        assert "HOME=/home/reconx" in txt, f"{name} must give the user a writable HOME"


# --------------------------------------------------------------------------- #
# Runtime assumptions the hardening depends on (no Docker needed)
# --------------------------------------------------------------------------- #
def test_tmp_is_writable_for_nmap_style_scratch():
    # nmap writes its XML via tempfile.mkstemp; assert that pattern works so the
    # only writable path the scanners need at runtime really is a temp dir.
    import os
    fd, path = tempfile.mkstemp(suffix=".xml", prefix="reconx_nmap_")
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("<nmaprun/>")
        with open(path, encoding="utf-8") as fh:
            assert fh.read() == "<nmaprun/>"
    finally:
        os.close(fd)
        os.remove(path)


def test_report_generation_needs_no_disk():
    from app import report
    html = report.generate({"name": "Acme", "scope": []}, findings=[], scans=[])
    assert isinstance(html, str) and len(html) > 100
    # Static: report.py never writes to disk (no tempfile / file-open for write).
    src = _read(APP / "report.py")
    assert "mkstemp" not in src and "mkdtemp" not in src
    assert "import tempfile" not in src


def test_prod_database_is_network_not_a_local_file():
    # backend/worker reach Postgres over the network → no writable DB path needed
    # in the (non-root, capability-dropped) container.
    svcs = _compose()["services"]
    for name in HARDENED_SERVICES:
        url = svcs[name]["environment"]["DATABASE_URL"]
        assert url.startswith("postgresql"), f"{name} DATABASE_URL should be Postgres"
        assert "sqlite" not in url


def test_worker_startup_is_the_arq_queue_backend():
    # Worker image runs the arq worker; compose forces the queue backend.
    assert 'CMD ["arq", "app.worker.WorkerSettings"]' in _read(BACKEND / "Dockerfile.worker")
    assert _compose()["services"]["worker"]["environment"]["RECONX_EXECUTION_BACKEND"] == "queue"


# --------------------------------------------------------------------------- #
# Frontend hardening (Docker pass) — non-root nginx, dropped caps, limits, HC
# --------------------------------------------------------------------------- #
FRONTEND = REPO / "frontend"


def test_frontend_runs_non_root_nginx():
    df = _read(FRONTEND / "Dockerfile")
    assert df, "frontend/Dockerfile missing"
    # Purpose-built non-root nginx base (runs as uid 101; no root master process).
    assert "nginx-unprivileged" in df, "frontend must use a non-root nginx image"
    # ...and must never re-escalate to root for the runtime.
    users = [ln.split(maxsplit=1)[1].strip() for ln in df.splitlines()
             if ln.strip().startswith("USER ")]
    assert users[-1:] not in (["root"], ["0"]), "frontend image must not end as root"


def test_frontend_listens_on_unprivileged_port():
    conf = _read(FRONTEND / "nginx.conf")
    assert "listen" in conf and "8080" in conf, \
        "nginx must listen on 8080 (unprivileged) to match the non-root image"
    assert "listen       80;" not in conf and "listen 80;" not in conf


def test_frontend_service_is_hardened():
    fe = _compose()["services"]["frontend"]
    assert fe.get("cap_drop") == ["ALL"], "frontend must cap_drop: [ALL]"
    assert "no-new-privileges:true" in (fe.get("security_opt") or [])
    assert fe.get("mem_limit") and fe.get("cpus") and fe.get("pids_limit")
    assert fe.get("restart") == "unless-stopped"
    hc = fe.get("healthcheck")
    assert hc and hc.get("test"), "frontend must have a healthcheck"


def test_frontend_maps_host_port_to_container_8080():
    ports = _compose()["services"]["frontend"].get("ports") or []
    assert any(str(p).endswith(":8080") for p in ports), \
        f"frontend host port must map to container 8080, got {ports}"


def test_frontend_limits_are_env_configurable():
    raw = _read(REPO / "docker-compose.yml")
    env = _read(REPO / ".env.example")
    for var in ("FRONTEND_MEM_LIMIT", "FRONTEND_CPUS", "FRONTEND_PIDS_LIMIT"):
        assert var in raw and var in env, f"{var} should be an env-overridable, documented limit"

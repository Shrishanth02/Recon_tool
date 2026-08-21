"""P1-H1 regression tests — honest scanner isolation.

Two things are proven here without Docker:
  * the isolation LEVEL reported is the one actually applied (no false
    "isolation enabled"), and the policy refuses to run when isolation is
    required but unavailable; and
  * real local subprocesses launched through ``base.stream_command`` are actually
    process-restricted: they inherit NO app secrets, run in a throwaway cwd, are
    killed (whole tree) on timeout/cancel, and their scratch dir is cleaned up.

All subprocesses are harmless local ``python -c`` invocations. Docker-level
(container) isolation is asserted only structurally; real container verification
is PENDING DOCKER.
"""

import os
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from app import sandbox
from app.scanners import base

PY = sys.executable
REPO = Path(__file__).resolve().parents[2]


# --------------------------------------------------------------------------- #
# Environment sanitization
# --------------------------------------------------------------------------- #
def test_sanitized_env_drops_all_app_secrets(monkeypatch):
    for k, v in {
        "JWT_SECRET": "s", "DATABASE_URL": "postgres://u:pw@h/db",
        "REDIS_URL": "redis://:pw@h:6379/0", "ANTHROPIC_API_KEY": "sk-x",
        "STRIPE_SECRET_KEY": "sk", "MSF_PASSWORD": "pw",
        "RECONX_API_KEY": "k", "AWS_SECRET_ACCESS_KEY": "x",
    }.items():
        monkeypatch.setenv(k, v)
    env = sandbox.sandboxed_env()
    for k in ("JWT_SECRET", "DATABASE_URL", "REDIS_URL", "ANTHROPIC_API_KEY",
              "STRIPE_SECRET_KEY", "MSF_PASSWORD", "RECONX_API_KEY",
              "AWS_SECRET_ACCESS_KEY"):
        assert k not in env, f"{k} leaked into scanner env"
    assert env.get("PATH"), "PATH must be present so tools resolve"


def test_sanitized_env_extra_overrides():
    env = sandbox.sandboxed_env(extra={"HOME": "/scratch/home"})
    assert env["HOME"] == "/scratch/home"


# --------------------------------------------------------------------------- #
# Honest isolation-level resolution + policy
# --------------------------------------------------------------------------- #
def test_effective_isolation_default_is_process(monkeypatch):
    monkeypatch.setattr(sandbox.settings, "SANDBOX_MODE", "process")
    assert sandbox.effective_isolation() == (sandbox.ISOLATION_PROCESS, "")


def test_effective_isolation_none(monkeypatch):
    monkeypatch.setattr(sandbox.settings, "SANDBOX_MODE", "none")
    assert sandbox.effective_isolation() == (sandbox.ISOLATION_NONE, "")


def test_effective_isolation_docker_available(monkeypatch):
    monkeypatch.setattr(sandbox.settings, "SANDBOX_MODE", "docker")
    monkeypatch.setattr(sandbox, "docker_available", lambda: True)
    mode, note = sandbox.effective_isolation()
    assert mode == sandbox.ISOLATION_CONTAINER


def test_effective_isolation_docker_missing_optional_degrades(monkeypatch):
    monkeypatch.setattr(sandbox.settings, "SANDBOX_MODE", "docker")
    monkeypatch.setattr(sandbox.settings, "SANDBOX_REQUIRED", False)
    monkeypatch.setattr(sandbox, "docker_available", lambda: False)
    mode, note = sandbox.effective_isolation()
    assert mode == sandbox.ISOLATION_PROCESS and "unavailable" in note.lower()


def test_effective_isolation_docker_missing_required_refuses(monkeypatch):
    monkeypatch.setattr(sandbox.settings, "SANDBOX_MODE", "docker")
    monkeypatch.setattr(sandbox.settings, "SANDBOX_REQUIRED", True)
    monkeypatch.setattr(sandbox, "docker_available", lambda: False)
    mode, note = sandbox.effective_isolation()
    assert mode == sandbox.ISOLATION_UNAVAILABLE and "required" in note.lower()


# --------------------------------------------------------------------------- #
# Command wrapping + popen hardening structure
# --------------------------------------------------------------------------- #
def test_maybe_wrap_process_mode_is_noop(monkeypatch):
    monkeypatch.setattr(sandbox.settings, "SANDBOX_MODE", "process")
    assert sandbox.maybe_wrap(["nmap", "x"]) == ["nmap", "x"]


def test_maybe_wrap_container_mode_wraps(monkeypatch):
    monkeypatch.setattr(sandbox.settings, "SANDBOX_MODE", "docker")
    monkeypatch.setattr(sandbox, "docker_available", lambda: True)
    wrapped = sandbox.maybe_wrap(["nmap", "x"])
    assert wrapped[0] == "docker" and "--cap-drop" in wrapped and "nmap" in wrapped


def test_maybe_wrap_container_unavailable_does_not_wrap(monkeypatch):
    monkeypatch.setattr(sandbox.settings, "SANDBOX_MODE", "docker")
    monkeypatch.setattr(sandbox, "docker_available", lambda: False)
    assert sandbox.maybe_wrap(["nmap", "x"]) == ["nmap", "x"]  # can't wrap w/o docker


def test_popen_hardening_posix_has_rlimit_and_new_session(monkeypatch):
    monkeypatch.setattr(sandbox, "_IS_POSIX", True)
    kw = sandbox.popen_hardening(max_seconds=100, cwd="/tmp")
    assert kw["start_new_session"] is True
    assert callable(kw.get("preexec_fn"))
    assert kw["cwd"] == "/tmp" and "JWT_SECRET" not in kw["env"]
    assert "creationflags" not in kw


def test_popen_hardening_windows_has_process_group_no_preexec(monkeypatch):
    monkeypatch.setattr(sandbox, "_IS_POSIX", False)
    kw = sandbox.popen_hardening(max_seconds=100, cwd=".")
    assert "creationflags" in kw and "preexec_fn" not in kw


def test_terminate_process_tree_on_finished_proc_is_noop():
    class Done:
        pid = 999999
        def poll(self):
            return 0
    sandbox.terminate_process_tree(Done())  # must not raise


@pytest.mark.skipif(os.name != "posix", reason="POSIX process groups only")
def test_terminate_never_signals_our_own_process_group(monkeypatch):
    """The scanner tree-kill must NEVER signal our own process group.

    Regression for the CI pytest self-kill: a scanner pid that has been reaped can
    be REUSED, and ``os.getpgid(reused_pid)`` may then resolve to this process's
    own group — so ``os.killpg(os.getpgid(pid), SIGKILL)`` would SIGKILL the worker
    (and, in CI, the whole pytest run). The fix signals ``proc.pid`` directly (the
    scanner leads its own group) and never signals ``os.getpgrp()``.
    """
    own = os.getpgrp()
    signalled = []
    monkeypatch.setattr(os, "killpg", lambda pgid, sig: signalled.append(pgid))
    # Simulate the pid-reuse hazard: make getpgid resolve to OUR OWN group.
    monkeypatch.setattr(os, "getpgid", lambda pid: own)
    proc = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)"], start_new_session=True
    )
    try:
        sandbox.terminate_process_tree(proc)
        assert own not in signalled, (
            f"terminate_process_tree signalled our OWN process group {own}: {signalled}"
        )
    finally:
        proc.kill()
        proc.wait()


@pytest.mark.skipif(os.name != "posix", reason="POSIX rlimits only")
def test_cpu_rlimit_preexec_sets_limit():
    import resource
    sandbox._cpu_rlimit_preexec(30)()
    soft, _hard = resource.getrlimit(resource.RLIMIT_CPU)
    assert soft <= 30 + 60 + 1


# --------------------------------------------------------------------------- #
# Real subprocess behaviour through stream_command
# --------------------------------------------------------------------------- #
def _logs(events):
    return [e["data"] for e in events if e.get("type") == "log"]


def _rc(events):
    rc = [e["data"] for e in events if e.get("type") == "returncode"]
    return rc[-1] if rc else None


def test_subprocess_inherits_no_secrets(monkeypatch):
    monkeypatch.setenv("JWT_SECRET", "top-secret-value")
    events = list(base.stream_command(
        [PY, "-c", "import os,sys; sys.stdout.write(os.environ.get('JWT_SECRET','ABSENT'))"],
        max_seconds=30,
    ))
    logs = _logs(events)
    assert not any("top-secret-value" in l for l in logs)   # secret never reached child
    assert "ABSENT" in logs


def test_honest_isolation_log_and_no_false_claim():
    events = list(base.stream_command([PY, "-c", "print('hi')"], max_seconds=30))
    logs = _logs(events)
    assert any("isolation_mode=" in l for l in logs)
    assert not any("isolation enabled" in l.lower() for l in logs)


def test_scratch_cwd_isolation_and_cleanup(monkeypatch):
    captured = {}
    real_mkdtemp = base.tempfile.mkdtemp

    def spy(*a, **k):
        p = real_mkdtemp(*a, **k)
        captured["dir"] = p
        return p

    monkeypatch.setattr(base.tempfile, "mkdtemp", spy)
    events = list(base.stream_command(
        [PY, "-c", "import os,sys; sys.stdout.write(os.getcwd())"], max_seconds=30))
    logs = _logs(events)
    assert any("reconx_scan_" in l for l in logs)          # ran in the scratch cwd
    assert not os.path.exists(captured["dir"])              # scratch dir cleaned up


def test_scanner_nonzero_exit_reports_returncode():
    events = list(base.stream_command([PY, "-c", "import sys; sys.exit(3)"], max_seconds=30))
    assert _rc(events) == 3


def test_missing_binary_is_reported_and_scratch_not_leaked(monkeypatch):
    before = set(p for p in os.listdir(base.tempfile.gettempdir())
                 if p.startswith("reconx_scan_"))
    events = list(base.stream_command(["reconx-nonexistent-bin-xyz"], max_seconds=5))
    assert any(e.get("type") == "error" and "not found" in str(e["data"]).lower()
               for e in events)
    assert _rc(events) == 127
    after = set(p for p in os.listdir(base.tempfile.gettempdir())
                if p.startswith("reconx_scan_"))
    assert after == before   # no scratch dir left behind on the not-found path


def test_timeout_terminates_and_reports():
    start = time.monotonic()
    events = list(base.stream_command(
        [PY, "-c", "import time; time.sleep(30)"], max_seconds=1))
    elapsed = time.monotonic() - start
    assert elapsed < 15, "timeout did not stop the process promptly"
    assert any("time limit" in l for l in _logs(events))


def test_cancellation_terminates_and_reports():
    cancel = threading.Event()
    threading.Timer(0.5, cancel.set).start()
    start = time.monotonic()
    events = list(base.stream_command(
        [PY, "-c", "import time; time.sleep(30)"], cancel=cancel, max_seconds=60))
    assert time.monotonic() - start < 15
    assert any("cancelled" in l.lower() for l in _logs(events))


def test_policy_required_but_unavailable_refuses_to_run(monkeypatch):
    monkeypatch.setattr(sandbox.settings, "SANDBOX_MODE", "docker")
    monkeypatch.setattr(sandbox.settings, "SANDBOX_REQUIRED", True)
    monkeypatch.setattr(sandbox, "docker_available", lambda: False)
    # A command that would create a marker file if it ran — it must NOT run.
    import tempfile
    marker = os.path.join(tempfile.gettempdir(), f"reconx_marker_{os.getpid()}.txt")
    if os.path.exists(marker):
        os.remove(marker)
    events = list(base.stream_command(
        [PY, "-c", f"open({marker!r}, 'w').write('ran')"], max_seconds=10))
    assert any(e.get("type") == "error" and "refusing" in str(e["data"]).lower()
               for e in events)
    assert _rc(events) == 126
    assert not os.path.exists(marker), "scanner ran despite required isolation being unavailable"


def test_policy_optional_unavailable_runs_degraded(monkeypatch):
    monkeypatch.setattr(sandbox.settings, "SANDBOX_MODE", "docker")
    monkeypatch.setattr(sandbox.settings, "SANDBOX_REQUIRED", False)
    monkeypatch.setattr(sandbox, "docker_available", lambda: False)
    events = list(base.stream_command([PY, "-c", "print('ok')"], max_seconds=10))
    logs = _logs(events)
    assert any("isolation_mode=process_restricted" in l for l in logs)
    assert any("degraded" in l.lower() for l in logs)
    assert _rc(events) == 0


def test_timeout_kills_whole_process_tree_no_orphans(tmp_path):
    # Parent spawns a grandchild that heartbeats a file; a timeout must kill the
    # WHOLE tree, so the grandchild stops updating the file (no orphan).
    heartbeat = tmp_path / "hb.txt"
    grandchild = (
        "import time,sys\n"
        "p=sys.argv[1]\n"
        "while True:\n"
        "    open(p,'w').write(str(time.time()))\n"
        "    time.sleep(0.1)\n"
    )
    parent = (
        "import subprocess,sys,time\n"
        "subprocess.Popen([sys.executable,'-c',sys.argv[1],sys.argv[2]])\n"
        "time.sleep(60)\n"
    )
    list(base.stream_command(
        [PY, "-c", parent, grandchild, str(heartbeat)], max_seconds=2))
    # Give any orphaned grandchild a chance to keep writing, then confirm it isn't.
    time.sleep(1.0)
    assert heartbeat.exists(), "grandchild never started"
    mtime1 = heartbeat.stat().st_mtime
    time.sleep(1.5)
    mtime2 = heartbeat.stat().st_mtime
    assert mtime1 == mtime2, "grandchild survived the timeout (orphan not reaped)"


# --------------------------------------------------------------------------- #
# The old false log must be gone from the codebase
# --------------------------------------------------------------------------- #
def test_execution_no_longer_claims_docker_isolation_enabled():
    src = (REPO / "backend" / "app" / "execution.py").read_text(encoding="utf-8")
    assert "docker isolation enabled" not in src

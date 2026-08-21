"""Scanner execution isolation — honest about the level actually applied.

Isolation is layered; :func:`effective_isolation` resolves the level that will
*really* be applied from configuration + runtime availability, so the caller can
log exactly that and never claim a level it did not provide:

* ``none`` — NO ISOLATION: a direct child process (no added restriction).
* ``process_restricted`` — PROCESS RESTRICTION, achievable without Docker:
  a sanitized environment (no app secrets), a throwaway working directory, a new
  process group so a hung tool's whole tree can be killed, a wall-clock timeout
  (enforced by the caller), and — on POSIX — a CPU rlimit backstop.
* ``container`` — CONTAINER ISOLATION: the tool runs inside an ephemeral,
  capability-dropped Docker container (:func:`build_docker_cmd`). Requires Docker
  at runtime; see ``PENDING DOCKER VERIFICATION`` in the deploy docs.
* ``unavailable`` — the policy REQUIRES isolation that cannot be provided
  (``SANDBOX_MODE=docker`` + ``SANDBOX_REQUIRED`` with no Docker); the caller must
  REFUSE to execute rather than silently downgrade.

Environment sanitization, the process group, and the timeout are applied as a
BASELINE in every runnable mode (they are subprocess *safety*, not "isolation"),
so a scanner never inherits JWT / DB / Redis / cloud secrets regardless of mode.
"""

from __future__ import annotations

import os
import shutil
import signal
import subprocess

from .config import settings

# --- Isolation levels ------------------------------------------------------- #
ISOLATION_NONE = "none"
ISOLATION_PROCESS = "process_restricted"
ISOLATION_CONTAINER = "container"
ISOLATION_UNAVAILABLE = "unavailable"

_IS_POSIX = os.name == "posix"

#: Docker network mode for scanner containers (bridge = outbound recon access
#: without the host network namespace).
SANDBOX_NETWORK_MODE = "bridge"

# --- Environment allow-list ------------------------------------------------- #
# A scanner subprocess receives ONLY these variables (plus ``LC_*``) from the
# parent environment. Everything else — every app secret (JWT_SECRET,
# DATABASE_URL, REDIS_URL, ANTHROPIC/STRIPE/MSF/SMTP keys, the whole ``RECONX_*``
# config) — is dropped. The list carries what external tools genuinely need:
# PATH + a home/cache for tool config (nuclei templates, subfinder), locale,
# temp dir, proxy + TLS trust settings, Go tool dirs, and Windows essentials.
_ALLOWED_ENV = frozenset({
    "PATH", "HOME", "LANG", "LANGUAGE", "TZ", "TERM", "SHELL", "USER", "LOGNAME",
    "TMPDIR", "TEMP", "TMP",
    "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME",
    "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY",
    "http_proxy", "https_proxy", "no_proxy",
    "SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE",
    "GOPATH", "GOCACHE", "GOMODCACHE",
    # Windows essentials (tools break without these; absent on POSIX):
    "SYSTEMROOT", "WINDIR", "PATHEXT", "COMSPEC", "NUMBER_OF_PROCESSORS",
    "USERPROFILE", "APPDATA", "LOCALAPPDATA", "PROGRAMFILES", "PROGRAMFILES(X86)",
    "PROGRAMDATA", "SYSTEMDRIVE", "HOMEDRIVE", "HOMEPATH", "COMPUTERNAME",
    "PROCESSOR_ARCHITECTURE", "PROCESSOR_ARCHITEW6432",
})


def sandboxed_env(extra: dict | None = None) -> dict:
    """Return a minimal, secret-free environment for a scanner subprocess.

    Only :data:`_ALLOWED_ENV` (plus ``LC_*``) pass through from the parent; app
    secrets are never included. ``PATH`` is always present so the tool and its
    dependencies resolve. ``extra`` overrides/adds on top (e.g. a scratch HOME).
    """
    env = {
        k: v for k, v in os.environ.items()
        if k in _ALLOWED_ENV or k.upper().startswith("LC_")
    }
    if not env.get("PATH"):
        env["PATH"] = os.defpath or "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    if extra:
        env.update(extra)
    return env


def docker_available() -> bool:
    """True iff a ``docker`` client is on PATH (does not prove the daemon runs)."""
    return shutil.which("docker") is not None


def effective_isolation() -> tuple[str, str]:
    """Resolve the isolation level that will ACTUALLY be applied.

    Returns ``(mode, note)``. ``note`` is a human-readable degradation reason
    when the requested level could not be met. ``mode == ISOLATION_UNAVAILABLE``
    means the caller MUST refuse to run (isolation is required but absent).
    """
    mode = (settings.SANDBOX_MODE or "process").strip().lower()
    if mode == "docker":
        if docker_available():
            return ISOLATION_CONTAINER, ""
        if settings.sandbox_required:
            return ISOLATION_UNAVAILABLE, "docker isolation required but docker is not available"
        return ISOLATION_PROCESS, "docker isolation unavailable; degraded to process_restricted"
    if mode == "none":
        return ISOLATION_NONE, ""
    return ISOLATION_PROCESS, ""


def _cpu_rlimit_preexec(max_seconds: float):
    """POSIX-only: cap the child's CPU seconds as a backstop for the wall-clock
    timeout. Deliberately does NOT set RLIMIT_AS (Go scanners reserve huge
    virtual address space and would crash) or RLIMIT_NPROC (per-UID; would
    interfere with the shared-UID app). Memory/PID caps come from the container
    limits (see docker-compose mem_limit/pids_limit).
    """
    cpu = max(1, int(max_seconds) + 60)

    def _apply():  # runs in the child after fork(), before exec()
        import resource
        # Cap CPU seconds, but NEVER try to raise the hard limit: raising it is
        # forbidden without privilege and would make subprocess abort the spawn
        # with "Exception occurred in preexec_fn". Clamp the target to whatever
        # hard limit the child inherited.
        _soft, hard = resource.getrlimit(resource.RLIMIT_CPU)
        target = cpu if hard == resource.RLIM_INFINITY else min(cpu, hard)
        resource.setrlimit(resource.RLIMIT_CPU, (target, target))

    return _apply


def popen_hardening(*, max_seconds: float, cwd: str) -> dict:
    """Return ``subprocess.Popen`` kwargs that implement process restriction on
    the current OS: sanitized env, scratch cwd, a new process group (so the whole
    tree is killable), and — on POSIX — a CPU rlimit backstop.
    """
    kw: dict = {"env": sandboxed_env(), "cwd": cwd}
    if _IS_POSIX:
        kw["start_new_session"] = True  # own session/process-group -> killpg works
        kw["preexec_fn"] = _cpu_rlimit_preexec(max_seconds)
    else:
        # Windows: no preexec/rlimits; a new process group enables tree-kill.
        kw["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    return kw


def terminate_process_tree(proc) -> None:
    """Kill the scanner AND its children (best-effort, cross-platform).

    On POSIX the process was started in its own session, so the whole group is
    signalled; on Windows ``taskkill /T`` walks the tree. Falls back to killing
    the direct process. Never raises.
    """
    if proc is None or proc.poll() is not None:
        return
    try:
        if _IS_POSIX:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        else:
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=10, check=False,
            )
    except (ProcessLookupError, PermissionError, OSError, subprocess.SubprocessError):
        pass
    finally:
        try:
            if proc.poll() is None:
                proc.kill()
        except Exception:  # noqa: BLE001 - cleanup must never raise
            pass


# --- Container wrapping (CONTAINER isolation; requires Docker) --------------- #
def build_docker_cmd(inner_cmd: list[str], allow_hosts: list[str] | None = None) -> list[str]:
    """Wrap ``inner_cmd`` in a hardened, ephemeral ``docker run`` invocation.

    ``inner_cmd`` is the scanner command as it would run on the host; the result
    is the full ``docker run ...`` argv. ``allow_hosts`` is reserved for a future
    egress-allowlist (an operational network-policy concern, intentionally
    deferred). The hardening flags and ephemerality below are real.
    """
    _ = allow_hosts
    return [
        "docker", "run", "--rm",
        "--network", SANDBOX_NETWORK_MODE,
        "--memory", "512m", "--cpus", "1", "--pids-limit", "256",
        "--read-only", "--tmpfs", "/tmp",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        settings.SCANNER_IMAGE,
        *inner_cmd,
    ]


def maybe_wrap(cmd: list[str], allow_hosts: list[str] | None = None) -> list[str]:
    """Return the container-wrapped command when container isolation is in effect,
    else ``cmd`` unchanged. Delegates the level decision to
    :func:`effective_isolation` so it can never wrap when Docker is unavailable.
    """
    mode, _note = effective_isolation()
    if mode == ISOLATION_CONTAINER:
        return build_docker_cmd(cmd, allow_hosts)
    return cmd

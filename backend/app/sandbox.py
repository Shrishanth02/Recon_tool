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
import tempfile

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
    # Windows identity: getpass.getuser() (used by sqlmap and many tools) reads
    # USERNAME on Windows; without it Python falls back to `import pwd` and
    # crashes. Not a secret. (POSIX uses USER/LOGNAME above.)
    "USERNAME", "USERDOMAIN",
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
            # Defensive: signal proc.pid directly (the scanner leads its own group
            # via start_new_session=True, so pgid == pid) instead of
            # os.getpgid(proc.pid). getpgid is TOCTOU-prone — once the child is
            # reaped its pid can be reused and getpgid would resolve to an
            # unrelated group; killpg(proc.pid) is reuse-safe (a stale group is
            # just ESRCH). And never signal our own group.
            pgid = proc.pid
            if pgid > 0 and pgid != os.getpgrp():
                os.killpg(pgid, signal.SIGKILL)
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
# The scanners create their argv scratch files with ``tempfile.mkstemp`` in the
# system temp dir under a shared ``reconx_`` prefix (nmap ``-oX`` output, httpx
# ``-l`` input list, ffuf ``-o`` output). These are HOST paths baked into the
# argv, then read back on the host after the run. Under ``--read-only --tmpfs
# /tmp`` the container's ``/tmp`` is a fresh ephemeral tmpfs, so an input file the
# host wrote is invisible inside the container and an output file the tool writes
# never reaches the host — the isolated scan silently returns nothing. We bridge
# each such file with a per-file bind mount into a dedicated container directory
# (kept out of ``/tmp`` so the tmpfs never masks it) and rewrite that argv token
# to the in-container path.
#
# Scanners also pass STATIC input files by absolute host path — notably ffuf's
# wordlist (``-w`` -> config.WORDLIST, e.g. the SecLists ``common.txt``). Those
# are not ``reconx_`` scratch and are NOT baked into the scanner image, so under a
# ``--read-only`` container the tool cannot open them and (for ffuf) silently
# returns nothing. Any absolute-path argv token that resolves to an existing
# regular file on the host is therefore bind-mounted READ-ONLY into a separate
# directory and its argv token rewritten, so an isolated scan reads its inputs
# just as a host-mode scan does. (Targets are hostnames/URLs, not files, so they
# never match; only real input files we deliberately pass do.)
IO_MOUNT_DIR = "/reconx-io"    # scanner scratch (rw): outputs + app-written inputs
IN_MOUNT_DIR = "/reconx-in"    # static inputs (ro): wordlists, etc.


def _is_scanner_scratch(token: str) -> bool:
    """True when ``token`` is a scanner-created scratch file we must bind-mount.

    Precisely: an absolute path that lives directly in the system temp dir and
    whose name carries the scanners' shared ``reconx_`` prefix. The prefix keeps
    this from ever matching an unrelated argv token (e.g. a target that happens to
    look like a path), and ``realpath`` on both sides makes it robust to a temp
    dir that is itself a symlink (``/tmp`` -> ``/private/tmp``). The file need not
    exist yet — ``realpath`` resolves the parent regardless — but for these
    scanners ``mkstemp`` has already created it.
    """
    if not isinstance(token, str) or not os.path.isabs(token):
        return False
    parent = os.path.dirname(os.path.realpath(token))
    tmp = os.path.realpath(tempfile.gettempdir())
    return parent == tmp and os.path.basename(token).startswith("reconx_")


def build_docker_cmd(inner_cmd: list[str], allow_hosts: list[str] | None = None) -> list[str]:
    """Wrap ``inner_cmd`` in a hardened, ephemeral ``docker run`` invocation.

    ``inner_cmd`` is the scanner command as it would run on the host; the result
    is the full ``docker run ...`` argv. Scanner scratch files (see
    :func:`_is_scanner_scratch`) are bind-mounted read-write and static input
    files (absolute paths to existing regular files, e.g. the ffuf wordlist) are
    bind-mounted read-only; in both cases the argv token is rewritten to the
    in-container path, so an isolated scan reads its inputs and hands its outputs
    back exactly as the host-mode scan does. ``allow_hosts`` is reserved for a
    future egress-allowlist (an operational network-policy concern, intentionally
    deferred). The hardening flags and ephemerality below are real.
    """
    _ = allow_hosts
    mounts: list[str] = []
    argv: list[str] = []
    mapped: dict[str, str] = {}
    used: dict[str, set[str]] = {}

    def _container_path(host_path: str, mount_dir: str) -> str:
        # Give the file a stable, collision-free name inside ``mount_dir`` (two
        # distinct host files sharing a basename would otherwise clobber).
        claimed = used.setdefault(mount_dir, set())
        base = os.path.basename(host_path)
        name, i = base, 1
        while name in claimed:
            name, i = f"{i}_{base}", i + 1
        claimed.add(name)
        return f"{mount_dir}/{name}"

    for token in inner_cmd:
        if _is_scanner_scratch(token):
            container_path = mapped.get(token)
            if container_path is None:
                container_path = _container_path(token, IO_MOUNT_DIR)
                mapped[token] = container_path
                # rw bind of the single file: the host tmpfile (created empty by
                # mkstemp) is shared, nothing else from the host temp dir is.
                mounts += ["-v", f"{token}:{container_path}"]
            argv.append(container_path)
        elif os.path.isabs(token) and os.path.isfile(token):
            container_path = mapped.get(token)
            if container_path is None:
                container_path = _container_path(token, IN_MOUNT_DIR)
                mapped[token] = container_path
                # ro bind: a static input (wordlist, etc.) the tool only reads.
                mounts += ["-v", f"{token}:{container_path}:ro"]
            argv.append(container_path)
        else:
            argv.append(token)
    return [
        "docker", "run", "--rm",
        "--network", SANDBOX_NETWORK_MODE,
        "--memory", "512m", "--cpus", "1", "--pids-limit", "256",
        "--read-only", "--tmpfs", "/tmp",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        *mounts,
        settings.SCANNER_IMAGE,
        *argv,
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

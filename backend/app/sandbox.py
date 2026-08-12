"""Ephemeral, hardened Docker sandbox for scanner tools.

When :data:`settings.use_docker_sandbox` is enabled, an external scanner tool
(nmap, nuclei, ffuf, ...) should run inside a throwaway, locked-down container
rather than directly on the API host. This module builds the ``docker run``
invocation with the hardening flags that make that isolation real:

* ``--rm`` — the container is destroyed the instant the tool exits.
* ``--network`` — attached to a single, controlled network mode.
* ``--memory``/``--cpus``/``--pids-limit`` — resource caps so one scan cannot
  starve the host.
* ``--read-only`` + ``--tmpfs /tmp`` — an immutable root filesystem with only a
  scratch ``/tmp``.
* ``--cap-drop ALL`` + ``--security-opt no-new-privileges`` — no Linux
  capabilities and no privilege escalation.

Docker is **not** installed on the current dev machine, so nothing here shells
out at import time; the module only *constructs* commands. :func:`maybe_wrap` is
the seam a caller uses to opt a command into the sandbox based on config.
"""

from __future__ import annotations

from .config import settings

#: Docker network mode for scanner containers. ``bridge`` gives the tool
#: outbound access (recon needs to reach the target) while keeping it off the
#: host's network namespace.
SANDBOX_NETWORK_MODE = "bridge"


def build_docker_cmd(
    inner_cmd: list[str], allow_hosts: list[str] | None = None
) -> list[str]:
    """Wrap ``inner_cmd`` in a hardened, ephemeral ``docker run`` invocation.

    ``inner_cmd`` is the scanner command as it would run on the host (e.g.
    ``["nmap", "-T4", "example.com"]``); the returned list is the full
    ``docker run ...`` argv that runs it inside the sandbox image.

    ``allow_hosts`` is accepted for a future egress-allowlist implementation.

    TODO(ops): true egress firewalling to ``allow_hosts`` is an operational
    concern (a per-container network + iptables/nftables egress policy, or a
    filtering proxy). The hardening flags and container ephemerality below are
    real; the host allowlist is best-effort and intentionally deferred.
    """
    _ = allow_hosts  # reserved for egress allowlisting (see TODO above)
    return [
        "docker",
        "run",
        "--rm",
        "--network",
        SANDBOX_NETWORK_MODE,
        "--memory",
        "512m",
        "--cpus",
        "1",
        "--pids-limit",
        "256",
        "--read-only",
        "--tmpfs",
        "/tmp",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        settings.SCANNER_IMAGE,
        *inner_cmd,
    ]


def maybe_wrap(
    cmd: list[str], allow_hosts: list[str] | None = None
) -> list[str]:
    """Return the sandbox-wrapped command when enabled, else ``cmd`` unchanged.

    This is the seam meant to sit in front of a scanner's ``subprocess`` call:
    with :data:`settings.SANDBOX_MODE` at its ``"none"`` default it is a no-op,
    preserving today's inline behavior exactly.
    """
    if settings.use_docker_sandbox:
        return build_docker_cmd(cmd, allow_hosts)
    return cmd

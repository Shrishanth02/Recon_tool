"""TEMPORARY CI-only OOM diagnostic (v6) — REMOVE once the pytest OOM is fixed.

The OOM is non-deterministic, out of the pytest process tree, and v4 caught a
>6 GB allocation at subprocess.Popen(preexec_fn=...) (the fork path used by the
sandbox's stream_command). Confirm the cause by ELIMINATION with repetition and
simultaneously test two candidate fixes:

  * BASELINE       — full suite as CI runs it (expected to OOM often).
  * NO-SANDBOX     — full suite minus test_sandbox_isolation.py (the only tests
                     that spawn real subprocesses through the fork/preexec path).
  * ARENA2         — full suite with MALLOC_ARENA_MAX=2 (limits glibc arenas).

A run counts as an OOM when pytest exits by signal (rc < 0) or 137.
"""

import os
import subprocess
import sys

REPS = 3


def run(label, args, extra_env=None):
    env = dict(os.environ)
    env["PYTHONUNBUFFERED"] = "1"
    if extra_env:
        env.update(extra_env)
    cmd = [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", *args]
    rcs = []
    for _ in range(REPS):
        proc = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env)
        rcs.append(proc.returncode)
    ooms = sum(1 for r in rcs if r < 0 or r == 137)
    print("::warning title=OOMDIAG-%s::rcs=%s ooms=%d/%d" % (label, rcs, ooms, len(rcs)))
    sys.stdout.flush()
    return rcs


run("BASELINE", [])
run("NO-SANDBOX", ["--ignore=tests/test_sandbox_isolation.py"])
run("ARENA2", [], {"MALLOC_ARENA_MAX": "2"})

"""TEMPORARY CI-only diagnostic (v9) — REMOVE once the fix lands.

v8 proved it is NOT an OOM (system memory 7% at the SIGKILL). The SIGKILL comes
from the sandbox's terminate_process_tree() -> os.killpg(os.getpgid(proc.pid),
SIGKILL) resolving to a process group that contains pytest itself. This run
installs a guard that REFUSES any killpg targeting our own process group (or a
non-positive pgid), logs every killpg call, and runs the full suite 3x. If the
suite now passes reliably AND the log shows BLOCKED self-kills, the self-kill is
proven and the guard is exactly the fix to apply to app/sandbox.py.
"""

import os
import subprocess
import sys
import tempfile

TMP = tempfile.gettempdir()
PLUGIN = os.path.join(TMP, "oomdiag_plugin.py")
with open(PLUGIN, "w", encoding="utf-8") as fh:
    fh.write(
        "import os\n"
        "_real = os.killpg\n"
        "_lf = open(os.environ['OOMDIAG_KILLLOG'], 'a', buffering=1, encoding='utf-8')\n"
        "def _guard(pgid, sig):\n"
        "    own = os.getpgrp()\n"
        "    if pgid == own or pgid <= 0:\n"
        "        _lf.write('BLOCKED-SELF-KILLPG pgid=%s own=%s sig=%s\\n' % (pgid, own, sig))\n"
        "        return\n"
        "    _lf.write('killpg pgid=%s own=%s sig=%s\\n' % (pgid, own, sig))\n"
        "    return _real(pgid, sig)\n"
        "os.killpg = _guard\n"
    )


def run(rep):
    killlog = os.path.join(TMP, "killpg_%d.log" % rep)
    open(killlog, "w", encoding="utf-8").close()
    env = dict(os.environ)
    env["PYTHONUNBUFFERED"] = "1"
    env["OOMDIAG_KILLLOG"] = killlog
    env["PYTHONPATH"] = TMP + os.pathsep + env.get("PYTHONPATH", "")
    cmd = [sys.executable, "-u", "-m", "pytest", "-q", "-p", "oomdiag_plugin", "-p", "no:cacheprovider"]
    proc = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env)
    with open(killlog, encoding="utf-8") as fh:
        lines = fh.read().splitlines()
    blocked = sum(1 for ln in lines if ln.startswith("BLOCKED"))
    normal = sum(1 for ln in lines if ln.startswith("killpg"))
    return proc.returncode, blocked, normal, lines


results = []
for rep in range(3):
    results.append(run(rep))

rcs = [r[0] for r in results]
ooms = sum(1 for r in rcs if r < 0 or r == 137)
tot_blocked = sum(r[1] for r in results)
tot_normal = sum(r[2] for r in results)
print("::warning title=OOMDIAG-GUARD::rcs=%s ooms=%d/3 blocked_self_killpg=%d normal_killpg=%d"
      % (rcs, ooms, tot_blocked, tot_normal))
# show a couple of the BLOCKED lines as proof
sample = []
for r in results:
    for ln in r[3]:
        if ln.startswith("BLOCKED"):
            sample.append(ln)
print("::warning title=OOMDIAG-GUARD-PROOF::%s" % ((" || ".join(sample[:6]) or "(no self-killpg observed)")[:1200]))
print("\n=== v9 === rcs", rcs, "blocked", tot_blocked, "normal", tot_normal)

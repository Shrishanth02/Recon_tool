"""TEMPORARY CI-only diagnostic (v10) — REMOVE once the real fix lands.

Established: NOT an OOM (v8: 7% system memory at death) and NOT a killpg-to-own
suicide (v9: guard blocked 0, still SIGKILL 3/3). Yet pytest dies with SIGKILL,
caused by the sandbox tests. Get the kernel's ground truth: run pytest, and on a
signal death dump `sudo dmesg` (OOM killer / cgroup / kill records), the cgroup
memory limits, the process count, and system memory — so we learn exactly what
sent the SIGKILL.
"""

import glob
import subprocess
import sys


def read(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return fh.read().strip()
    except Exception:
        return "?"


cmd = [sys.executable, "-u", "-m", "pytest", "-q", "-p", "no:cacheprovider"]
proc = subprocess.run(cmd)
rc = proc.returncode

nproc = len(glob.glob("/proc/[0-9]*"))
cg_cur = read("/sys/fs/cgroup/memory.current")
cg_max = read("/sys/fs/cgroup/memory.max")
cg_events = read("/sys/fs/cgroup/memory.events")
meminfo = read("/proc/meminfo").splitlines()[:3]

dmesg = ""
try:
    d = subprocess.run(["sudo", "dmesg"], capture_output=True, text=True, timeout=30)
    dmesg = d.stdout or d.stderr
except Exception as e:
    dmesg = "dmesg failed: %s" % e

# keep only lines that explain a kill
keep = [ln for ln in dmesg.splitlines()
        if any(k in ln.lower() for k in ("oom", "kill", "memory cgroup", "out of memory", "sig"))]
tail = keep[-14:] if keep else dmesg.splitlines()[-8:]

print("::warning title=OOMDIAG-KERNEL::exit=%d nproc=%d cgroup_cur=%s cgroup_max=%s | %s"
      % (rc, nproc, cg_cur, cg_max, " ; ".join(meminfo)))
print("::warning title=OOMDIAG-CGEVENTS::%s" % cg_events.replace("\n", " ; ")[:400])
print("::warning title=OOMDIAG-DMESG::%s" % ((" || ".join(tail)) or "(no kill-related dmesg lines)")[:1500])
print("\n=== v10 === exit", rc, "nproc", nproc)
print("cgroup_cur", cg_cur, "cgroup_max", cg_max)
print("dmesg tail:")
for ln in tail:
    print("  " + ln)

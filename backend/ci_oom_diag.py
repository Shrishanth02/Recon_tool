"""TEMPORARY CI-only OOM diagnostic — REMOVE once the pytest OOM is fixed.

Runs the full pytest suite on the Linux runner under a memory sampler and reports,
via GitHub ``::warning::`` annotations (readable through the check-runs API without
downloading logs), the peak process-tree RSS, when it was reached, and the exact
test that was RUNNING when the process was OOM-killed.

A tiny in-process plugin records each test's nodeid at start (line-buffered to a
file) so the last line survives the uncatchable SIGKILL. The monitor process is
tiny, so the kernel OOM killer targets the big pytest child, not this monitor.
"""

import collections
import os
import subprocess
import sys
import tempfile
import threading
import time

import psutil

CUR = os.path.join(tempfile.gettempdir(), "oomdiag_cur.txt")
PLUGIN = os.path.join(tempfile.gettempdir(), "oomdiag_plugin.py")

with open(PLUGIN, "w", encoding="utf-8") as fh:
    fh.write(
        "import os\n"
        "_f = open(os.environ['OOMDIAG_CUR'], 'w', buffering=1, encoding='utf-8')\n"
        "def pytest_runtest_logstart(nodeid, location):\n"
        "    _f.write(nodeid + '\\n')\n"
    )

open(CUR, "w", encoding="utf-8").close()

env = dict(os.environ)
env["PYTHONUNBUFFERED"] = "1"
env["OOMDIAG_CUR"] = CUR
env["PYTHONPATH"] = tempfile.gettempdir() + os.pathsep + env.get("PYTHONPATH", "")

cmd = [
    sys.executable, "-u", "-m", "pytest", "-q",
    "-p", "oomdiag_plugin", "-p", "no:cacheprovider",
]
p = subprocess.Popen(
    cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, env=env
)

peak = 0.0
peak_t = 0.0
peak_nproc = 1
t0 = time.time()
stop = threading.Event()
parent = psutil.Process(p.pid)


def sample():
    global peak, peak_t, peak_nproc
    while not stop.is_set():
        try:
            total = parent.memory_info().rss
            nproc = 1
            for child in parent.children(recursive=True):
                try:
                    total += child.memory_info().rss
                    nproc += 1
                except Exception:
                    pass
            if total > peak:
                peak, peak_t, peak_nproc = total, time.time() - t0, nproc
        except Exception:
            break
        stop.wait(0.2)


th = threading.Thread(target=sample, daemon=True)
th.start()

tail = collections.deque(maxlen=20)
for line in p.stdout:
    tail.append(line.rstrip())
rc = p.wait()
stop.set()
th.join(timeout=2)

with open(CUR, encoding="utf-8") as fh:
    started = fh.read().splitlines()

vm = psutil.virtual_memory().total / 1e6
summary = (
    "exit=%d peak_rss=%.0fMB at t=%.1fs peak_nproc=%d runner_mem=%.0fMB "
    "tests_started=%d last_started=%s"
    % (rc, peak / 1e6, peak_t, peak_nproc, vm, len(started),
       started[-1] if started else "(none)")
)
print("::warning title=OOMDIAG::" + summary[:1400])
print("\n=== OOMDIAG ===")
print(summary)
print("last 15 tests started:")
for nid in started[-15:]:
    print("  " + nid)
print("last pytest output lines:")
for outline in tail:
    print("  " + outline)

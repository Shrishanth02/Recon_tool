"""TEMPORARY CI-only OOM diagnostic (v5) — REMOVE once the pytest OOM is fixed.

The OOM triggers inside subprocess.Popen(close_fds=True, preexec_fn=...) in
stream_command (fork path). This run records, per test, the pytest process's
RSS *and* virtual size (VmSize) *and* live child-process count, to tell apart:
  * VmSize ballooning (glibc arenas / mmap) -> fork COW explosion, vs
  * child-process accumulation (subprocesses not reaped) -> process leak.
No address-space cap this time, so the natural OOM curve is captured up to the
kill. The monitor also samples the whole-tree peak RSS.
"""

import os
import subprocess
import sys
import tempfile
import threading

import psutil

TMP = tempfile.gettempdir()
PLUGIN = os.path.join(TMP, "oomdiag_plugin.py")
with open(PLUGIN, "w", encoding="utf-8") as fh:
    fh.write(
        "import os, threading, psutil\n"
        "_p = psutil.Process(os.getpid())\n"
        "_f = open(os.environ['OOMDIAG_LOG'], 'w', buffering=1, encoding='utf-8')\n"
        "def _row(tag, nodeid):\n"
        "    mi = _p.memory_info()\n"
        "    try: nch = len(_p.children(recursive=True))\n"
        "    except Exception: nch = -1\n"
        "    _f.write('%s rss=%.0f vms=%.0f nch=%d nthr=%d %s\\n'\n"
        "             % (tag, mi.rss/1e6, mi.vms/1e6, nch, threading.active_count(), nodeid))\n"
        "def pytest_runtest_logstart(nodeid, location):\n"
        "    _row('START', nodeid)\n"
        "def pytest_runtest_logreport(report):\n"
        "    if report.when == 'teardown':\n"
        "        _row('END', report.nodeid)\n"
    )

log = os.path.join(TMP, "oomdiag_full.log")
open(log, "w", encoding="utf-8").close()
env = dict(os.environ)
env["PYTHONUNBUFFERED"] = "1"
env["OOMDIAG_LOG"] = log
env["PYTHONPATH"] = TMP + os.pathsep + env.get("PYTHONPATH", "")
cmd = [
    sys.executable, "-u", "-m", "pytest", "-q",
    "-p", "oomdiag_plugin", "-p", "no:cacheprovider",
]
p = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env)
peak = 0.0
stop = threading.Event()
parent = psutil.Process(p.pid)


def sample():
    global peak
    while not stop.is_set():
        try:
            total = parent.memory_info().rss
            for child in parent.children(recursive=True):
                try:
                    total += child.memory_info().rss
                except Exception:
                    pass
            if total > peak:
                peak = total
        except Exception:
            break
        stop.wait(0.05)


th = threading.Thread(target=sample, daemon=True)
th.start()
rc = p.wait()
stop.set()
th.join(timeout=2)

with open(log, encoding="utf-8") as fh:
    lines = fh.read().splitlines()

# emit the last ~18 rows (the VmSize / child-count trajectory into the OOM)
tail = " || ".join(lines[-18:])
print("::warning title=OOMDIAG-VMS::exit=%d tree_peak_rss=%.0fMB rows=%d  TAIL: %s"
      % (rc, peak / 1e6, len(lines), tail[:1500]))
# also emit a coarse VmSize progression (every ~80th row) to see the climb
prog = []
for i in range(0, len(lines), 80):
    ln = lines[i]
    if "vms=" in ln:
        prog.append(ln.split("vms=")[1].split(" ")[0])
print("::warning title=OOMDIAG-VMSCURVE::vms_MB every~80 tests: %s" % (" ".join(prog))[:1400])

print("\n=== OOMDIAG v5 ===  exit", rc, "tree_peak_MB", peak / 1e6)
for ln in lines[-40:]:
    print("  " + ln)

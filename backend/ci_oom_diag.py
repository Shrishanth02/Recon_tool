"""TEMPORARY CI-only OOM diagnostic (v7) — REMOVE once the pytest OOM is fixed.

Elimination proved the OOM is caused by test_sandbox_isolation.py's subprocess
spawns (close_fds=True fork path) amplifying a resource leaked by earlier tests,
and that it is NOT glibc arenas. This run measures, per test, the open
file-descriptor count and the number of memory-mapping regions (VMAs) so a leak
that fork/close_fds amplifies becomes visible. Single full run (OOMs early-ish).
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
        "import os, psutil\n"
        "_p = psutil.Process(os.getpid())\n"
        "_f = open(os.environ['OOMDIAG_LOG'], 'w', buffering=1, encoding='utf-8')\n"
        "def _stats():\n"
        "    try: fds = len(os.listdir('/proc/self/fd'))\n"
        "    except Exception: fds = -1\n"
        "    try:\n"
        "        with open('/proc/self/maps') as m: vmas = sum(1 for _ in m)\n"
        "    except Exception: vmas = -1\n"
        "    return fds, vmas, _p.memory_info().rss/1e6\n"
        "def pytest_runtest_logreport(report):\n"
        "    if report.when == 'teardown':\n"
        "        fds, vmas, rss = _stats()\n"
        "        _f.write('fds=%d vmas=%d rss=%.0f %s\\n' % (fds, vmas, rss, report.nodeid))\n"
    )

log = os.path.join(TMP, "oomdiag_full.log")
open(log, "w", encoding="utf-8").close()
env = dict(os.environ)
env["PYTHONUNBUFFERED"] = "1"
env["OOMDIAG_LOG"] = log
env["PYTHONPATH"] = TMP + os.pathsep + env.get("PYTHONPATH", "")
cmd = [sys.executable, "-u", "-m", "pytest", "-q", "-p", "oomdiag_plugin", "-p", "no:cacheprovider"]
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

tail = " || ".join(lines[-12:])
print("::warning title=OOMDIAG-FDS::exit=%d peak=%.0fMB rows=%d  TAIL: %s"
      % (rc, peak / 1e6, len(lines), tail[:1400]))
fdcurve = []
vmacurve = []
for i in range(0, len(lines), 60):
    ln = lines[i]
    if "fds=" in ln:
        fdcurve.append(ln.split("fds=")[1].split(" ")[0])
        vmacurve.append(ln.split("vmas=")[1].split(" ")[0])
print("::warning title=OOMDIAG-FDCURVE::fds every~60: %s || vmas: %s"
      % (" ".join(fdcurve), " ".join(vmacurve)))
print("\n=== v7 ===", rc)
for ln in lines[-30:]:
    print("  " + ln)

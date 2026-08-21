"""TEMPORARY CI-only OOM diagnostic (v3) — REMOVE once the pytest OOM is fixed.

The OOM test is test_check_schedules_enqueues_in_scope, but it passes in
isolation and OOMs only in the full suite, on the async (await) path, with a flat
RSS curve up to a sudden spike. That points to a background thread left running
by an earlier test. This run records per-test RSS + live thread count and, at the
victim's start, dumps every thread's name and stack — so a rogue background
thread (and what it is doing) becomes visible via ::warning:: annotations.
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
        "import os, sys, threading, traceback, psutil\n"
        "_p = psutil.Process(os.getpid())\n"
        "_f = open(os.environ['OOMDIAG_LOG'], 'w', buffering=1, encoding='utf-8')\n"
        "def _rss():\n"
        "    t = _p.memory_info().rss\n"
        "    for c in _p.children(recursive=True):\n"
        "        try: t += c.memory_info().rss\n"
        "        except Exception: pass\n"
        "    return t / 1e6\n"
        "def pytest_runtest_logstart(nodeid, location):\n"
        "    _f.write('START\\t%.0f\\t%d\\t%s\\n' % (_rss(), threading.active_count(), nodeid))\n"
        "    if 'test_check_schedules_enqueues' in nodeid:\n"
        "        _f.write('THREADS %s\\n' % [t.name for t in threading.enumerate()])\n"
        "        frames = sys._current_frames()\n"
        "        for t in threading.enumerate():\n"
        "            fr = frames.get(t.ident)\n"
        "            if fr is None:\n"
        "                continue\n"
        "            st = ' ~ '.join(x.strip() for x in traceback.format_stack(fr)[-5:])\n"
        "            _f.write('STACK[%s] %s\\n' % (t.name, st[:600]))\n"
        "def pytest_runtest_logreport(report):\n"
        "    if report.when == 'teardown':\n"
        "        _f.write('END\\t%.0f\\t%d\\t%s\\n' % (_rss(), threading.active_count(), report.nodeid))\n"
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

starts = [ln for ln in lines if ln.startswith(("START", "END"))]
threadlines = [ln for ln in lines if ln.startswith(("THREADS", "STACK["))]
tcurve = " || ".join(starts[-12:])
print("::warning title=OOMDIAG-SUMMARY::exit=%d peak_sampled=%.0fMB logged=%d  CURVE: %s"
      % (rc, peak / 1e6, len(lines), tcurve[:1300]))
# thread dump at the victim, possibly across a few annotations
chunk = ""
idx = 0
for tl in threadlines:
    if len(chunk) + len(tl) > 1300:
        print("::warning title=OOMDIAG-THREADS-%d::%s" % (idx, chunk))
        idx += 1
        chunk = ""
    chunk += tl + "  ||  "
if chunk:
    print("::warning title=OOMDIAG-THREADS-%d::%s" % (idx, chunk))

print("\n=== OOMDIAG v3 ===")
print("exit", rc, "peak_sampled_MB", peak / 1e6)
for ln in lines[-40:]:
    print("  " + ln)

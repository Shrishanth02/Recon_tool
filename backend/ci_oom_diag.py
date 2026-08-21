"""TEMPORARY CI-only OOM diagnostic (v2) — REMOVE once the pytest OOM is fixed.

Two experiments on the real Linux runner, each under a memory monitor + a
per-test RSS plugin, reported via GitHub ``::warning::`` annotations:

  1. ISOLATED — run tests/test_scheduled_scan_security.py alone. If it OOMs by
     itself, the culprit is inside that file; if it passes, the OOM is cumulative
     or comes from a background thread left by an earlier test.
  2. FULL — run the whole suite. The per-test RSS log (START rss before each
     test, END rss after teardown) shows whether RSS climbs gradually
     (cumulative) or is flat right up to a single spiking test.

The monitor process is tiny, so the kernel OOM killer targets the big pytest
child, not this monitor — letting it report after the kill.
"""

import os
import subprocess
import sys
import tempfile
import threading
import time

import psutil

TMP = tempfile.gettempdir()
PLUGIN = os.path.join(TMP, "oomdiag_plugin.py")
with open(PLUGIN, "w", encoding="utf-8") as fh:
    fh.write(
        "import os, psutil\n"
        "_p = psutil.Process(os.getpid())\n"
        "_f = open(os.environ['OOMDIAG_LOG'], 'w', buffering=1, encoding='utf-8')\n"
        "def _rss():\n"
        "    t = _p.memory_info().rss\n"
        "    for c in _p.children(recursive=True):\n"
        "        try: t += c.memory_info().rss\n"
        "        except Exception: pass\n"
        "    return t / 1e6\n"
        "def pytest_runtest_logstart(nodeid, location):\n"
        "    _f.write('START\\t%.0f\\t%s\\n' % (_rss(), nodeid))\n"
        "def pytest_runtest_logreport(report):\n"
        "    if report.when == 'teardown':\n"
        "        _f.write('END\\t%.0f\\t%s\\n' % (_rss(), report.nodeid))\n"
    )


def run(args, label):
    log = os.path.join(TMP, "oomdiag_%s.log" % label)
    open(log, "w", encoding="utf-8").close()
    env = dict(os.environ)
    env["PYTHONUNBUFFERED"] = "1"
    env["OOMDIAG_LOG"] = log
    env["PYTHONPATH"] = TMP + os.pathsep + env.get("PYTHONPATH", "")
    cmd = [
        sys.executable, "-u", "-m", "pytest", "-q",
        "-p", "oomdiag_plugin", "-p", "no:cacheprovider", *args,
    ]
    p = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env)
    peak = 0.0
    t0 = time.time()
    stop = threading.Event()
    parent = psutil.Process(p.pid)

    def sample():
        nonlocal peak
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
    tail = " || ".join(lines[-14:])
    summary = "%s exit=%d peak_sampled=%.0fMB wall=%.1fs logged=%d" % (
        label, rc, peak / 1e6, time.time() - t0, len(lines))
    print("::warning title=OOMDIAG-%s::%s" % (label, (summary + "  TAIL: " + tail)[:1600]))
    print("\n=== %s ===" % label)
    print(summary)
    for ln in lines[-30:]:
        print("  " + ln)
    return rc


vm = psutil.virtual_memory().total / 1e6
print("::warning title=OOMDIAG-ENV::runner_mem=%.0fMB python=%s" % (vm, sys.version.split()[0]))
run(["tests/test_scheduled_scan_security.py"], "ISOLATED")
run([], "FULL")

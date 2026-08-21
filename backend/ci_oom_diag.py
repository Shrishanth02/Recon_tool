"""TEMPORARY CI-only OOM diagnostic (v4) — REMOVE once the pytest OOM is fixed.

The OOM is a sudden ~16 GB single allocation at a NON-deterministic test (varies
run to run), single-threaded, flat baseline. To pin the exact allocation line we
cap the pytest child's address space (RLIMIT_AS) so the giant allocation raises
MemoryError WITH A TRACEBACK instead of being OOM-killed; a plugin captures the
failing test's longrepr and we surface it via ::warning:: annotations. Also
prints RLIMIT_NOFILE (a huge value is a classic source of fd-sized allocations
on Linux containers).
"""

import os
import resource
import subprocess
import sys
import tempfile
import threading

import psutil

TMP = tempfile.gettempdir()
PLUGIN = os.path.join(TMP, "oomdiag_plugin.py")
with open(PLUGIN, "w", encoding="utf-8") as fh:
    fh.write(
        "import os\n"
        "_f = open(os.environ['OOMDIAG_LOG'], 'w', buffering=1, encoding='utf-8')\n"
        "def pytest_runtest_logreport(report):\n"
        "    if report.failed:\n"
        "        _f.write('FAILED[%s] %s\\n' % (report.when, report.nodeid))\n"
        "        _f.write(str(report.longrepr)[:6000] + '\\n---ENDFAIL---\\n')\n"
    )

soft_nofile, hard_nofile = resource.getrlimit(resource.RLIMIT_NOFILE)
soft_as, hard_as = resource.getrlimit(resource.RLIMIT_AS)
print("::warning title=OOMDIAG-LIMITS::RLIMIT_NOFILE soft=%s hard=%s | RLIMIT_AS soft=%s hard=%s"
      % (soft_nofile, hard_nofile, soft_as, hard_as))

CAP = 6 * 1024 * 1024 * 1024  # 6 GiB address-space cap for the pytest child


def _cap():
    try:
        resource.setrlimit(resource.RLIMIT_AS, (CAP, CAP))
    except Exception:
        pass


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
p = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env, preexec_fn=_cap)
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
    content = fh.read()

print("::warning title=OOMDIAG-RESULT::exit=%d peak_sampled=%.0fMB cap=6GiB failures_captured=%d"
      % (rc, peak / 1e6, content.count("FAILED[")))

blocks = [b for b in content.split("---ENDFAIL---") if "FAILED[" in b]
for i, b in enumerate(blocks[:4]):
    # emphasise the MemoryError / allocation frames
    msg = b.strip().replace("\n", " || ")
    print("::warning title=OOMDIAG-FAIL-%d::%s" % (i, msg[:1600]))

print("\n=== OOMDIAG v4 ===")
print("exit", rc, "peak_MB", peak / 1e6)
print(content[-6000:])

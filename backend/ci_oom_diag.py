"""TEMPORARY CI-only OOM diagnostic (v8) — REMOVE once the pytest failure is fixed.

Reframe: memory never spiked (peak ~262 MB across many runs) and fds/VMAs are
flat, yet pytest dies with SIGKILL. The sandbox's terminate_process_tree() does
os.killpg(os.getpgid(proc.pid), SIGKILL) — a SIGKILL source that, on a wrong/stale
pgid, kills pytest's own group (NOT an OOM). This run samples SYSTEM memory at
high frequency and reports the used-memory trajectory right up to pytest's death:
if system memory is LOW at death, it is a self-inflicted killpg, not an OOM.
"""

import collections
import subprocess
import sys
import threading
import time

import psutil

cmd = [sys.executable, "-u", "-m", "pytest", "-q", "-p", "no:cacheprovider"]
p = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
ring = collections.deque(maxlen=30)  # last ~1.5s of system-memory samples
peak_used = 0.0
stop = threading.Event()
t0 = time.time()


def sample():
    global peak_used
    while not stop.is_set():
        try:
            vm = psutil.virtual_memory()
            used = vm.used / 1e6
            if used > peak_used:
                peak_used = used
            ring.append("%.1fs:%.0fMB" % (time.time() - t0, used))
        except Exception:
            pass
        stop.wait(0.05)


th = threading.Thread(target=sample, daemon=True)
th.start()
rc = p.wait()
stop.set()
th.join(timeout=2)

total = psutil.virtual_memory().total / 1e6
last = " ".join(list(ring))
print("::warning title=OOMDIAG-SYSMEM::exit=%d total_mem=%.0fMB peak_used=%.0fMB "
      "(%.0f%% of total)  LAST_SAMPLES: %s"
      % (rc, total, peak_used, 100 * peak_used / total, last[:1200]))
verdict = "LIKELY NOT OOM (killpg/self-kill)" if peak_used < 0.6 * total else "consistent with OOM"
print("::warning title=OOMDIAG-VERDICT::%s (peak_used %.0fMB vs total %.0fMB)"
      % (verdict, peak_used, total))
print("\n=== v8 === exit", rc, "peak_used_MB", peak_used, "total_MB", total)

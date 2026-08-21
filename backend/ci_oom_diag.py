"""TEMPORARY CI-only diagnostic (v11) — REMOVE once the real fix lands.

Outcome is flaky: sometimes SIGKILL (-9), sometimes a test failure (exit 1), no
OOM and no kernel kill (v10). That is a subprocess reaping/timing race in the
sandbox tests (only in the full suite). Run the suite a few times capturing the
pytest failure summary so we learn exactly which test(s) fail and why.
"""

import subprocess
import sys


def run(rep):
    cmd = [sys.executable, "-u", "-m", "pytest", "-q", "-rfE", "--tb=line",
           "-p", "no:cacheprovider"]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    out = (proc.stdout or "") + (proc.stderr or "")
    lines = out.splitlines()
    # capture FAILED/ERROR summary lines + any "returncode"/assert lines
    interesting = [ln for ln in lines
                   if ln.startswith(("FAILED", "ERROR"))
                   or "assert" in ln.lower() or "Error" in ln
                   or "sandbox" in ln.lower() or "::" in ln and ("FAIL" in ln or "Error" in ln)]
    summary = [ln for ln in lines if " passed" in ln or " failed" in ln or " error" in ln]
    return proc.returncode, interesting[-12:], summary[-1:] if summary else []


for rep in range(3):
    rc, interesting, summary = run(rep)
    msg = "rc=%d | %s | %s" % (rc, " ".join(summary), " || ".join(interesting))
    print("::warning title=OOMDIAG-RUN%d::%s" % (rep, msg[:1500]))
    print("\n=== run %d === rc=%d" % (rep, rc))
    print("summary:", summary)
    for ln in interesting:
        print("  " + ln)

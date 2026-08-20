# Dependency locking + auditing (P1-H3).
#
# Layout (pip-tools):
#   requirements.in / requirements-dev.in   -> human-edited SOURCE (direct deps
#                                              + real constraints, e.g. bcrypt<4.1)
#   requirements.txt / requirements-dev.txt  -> GENERATED, fully-pinned, HASHED
#                                              locks capturing every transitive.
# Commit all four. Production and CI install ONLY the locks, with --require-hashes.
#
# Prerequisites:  pip install uv pip-audit
#
# Locks are UNIVERSAL (`uv pip compile --universal`): resolved for EVERY OS and
# Python version the project targets, with PEP 508 markers on the conditional
# distributions. This matters because the runtime (Docker + CI) is Linux/Python
# 3.11 while dev machines may be Windows/3.13: a platform-scoped lock generated
# on Windows/3.13 OMITS Linux-only deps (e.g. `uvloop`, pulled by
# uvicorn[standard]) and version-gated deps (e.g. `async-timeout`), which then
# makes `pip install --require-hashes` FAIL on the Linux/3.11 target. A universal
# lock includes them (behind markers), so `--require-hashes` resolves correctly
# on every target. Regenerate from any dev machine; commit all locks.
#
# Reproducibility: `make lock` re-pins from the .in files, preferring the
# versions already in the .txt (uv reads the output file as preferences), so it
# reproduces the committed locks. `make lock-upgrade` moves versions forward.

UV_COMPILE = uv pip compile --universal --generate-hashes

.PHONY: lock lock-upgrade audit audit-all

## Re-pin the locks from the .in files, keeping the current versions.
lock:
	$(UV_COMPILE) requirements.in --output-file=requirements.txt
	$(UV_COMPILE) requirements-dev.in --constraint=requirements.txt --output-file=requirements-dev.txt
	$(UV_COMPILE) requirements-optional.in --constraint=requirements.txt --output-file=requirements-optional.txt

## Upgrade every dependency to the latest compatible version, then re-lock.
lock-upgrade:
	$(UV_COMPILE) --upgrade requirements.in --output-file=requirements.txt
	$(UV_COMPILE) --upgrade requirements-dev.in --constraint=requirements.txt --output-file=requirements-dev.txt
	$(UV_COMPILE) --upgrade requirements-optional.in --constraint=requirements.txt --output-file=requirements-optional.txt

## Scan the PRODUCTION lock for known vulnerabilities (matches the CI gate).
## Fails on any advisory NOT in the reviewed baseline (.pip-audit-ignores).
audit:
	pip-audit --no-deps --requirement requirements.txt \
		$(shell grep -vE '^[[:space:]]*#|^[[:space:]]*$$' .pip-audit-ignores | sed 's/^/--ignore-vuln /') --desc

## Show ALL current advisories (including the baseline) — the upgrade backlog.
audit-all:
	pip-audit --no-deps --requirement requirements.txt --desc

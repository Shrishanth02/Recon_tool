# Dependency locking + auditing (P1-H3).
#
# Layout (pip-tools):
#   requirements.in / requirements-dev.in   -> human-edited SOURCE (direct deps
#                                              + real constraints, e.g. bcrypt<4.1)
#   requirements.txt / requirements-dev.txt  -> GENERATED, fully-pinned, HASHED
#                                              locks capturing every transitive.
# Commit all four. Production and CI install ONLY the locks, with --require-hashes.
#
# Prerequisites:  pip install pip-tools pip-audit
#
# Reproducibility: `make lock` regenerates the locks from the .in files WITHOUT
# upgrading (pip-tools preserves the versions already pinned in the .txt), so it
# reproduces the committed locks. `make lock-upgrade` is the deliberate,
# reviewed way to move versions forward.

PIP_COMPILE = pip-compile --generate-hashes --allow-unsafe

.PHONY: lock lock-upgrade audit

## Re-pin the locks from the .in files, keeping the current versions.
lock:
	$(PIP_COMPILE) --output-file=requirements.txt requirements.in
	$(PIP_COMPILE) --constraint=requirements.txt --output-file=requirements-dev.txt requirements-dev.in

## Upgrade every dependency to the latest compatible version, then re-lock.
lock-upgrade:
	$(PIP_COMPILE) --upgrade --output-file=requirements.txt requirements.in
	$(PIP_COMPILE) --upgrade --constraint=requirements.txt --output-file=requirements-dev.txt requirements-dev.in

## Scan the PRODUCTION lock for known vulnerabilities (matches the CI gate).
## Fails on any advisory NOT in the reviewed baseline (.pip-audit-ignores).
audit:
	pip-audit --no-deps --requirement requirements.txt \
		$(shell grep -vE '^[[:space:]]*#|^[[:space:]]*$$' .pip-audit-ignores | sed 's/^/--ignore-vuln /') --desc

## Show ALL current advisories (including the baseline) — the upgrade backlog.
audit-all:
	pip-audit --no-deps --requirement requirements.txt --desc

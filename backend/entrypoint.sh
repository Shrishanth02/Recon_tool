#!/bin/sh
# Production entrypoint for the RedOpsX API image.
#   1. Apply database migrations (alembic) on a real/managed DB, so a release
#      that adds a column/table actually reaches the live schema. SQLite dev
#      DBs keep using create_all (the app bootstraps them on startup).
#   2. Serve under gunicorn with N uvicorn workers (WEB_CONCURRENCY, default 4)
#      for real throughput and crash-isolation.
set -e

case "${DATABASE_URL:-}" in
  sqlite*|"")
    echo "[entrypoint] SQLite/unset DATABASE_URL — schema managed by create_all; skipping alembic."
    ;;
  *)
    echo "[entrypoint] Applying database migrations: alembic upgrade head"
    alembic upgrade head
    ;;
esac

WORKERS="${WEB_CONCURRENCY:-4}"
echo "[entrypoint] Starting gunicorn with ${WORKERS} uvicorn workers on :8002"
exec gunicorn app.main:app \
  -k uvicorn.workers.UvicornWorker \
  -w "${WORKERS}" \
  -b 0.0.0.0:8002 \
  --timeout 120 \
  --graceful-timeout 30 \
  --access-logfile - \
  --error-logfile -

# Deploying RECON-X

Two supported paths:

- **Docker Compose** — the quickest way to run the full production-shaped stack
  (API + Postgres + Redis + frontend) on a single host.
- **Helm** (`deploy/helm/reconx`) — self-hosted / on-prem delivery onto
  Kubernetes.

Both run the same v4.0.0 image. Local development does **not** need any of this —
`python run.py` uses SQLite and in-process scans (see the root
[README](../README.md)).

> **Authorized testing only.** RECON-X drives active security scanners. Deploy it
> only where operators are authorized to scan the targets they enter, and keep
> workspace scope and asset ownership verification enforced.

---

## 1. Docker Compose

From the repository root:

```bash
docker compose up --build
```

This is intended to bring up:

| Service    | Role                                                      |
|------------|-----------------------------------------------------------|
| `api`      | FastAPI backend (uvicorn); applies Alembic migrations     |
| `db`       | Postgres — backs `DATABASE_URL=postgresql+psycopg://…`    |
| `redis`    | Redis — backs `REDIS_URL` (Phase-2 queue/streaming)       |
| `frontend` | Built React dashboard (or the Vite dev server)            |

The API reads all configuration from the environment (see the
[configuration table](../README.md#configuration)). Before first boot:

- **Set a strong `JWT_SECRET`.** The app warns when the insecure default is used
  outside `DEBUG`; do not ship the default.
- **Point `DATABASE_URL` at Postgres**, e.g.
  `postgresql+psycopg://reconx:reconx@db:5432/reconx`. SQLAlchemy handles both
  SQLite and Postgres, so only the URL changes.
- **Set `REDIS_URL`** (e.g. `redis://redis:6379/0`) if you are exercising the
  Phase-2 queue scaffold; the app boots fine without Redis.
- **Optionally seed a first admin** with `BOOTSTRAP_ADMIN_EMAIL`,
  `BOOTSTRAP_ADMIN_PASSWORD` and `BOOTSTRAP_ORG_NAME`. The seed only runs when
  the database has no users yet.

Put these in a `.env` file next to `docker-compose.yml` (Compose loads it
automatically) or export them in the shell.

Schema is created two ways and both are safe to run: Alembic migrations
(`backend/migrations`) are authoritative for production, and the API also runs
`create_all()` on startup. For a fresh Postgres, apply migrations explicitly:

```bash
docker compose run --rm api alembic upgrade head
```

> **Status:** the `api` image reads `DATABASE_URL` / `REDIS_URL` / `JWT_SECRET`
> exactly as described. If a `docker-compose.yml` and Dockerfiles are not yet
> present at the repo root, add them wiring the four services above — the
> application contract (env vars, migrations, ports) is already stable.

---

## 2. Helm (self-hosted / on-prem)

The chart lives at `deploy/helm/reconx` (`Chart.yaml`: `reconx`, appVersion
`4.0.0`).

```bash
helm install reconx deploy/helm/reconx \
  --namespace reconx --create-namespace \
  --set env.JWT_SECRET=<strong-random-secret> \
  --set env.DATABASE_URL='postgresql+psycopg://reconx:reconx@reconx-postgres:5432/reconx' \
  --set env.REDIS_URL='redis://reconx-redis:6379/0'
```

Manage sensitive values (JWT secret, DB credentials) as Kubernetes Secrets
rather than plain `--set` flags in production, e.g.
`--set-string env.JWT_SECRET=$(openssl rand -hex 32)` sourced from a secret
store, or reference an existing Secret from the chart values.

Upgrade and remove:

```bash
helm upgrade reconx deploy/helm/reconx -n reconx -f my-values.yaml
helm uninstall reconx -n reconx
```

> **Status:** `Chart.yaml` is in place; the `templates/` directory is the
> scaffold for the Deployment, Service, Ingress and Secret manifests. Populate it
> with the API Deployment (env from the table above), a Service/Ingress for the
> API and frontend, and either bundled or external Postgres/Redis before a real
> install.

---

## Licensing

RECON-X ships in two delivery modes, reflected on each `Organization`
(`license_tier`):

- **Cloud** (`license_tier="cloud"`) — the managed multi-tenant SaaS.
- **Self-hosted / on-prem** — delivered via the Helm chart in this directory for
  customers who must keep scan data inside their own infrastructure.

Self-hosted deployments are governed by a separate license agreement. Confirm
your entitlement and tier before deploying on-prem, and keep the "authorized
testing only" obligations in the root README in force for every tenant.

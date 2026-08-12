# RECON-X

A real-time reconnaissance **and vulnerability-assessment** platform. A FastAPI
backend drives industry-standard security tools (`nmap`, `nuclei`, `httpx`,
`ffuf`, `subfinder`), streams their output live over a WebSocket to a
professional React dashboard, persists everything, enforces engagement scope,
and generates client-ready reports.

As of **v4.0.0** RECON-X is **multi-tenant and auth-gated**: users authenticate,
belong to organizations, and work inside scoped workspaces (engagements). The
same build runs locally with **zero external services** (SQLite + in-process
scans) and scales up to **Postgres + Redis** purely through environment
variables — the scanner engine is unchanged.

> **Authorized testing only.** Run scans against systems you own or have
> explicit written permission to test. Every workspace carries a **scope** and
> out-of-scope targets are refused. Asset **ownership verification** (DNS TXT)
> is the foundation for enforcing this at the tenant level.

---

## Features

- **Multi-tenant** — Organizations contain Users (via memberships), Workspaces
  (engagements), Assets, Scans and Findings. Everything is scoped to a workspace
  that belongs to an org the caller is a member of.
- **Auth & RBAC** — JWT access/refresh tokens (HS256), bcrypt password hashing,
  optional **TOTP MFA**, and org-scoped API keys. Four roles: `owner` > `admin`
  > `analyst` > `viewer`.
- **Live streaming output** — watch each tool run line-by-line over WebSockets.
- **Vulnerability scanning** — `nuclei` (CVE / misconfig / exposure templates)
  and `httpx` HTTP probing, with severity-ranked findings.
- **Persistence** — SQLite by default, Postgres in production (SQLAlchemy 2.0 +
  Alembic). Every scan and finding survives restarts.
- **Findings management** — normalized, severity-graded findings with CVE/CWE/
  CVSS and a triage status (`open` / `triaged` / `false_positive` / `resolved`).
- **Asset ownership verification** — register a domain/IP, publish a DNS TXT
  record (`_reconx-verify.<domain>`), and verify ownership (Phase-1 scaffolding).
- **Professional reports** — one-click client-ready HTML report (print → PDF)
  per workspace, with executive summary, risk rating, findings and scan activity.
- **Scope enforcement** — out-of-scope targets are refused (domains, wildcards,
  IPs, CIDR ranges), on both REST and WebSocket paths.
- **Safety** — shared concurrent-scan cap across REST + WebSocket, audit logging,
  stop/cancel any running scan.

### Scanner modules

| Module            | Tool / source        | Target          |
|-------------------|----------------------|-----------------|
| Subdomain Enum    | `subfinder`          | domain          |
| Port Scan         | `nmap` (6 profiles)  | host / IP       |
| HTTP Probe        | `httpx`              | host(s) / URL(s)|
| Vuln Scan         | `nuclei`             | target(s)       |
| Content Discovery | `ffuf` + SecLists    | URL             |
| Tech Detect       | `builtwith` + HTTP   | URL             |
| WHOIS             | `python-whois`       | domain          |
| Reverse IP        | hackertarget.com API | IP / host       |

See **[ARCHITECTURE.md](ARCHITECTURE.md)** for the tenancy, auth and data models,
and **[deploy/README.md](deploy/README.md)** for containerized and self-hosted
(Helm) deployment.

---

## Requirements

- **Python 3.11+** and **Node.js 18+**
- **Go** (to install the ProjectDiscovery tools below)
- CLI tools on your `PATH`:
  - [`nmap`](https://nmap.org), [`ffuf`](https://github.com/ffuf/ffuf)
  - [`subfinder`](https://github.com/projectdiscovery/subfinder),
    [`httpx`](https://github.com/projectdiscovery/httpx),
    [`nuclei`](https://github.com/projectdiscovery/nuclei)

Install the ProjectDiscovery suite:

```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
nuclei -update-templates   # one-time: downloads ~10k detection templates
```

> Optional in production only: **Postgres** and **Redis**. Neither is needed for
> local development — RECON-X falls back to SQLite and in-process scans.

---

## Quickstart

### Option A — Local dev (SQLite, no external services)

**1. Backend (API + scan engine + database)**

```bash
cd backend
pip install -r requirements.txt        # add -r requirements-dev.txt for tests/lint
python run.py
```

API starts on **http://127.0.0.1:8002**
(equivalently `python -m uvicorn app.main:app --port 8002 --reload`).
A SQLite database `backend/reconx.db` is created automatically on startup
(`init_models()` runs `create_all`), so no migration step is required for dev.

**2. Frontend (dashboard)**

```bash
cd frontend
npm install
npm run dev
```

Open the printed URL (default **http://localhost:5173**). Any `localhost` /
`127.0.0.1` port is allowed by CORS automatically. Override the API base with a
`frontend/.env` containing `VITE_API_BASE=http://127.0.0.1:8002` if needed.

**3. Create the first account.** Register through the UI, or via the API:

```bash
curl -X POST http://127.0.0.1:8002/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"email":"you@example.com","password":"changeme123","full_name":"You","org_name":"Acme"}'
```

Registration creates your **User**, a first **Organization** (you become
`owner`), and a **Default Engagement** workspace, then returns tokens.

### Option B — Docker Compose (Postgres + Redis)

```bash
docker compose up --build
```

This brings up the API (with Postgres + Redis wired through env vars), a
background **scan worker** (`arq app.queue.WorkerSettings`, for `queue`-mode
execution), applies Alembic migrations, and serves the built frontend. Set a
strong `JWT_SECRET` and (optionally) the `BOOTSTRAP_ADMIN_*` seed variables
before first boot. See
**[deploy/README.md](deploy/README.md)** for the compose services, the Helm
chart for self-hosting under `deploy/helm/reconx`, and the licensing note.

---

## Auth flow (register → token → Bearer)

RECON-X is a bearer-token API. The flow:

1. **Register** (`POST /auth/register`) or **log in** (`POST /auth/login`,
   with `mfa_code` when MFA is enabled). Both return:

   ```json
   { "access_token": "…", "refresh_token": "…", "token_type": "bearer",
     "user": { … }, "org": { … }, "workspace": { … } }
   ```

2. **Call REST endpoints** with the access token:

   ```
   Authorization: Bearer <access_token>
   ```

3. **Refresh** when the access token expires (default 30 min) via
   `POST /auth/refresh` with `{ "refresh_token": "…" }` → a fresh token pair.

4. **WebSocket** cannot carry custom headers, so `/ws/scan` authenticates via a
   query parameter: `ws://127.0.0.1:8002/ws/scan?token=<access_token>`.

5. **Service-to-service / CI** can use an org **API key** instead of a user
   token: send `X-API-Key: rcx_<prefix>_<secret>` on REST, or
   `?key=rcx_…` on the WebSocket. API keys are created (and shown **once**) via
   `POST /orgs/{org_id}/apikeys`.

Everything is scoped by `workspace_id`, which must belong to an org the caller
is a member of. Role gating: reads require `viewer+`; running scans, creating
assets, and triaging findings require `analyst+`; managing members, API keys and
workspaces requires `admin+`; deleting an org requires `owner`.

---

## Typical workflow

1. **Register / log in**, then open (or create) a **Workspace** and set its
   **scope** (e.g. `acme.com, *.acme.com, 10.0.0.0/24`).
2. Optionally **register assets** and verify ownership via the DNS TXT record.
3. **Subdomain Enum** → copy results into **HTTP Probe** to find live hosts.
4. **Vuln Scan** the live hosts with `nuclei`; **Port Scan** with `nmap`.
5. Watch findings accumulate in the **Findings** tab; triage each one.
6. Click **Report** for a client-ready document (Save as PDF from the browser).

---

## Configuration

All settings are environment variables read by `app/config.py`
(pydantic-settings). Local development needs **none** of them.

| Variable                  | Default                                       | Purpose                                             |
|---------------------------|-----------------------------------------------|-----------------------------------------------------|
| `DATABASE_URL`            | `sqlite:///…/backend/reconx.db`               | SQLAlchemy URL. Prod: `postgresql+psycopg://…`      |
| `REDIS_URL`               | `redis://localhost:6379/0`                    | Queue backend (Phase-2 workers; optional)           |
| `JWT_SECRET`              | `dev-insecure-change-me`                      | Token signing key — **must** be changed in prod     |
| `JWT_ALG`                 | `HS256`                                        | JWT algorithm                                       |
| `ACCESS_TTL_MIN`          | `30`                                           | Access-token lifetime (minutes)                     |
| `REFRESH_TTL_DAYS`        | `14`                                           | Refresh-token lifetime (days)                       |
| `DEBUG`                   | `true`                                         | Dev mode; a warning fires if `JWT_SECRET` is default while `false` |
| `BOOTSTRAP_ADMIN_EMAIL`   | *(empty)*                                      | Seed admin email (only if DB has no users)          |
| `BOOTSTRAP_ADMIN_PASSWORD`| *(empty)*                                      | Seed admin password                                 |
| `BOOTSTRAP_ORG_NAME`      | `RECON-X`                                       | Seed organization name                              |
| `RECONX_WORDLIST`         | `SecLists/Discovery/Web-Content/common.txt`   | ffuf wordlist                                       |
| `RECONX_ORIGINS`          | `http://localhost:5173,http://127.0.0.1:5173` | Extra CORS origins (localhost ports auto-allowed)   |
| `RECONX_MAX_CONCURRENT`   | `4`                                            | Max simultaneous scans (shared REST + WebSocket)    |
| `RECONX_SCAN_TIMEOUT`     | `1800`                                         | Per-scan ceiling (seconds)                          |
| `RECONX_API_KEY`          | *(empty)*                                       | Legacy single static key (back-compat)              |
| `RECONX_EXECUTION_BACKEND` | `inline`                                      | `EXECUTION_BACKEND`: `inline` (in-process) or `queue` (arq + Redis worker) |
| `RECONX_SANDBOX`          | `none`                                          | `SANDBOX_MODE`: `none` or `docker` (hardened ephemeral scanner containers) |
| `RECONX_SCANNER_IMAGE`    | `reconx-scanner:latest`                         | `SCANNER_IMAGE`: image used for sandboxed scanner containers |
| `RECONX_REQUIRE_VERIFIED_ASSET` | `false`                                   | `REQUIRE_VERIFIED_ASSET`: when true, only **verified** assets may be scanned |
| `RECONX_BLOCK_PRIVATE_TARGETS` | `true`                                     | `BLOCK_PRIVATE_TARGETS`: when true, refuse private/loopback targets (cloud metadata always blocked) |
| `ANTHROPIC_API_KEY`       | *(empty)*                                       | Enables AI triage (Phase 4); no key → deterministic heuristic fallback |
| `RECONX_AI_MODEL`         | `claude-opus-4-8`                               | Anthropic model id used for AI triage               |
| `RECONX_AI_EFFORT`        | `medium`                                        | Reasoning effort / token budget for triage calls    |
| `RECONX_SCHEDULER_ENABLED`| `false`                                         | When true, start the continuous-scan cron worker    |
| `RECONX_SMTP_HOST` / `_PORT` / `_USER` / `_PASSWORD` / `_FROM` | *(empty)*         | SMTP settings for the email alert channel           |

> Backward compatibility: the historical `config.PROJECT_ROOT`, `WORDLIST`,
> `ALLOWED_ORIGINS`, `SCAN_TIMEOUT`, `MAX_CONCURRENT_SCANS` and `API_KEY`
> module constants are still exported, so the scanner engine imports unchanged.

### Execution modes & safety

RECON-X runs scans through one execution core with two interchangeable backends,
plus safety controls that apply to both. Everything below defaults **off** —
inline mode is the zero-dependency default (no Redis, no Docker); queue and the
Docker sandbox need the `docker compose` stack.

- **Inline (default)** — `EXECUTION_BACKEND=inline` runs the scanner in-process,
  capped by a shared REST + WebSocket concurrency limit (`RECONX_MAX_CONCURRENT`).
- **Queue** — `EXECUTION_BACKEND=queue` hands the scan to an out-of-process
  **arq worker** over Redis; the worker persists the result and streams live
  output back via **Redis Streams** (so a late-joining WebSocket still replays
  the full log). Requires Redis + arq.
- **Docker sandbox** — `SANDBOX_MODE=docker` runs scanner tools inside ephemeral,
  hardened containers (from `SCANNER_IMAGE`, built by `Dockerfile.worker`) with
  `--rm`, `--read-only` + `--tmpfs /tmp`, `--cap-drop ALL`,
  `--security-opt no-new-privileges`, and memory/CPU/PID caps.
- **SSRF netguard (always on)** — every scan target is checked first and refused
  if it resolves to `localhost`, a private/loopback range, or a cloud-metadata
  endpoint. It resolves hostnames and vets **all** returned IPs (defeating
  DNS-rebinding). `BLOCK_PRIVATE_TARGETS=false` relaxes the private checks for
  deliberate on-prem internal scanning; metadata endpoints stay blocked.
- **Verified-asset gate (opt-in)** — with `REQUIRE_VERIFIED_ASSET=true`, a scan
  is allowed only if every target host matches (or is a subdomain of) a
  **verified** asset in the workspace; denials are audited and return **403**.

See **[ARCHITECTURE.md](ARCHITECTURE.md) §7** for the full design.

---

## API

Send `Authorization: Bearer <access>` (or `X-API-Key: <key>`) on every REST
call except the public liveness endpoints. Unless noted, `viewer+` may read and
`analyst+` may write.

### System / auth

| Method | Path                    | Description                                             |
|--------|-------------------------|---------------------------------------------------------|
| GET    | `/`                     | Service banner (public)                                 |
| GET    | `/health`               | Liveness probe (public)                                 |
| POST   | `/auth/register`        | Create user + org + default workspace; returns tokens   |
| POST   | `/auth/login`           | Log in (optional `mfa_code`); returns tokens            |
| POST   | `/auth/refresh`         | Rotate a refresh token into a new pair                  |
| GET    | `/auth/me`              | Current user + memberships + orgs                       |
| POST   | `/auth/mfa/enroll`      | Generate a TOTP secret + otpauth URI                    |
| POST   | `/auth/mfa/verify`      | Confirm the TOTP code and enable MFA                    |

### Organizations, members & API keys

| Method | Path                                   | Description                              |
|--------|----------------------------------------|------------------------------------------|
| GET    | `/orgs`                                | Orgs the caller belongs to               |
| POST   | `/orgs`                                | Create an org (caller becomes owner)     |
| GET    | `/orgs/{org_id}`                       | Org detail                               |
| GET    | `/orgs/{org_id}/members`               | List members                             |
| POST   | `/orgs/{org_id}/members`               | Add a member by email + role (`admin+`)  |
| PATCH  | `/orgs/{org_id}/members/{user_id}`     | Change a member's role (`admin+`)        |
| DELETE | `/orgs/{org_id}/members/{user_id}`     | Remove a member (`admin+`)               |
| GET    | `/orgs/{org_id}/apikeys`               | List API keys (metadata only)            |
| POST   | `/orgs/{org_id}/apikeys`               | Create a key — full key returned **once** |
| DELETE | `/orgs/{org_id}/apikeys/{key_id}`      | Revoke a key (`admin+`)                  |

### Workspaces & assets

| Method | Path                              | Description                                   |
|--------|-----------------------------------|-----------------------------------------------|
| GET    | `/orgs/{org_id}/workspaces`       | List an org's workspaces (with summaries)     |
| POST   | `/orgs/{org_id}/workspaces`       | Create a workspace (`admin+`)                 |
| GET    | `/workspaces/{ws_id}`             | Workspace detail + scan/finding counts        |
| PUT    | `/workspaces/{ws_id}/scope`       | Replace the workspace scope list (`admin+`)   |
| DELETE | `/workspaces/{ws_id}`             | Delete a workspace + its data (`admin+`)      |
| GET    | `/workspaces/{ws_id}/assets`      | List registered assets                        |
| POST   | `/workspaces/{ws_id}/assets`      | Register an asset → DNS TXT proof (`analyst+`)|
| POST   | `/assets/{asset_id}/verify`       | Resolve TXT record and mark verified          |

### Scanning, findings & report

| Method | Path                              | Description                                        |
|--------|-----------------------------------|----------------------------------------------------|
| GET    | `/tools`                          | Scanner catalogue (drives the UI)                  |
| GET    | `/scan/{tool}`                    | Run a scan synchronously (REST); scope-enforced    |
| WS     | `/ws/scan`                        | Run a scan, stream output + result live            |
| GET    | `/workspaces/{ws_id}/scans`       | Stored scan history (newest first)                 |
| GET    | `/scans/{scan_id}`                | A single stored scan                               |
| GET    | `/workspaces/{ws_id}/findings`    | Normalized findings (critical-first)               |
| PATCH  | `/findings/{finding_id}`          | Update a finding's triage status (`analyst+`)      |
| GET    | `/workspaces/{ws_id}/report`      | Client-ready HTML report                           |

**`GET /scan/{tool}`** query params: `target` (required), `workspace_id`
(defaults to the caller's org default workspace), `scan_type` (nmap profile),
`severity` (nuclei filter).

**WebSocket** — connect to `/ws/scan?token=<access>` (or `?key=<api key>`), then
send `{ "tool", "target", "options", "workspace_id" }`. You receive
`start` → `log`* → `result` → `saved` → `done` (with `error` on failure). Send
`{ "action": "stop" }` to cancel.

### Premium & AI features (Phase 4)

| Method | Path                              | Description                                        |
|--------|-----------------------------------|----------------------------------------------------|
| GET    | `/workspaces/{ws_id}/risk`        | Unified workspace risk score (0–100) + breakdown   |
| GET    | `/workspaces/{ws_id}/diff`        | Scan-to-scan diff: new / resolved / unchanged      |
| POST   | `/triage`                         | AI-triage a finding via Claude (`analyst+`)        |
| GET    | `/workspaces/{ws_id}/schedules`   | List continuous-scan schedules                     |
| POST   | `/workspaces/{ws_id}/schedules`   | Create a cron-scheduled recurring scan (`analyst+`)|
| DELETE | `/schedules/{schedule_id}`        | Remove a schedule (`analyst+`)                     |
| GET    | `/workspaces/{ws_id}/notifications` | List alert channels (Slack / webhook / email)    |
| POST   | `/workspaces/{ws_id}/notifications` | Register an alert channel (`admin+`)             |

- **AI triage** (`/triage`) sends a finding to Anthropic's **`claude-opus-4-8`**
  and returns **structured output** (suggested severity, false-positive flag,
  confidence, rationale, remediation). It is **gated on `ANTHROPIC_API_KEY`** —
  with no key set it falls back to a deterministic heuristic and never errors.
  Tune the model and reasoning budget with `RECONX_AI_MODEL` / `RECONX_AI_EFFORT`.
- **Risk score** (`/risk`) and **diff** (`/diff`) are pure-Python and always
  available; they roll up and compare persisted findings.
- **Schedules** (`/schedules`) run recurring scans on a cron cadence; enable the
  cron worker with `RECONX_SCHEDULER_ENABLED=true` (production scheduling reuses
  the Redis/arq queue worker).
- **Notifications** (`/notifications`) push events (finished scheduled scans, new
  critical findings, risk-threshold crossings) to **Slack**, a **generic
  webhook**, or **email** (SMTP via `RECONX_SMTP_*`).

See **[ARCHITECTURE.md](ARCHITECTURE.md) §8** for the full design and which
features need external services (Anthropic key, Redis, SMTP).

---

## Billing & licensing

RECON-X ships as a **hybrid product**: the same build runs as a hosted SaaS or as
a self-hosted install, selected by `RECONX_BILLING_MODE`. It defaults to `none`,
which disables all quota/feature enforcement — the zero-dependency default and
the test suite behave exactly as before. The two paid modes are:

- **`cloud`** — Stripe subscriptions. The effective plan is read from the org's
  Stripe subscription, kept in sync by a signature-verified webhook.
- **`self_hosted`** — offline, Ed25519-signed **license keys** verified locally
  against an embedded vendor public key. No phone-home is ever required.

### Plans

| Plan      | $/mo | assets | seats | scans/mo | AI  | continuous | integrations | white-label |
|-----------|-----:|:------:|:-----:|:--------:|:---:|:----------:|:------------:|:-----------:|
| `free`    |    0 |   1    |   2   |    20    | no  |     no     |     no       |     no      |
| `starter` |   49 |   3    |   3   |   200    | no  |    yes     |     no       |     no      |
| `pro`     |  299 |  25    |  10   |  2000    | yes |    yes     |    yes       |     no      |
| `mssp`    |  999 |   ∞    |   ∞   |    ∞     | yes |    yes     |    yes       |    yes      |

`∞` = unlimited. When billing is enabled, a scan over the plan's monthly limit is
refused with **402 Payment Required**; the asset and seat quotas gate creation the
same way. The catalog lives in `app/plans.py` and is served at
`GET /billing/plans`.

### Configuration

| Variable                         | Default   | Purpose                                                        |
|----------------------------------|-----------|----------------------------------------------------------------|
| `RECONX_BILLING_MODE`            | `none`    | `none` (inert) / `cloud` (Stripe) / `self_hosted` (license)     |
| `RECONX_STRIPE_SECRET_KEY`       | *(empty)* | Stripe API key; enables the Stripe integration when set        |
| `RECONX_STRIPE_WEBHOOK_SECRET`   | *(empty)* | Signing secret used to verify `POST /billing/webhook`          |
| `RECONX_STRIPE_PRICE_STARTER`    | *(empty)* | Stripe price id mapped to the `starter` plan                   |
| `RECONX_STRIPE_PRICE_PRO`        | *(empty)* | Stripe price id mapped to the `pro` plan                       |
| `RECONX_LICENSE_KEY`             | *(empty)* | Signed license token installed on a self-hosted deployment     |
| `RECONX_LICENSE_PUBLIC_KEY`      | *(empty)* | Overrides the embedded vendor public key for verification      |
| `RECONX_LICENSE_PRIVATE_KEY`     | *(empty)* | Ed25519 issuer key — **vendor side only**, never on a customer install |

Cloud mode needs the optional **`stripe`** dependency; self-hosted license
signing/verification needs **`cryptography`**. Both are imported lazily, so
`BILLING_MODE=none` requires neither.

### Routes

| Method | Path                                | Description                                              |
|--------|-------------------------------------|----------------------------------------------------------|
| GET    | `/billing/plans`                    | Static plan catalog (public)                             |
| GET    | `/orgs/{org_id}/billing`            | Org billing status: mode, effective plan, limits, usage (`viewer+`) |
| POST   | `/orgs/{org_id}/billing/checkout`   | Start a Stripe Checkout session for a plan (`admin+`)    |
| POST   | `/orgs/{org_id}/billing/portal`     | Open the Stripe Billing Portal to manage the plan (`admin+`) |
| POST   | `/billing/webhook`                  | Stripe webhook — syncs the org's subscription (signature-authenticated) |
| GET    | `/orgs/{org_id}/license`            | Active/stored license entitlements (`viewer+`)          |
| POST   | `/orgs/{org_id}/license`            | Verify and install a signed license token (`admin+`)    |

See **[ARCHITECTURE.md](ARCHITECTURE.md) §9** for the full design (effective-plan
resolution, quota enforcement, Stripe glue, and offline license signing).

---

## Enterprise & compliance

Phase 5 makes RECON-X enterprise-deployable: federated **SSO**, HTTP **security
hardening**, **observability**, session/token **revocation**, a compliance-grade
**audit trail** with GDPR export/retention, and MSSP **white-label branding** in
reports. Everything is **flag-gated** and defaults **off**, so the zero-dependency
default build is unchanged.

- **SSO** — OIDC (authorization-code flow) with **JIT provisioning** creates the
  user + org membership on first sign-in; a **SAML** ACS endpoint is scaffolded
  (full assertion signature validation needs the optional **`xmlsec`** native
  dependency, so the SAML path stays inert where `xmlsec` is unavailable — OIDC
  is the recommended default).
- **Hardening** — security headers + a restrictive **CSP**, per-principal/IP
  **rate limiting** (429 over the limit), and per-request **request IDs** carried
  into logs.
- **Observability** — `GET /metrics` (Prometheus), a dependency-aware
  `GET /ready` readiness probe, and structured **JSON logs**.
- **Revocation** — a per-user `token_version` claim; `POST /auth/logout-all`
  bumps it to invalidate every outstanding access/refresh token at once.
- **Audit & GDPR** — a filterable org audit trail, a structured data-subject
  **export**, and a retention sweep driven by `RECONX_DATA_RETENTION_DAYS`.
- **White-label** — per-org branding (name, logo, color, footer) that the report
  generator renders into client-ready reports; an `mssp`-tier (`white_label`)
  feature.

### Configuration

| Variable                        | Default   | Purpose                                                   |
|---------------------------------|-----------|-----------------------------------------------------------|
| `RECONX_SSO_ENABLED`            | `false`   | Enable OIDC/SAML single sign-on + JIT provisioning        |
| `RECONX_OIDC_REDIRECT_BASE`     | *(empty)* | Public base URL used to build the OIDC callback / ACS URIs|
| `RECONX_SECURITY_HEADERS`       | `false`   | Emit hardened security headers + CSP on every response    |
| `RECONX_RATE_LIMIT_ENABLED`     | `false`   | Turn on per-principal/IP rate limiting                    |
| `RECONX_RATE_LIMIT_PER_MINUTE`  | `120`     | Request/minute ceiling when rate limiting is enabled      |
| `RECONX_METRICS_ENABLED`        | `false`   | Expose `GET /metrics` in Prometheus format                |
| `RECONX_JSON_LOGS`              | `false`   | Emit single-line structured JSON logs                     |
| `RECONX_DATA_RETENTION_DAYS`    | `0`       | Prune scans/findings/audit older than N days (`0` = keep) |

### Routes

| Method | Path                          | Description                                                  |
|--------|-------------------------------|-------------------------------------------------------------|
| GET    | `/auth/sso/login`             | Begin OIDC login — redirect to the identity provider        |
| GET    | `/auth/sso/callback`          | OIDC callback: code exchange, JIT provisioning, tokens      |
| POST   | `/auth/sso/saml/acs`          | SAML assertion-consumer-service endpoint (scaffold)         |
| POST   | `/auth/logout-all`            | Bump `token_version` — revoke all of the user's tokens      |
| GET/PUT| `/orgs/{id}/sso`              | Read / update the org's SSO configuration (`admin+`)        |
| GET/PUT| `/orgs/{id}/branding`         | Read / update MSSP white-label branding (`admin+`)          |
| GET    | `/orgs/{id}/audit`            | Filterable org audit trail (`admin+`)                       |
| GET    | `/orgs/{id}/export`           | GDPR data-subject export of the org's data (`admin+`)       |
| GET    | `/metrics`                    | Prometheus metrics (when `RECONX_METRICS_ENABLED`)          |
| GET    | `/ready`                      | Dependency-aware readiness probe (503 until ready)          |

See **[ARCHITECTURE.md](ARCHITECTURE.md) §10** for the full design (SSO flow, JIT
provisioning, hardening middleware, token-version revocation, audit/GDPR tooling,
and white-label branding).

---

## Project structure

```
recon-tool/
├── backend/
│   ├── requirements.txt          # runtime deps
│   ├── requirements-dev.txt      # pytest / httpx / ruff / pytest-asyncio
│   ├── run.py                    # launcher (port 8002)
│   ├── alembic.ini               # migration config (reads DATABASE_URL)
│   ├── migrations/               # Alembic env + versions/0001_initial.py
│   ├── reconx.db                 # SQLite (auto-created in dev)
│   └── app/
│       ├── main.py               # FastAPI app: CORS, lifespan, routers, /health
│       ├── config.py             # pydantic-settings Settings + back-compat consts
│       ├── database.py           # engine, SessionLocal, Base, get_db, init_models
│       ├── models.py             # SQLAlchemy 2.0 ORM (Org, User, Workspace, …)
│       ├── schemas.py            # pydantic v2 request/response models
│       ├── security.py           # passwords, JWT, API keys, TOTP, ROLE_RANK
│       ├── deps.py               # get_current_user, get_principal, RBAC deps
│       ├── crud.py               # tenant-aware DB ops, finding derivation, asset gate
│       ├── execution.py          # shared scan-execution core (inline | queue)
│       ├── worker.py             # arq worker entrypoint (queue mode)
│       ├── queue.py              # arq producer + WorkerSettings re-export
│       ├── streaming.py          # Redis Streams publisher/tailer (live output)
│       ├── sandbox.py            # hardened Docker sandbox for scanner tools
│       ├── netguard.py           # SSRF guard (blocks private/metadata targets)
│       ├── db.py                 # deprecated shim → crud (back-compat)
│       ├── scope.py              # in-scope enforcement (unchanged)
│       ├── report.py             # HTML report generator (unchanged)
│       ├── routers/              # auth, orgs, workspaces, assets, scans, ws
│       └── scanners/             # one streaming module per tool (unchanged)
├── frontend/                     # React dashboard (Vite)
├── deploy/                       # docker-compose notes + Helm chart (self-host)
└── SecLists/                     # vendored wordlists
```

---

## Roadmap

**Phase 2 has shipped**: a shared execution core with an **inline** default and
an optional **queue** backend (arq + Redis worker) streaming output over Redis
Streams, **sandboxed** scanner containers (`Dockerfile.worker`), an always-on
**SSRF netguard**, and an opt-in **verified-asset gate**. See the
[Execution modes & safety](#execution-modes--safety) section and
**[ARCHITECTURE.md](ARCHITECTURE.md) §7**. Next up: cross-process scan
cancellation for queue mode and per-container egress allowlisting for the sandbox.

> **Authorized testing only.** RECON-X is for security professionals testing
> systems they own or are explicitly authorized to assess. You are responsible
> for complying with all applicable laws and the terms of your engagement.

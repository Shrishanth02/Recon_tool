# RECON-X Architecture

RECON-X v4.0.0 turns the original single-user scanning demo into an auth-gated,
multi-tenant service **without changing the scanner engine**. It boots with zero
external services (SQLite + in-process scans) and scales to Postgres + Redis
through environment variables alone.

> **Authorized testing only.** Scope enforcement and asset ownership
> verification exist so that scans only ever run against systems a tenant is
> entitled to test.

---

## 1. Request / scan decoupling

Scanners are Python generators that yield `{"type": "log"|"result"|"error", …}`
events. Two entrypoints drive them, sharing one concurrency guard:

- **Synchronous REST** — `GET /scan/{tool}` (`routers/scans.py`) runs the
  generator to completion, collecting logs + result, then persists the scan and
  derives findings before returning the stored record.
- **Streaming WebSocket** — `WS /ws/scan` (`routers/ws.py`) runs the generator on
  a worker thread whose events are pushed onto an `asyncio.Queue` and relayed to
  the client as `start → log* → result → saved → done`. A concurrent receiver
  task watches for `{"action":"stop"}`, which sets a `threading.Event` the
  scanner honors for cooperative cancellation.

Both paths acquire the **same** `threading.Semaphore(MAX_CONCURRENT_SCANS)`
(`scan_slots`, defined in `routers/scans.py` and imported by `routers/ws.py`), so
the concurrency cap spans REST and WebSocket together. Both enforce the target
against the workspace scope (`scope.check`) and persist through
`crud.save_scan`, which also derives normalized findings.

**Phase 2** factors both entrypoints onto a **single execution abstraction**
(`execution.py`) with two interchangeable backends selected purely by config —
**inline** (the default; runs the scanner in-process exactly as before) and
**queue** (enqueues the job to an out-of-process worker over Redis + arq and
streams its output back via Redis Streams). See §7 for the full design.

---

## 2. Tenancy model — Organization → Workspace → User

```
Organization ──< Membership >── User
     │
     ├──< Workspace ──< Asset
     │        ├──< Scan ──< Finding
     │        └──< Finding
     ├──< ApiKey
     └──< AuditLog
```

- **Organization** — the billing/tenant boundary (`plan`, `license_tier`, unique
  `slug`).
- **User** — a global identity (unique lowercased email, bcrypt `password_hash`,
  optional TOTP secret). A user can belong to **many** orgs.
- **Membership** — links a User to an Organization with a **role**
  (`owner` / `admin` / `analyst` / `viewer`).
- **Workspace** — the engagement/client container inside an org. It **carries the
  scope** (JSON list of domains, wildcards, IPs, CIDRs) and owns the Assets,
  Scans and Findings.
- **Asset** — a domain/IP a workspace claims, plus its ownership-verification
  state (the moat; see §5).
- **ApiKey** — an org-scoped service principal (`rcx_<prefix>_<secret>`; only the
  hash is stored).
- **AuditLog** — append-only record of security-relevant actions.

**Cascade deletes:** deleting an Org removes its Memberships, Workspaces and
ApiKeys; deleting a Workspace removes its Assets, Scans and Findings; deleting a
Scan removes its Findings.

Every request resolves a `workspace_id` and checks that it belongs to an org the
caller is a member of (`deps.get_workspace_for_user`). Nonexistent-or-invisible
workspaces return **404** (existence hiding); an authenticated member lacking the
required role gets **403**.

---

## 3. Auth model

**Principals.** A request is authenticated as one of two principal kinds
(`deps.get_principal`):

- **User (JWT)** — `Authorization: Bearer <access>` on REST, or `?token=` on the
  WebSocket. Tokens are HS256 JWTs (PyJWT) with `sub`, optional `org_id`, a
  `type` of `access` or `refresh`, and an expiry. Access tokens default to 30
  min, refresh tokens to 14 days; `POST /auth/refresh` rotates a refresh token
  into a fresh pair.
- **API key (service principal)** — `X-API-Key: rcx_…` on REST, or `?key=` on the
  WebSocket. Resolves to an org rather than a user; `last_used_at` is bumped on
  use.

**Passwords & MFA.** Passwords are hashed with passlib/bcrypt. Optional TOTP MFA
(pyotp): `/auth/mfa/enroll` issues a secret + otpauth URI, `/auth/mfa/verify`
confirms possession and switches MFA on; thereafter login requires `mfa_code`.

**RBAC.** Roles are ranked in `security.ROLE_RANK`:

| Role      | Rank | Can…                                                        |
|-----------|:----:|-------------------------------------------------------------|
| `owner`   |  3   | everything, including org deletion                          |
| `admin`   |  2   | manage members, API keys, and workspaces                    |
| `analyst` |  1   | run scans, register/verify assets, triage findings          |
| `viewer`  |  0   | read-only                                                   |

Reads require `viewer+`; scan/asset/finding writes require `analyst+`;
member/key/workspace management requires `admin+`; org deletion requires
`owner`. `deps.require_role(min_role)` and the per-route checks enforce this.

---

## 4. Data model summary

SQLAlchemy 2.0 (`Mapped`) models in `app/models.py`, Integer autoincrement PKs,
`DateTime(timezone=True)` timestamps (exposed as ISO strings in schemas), JSON
columns for lists/dicts, enums validated as plain strings in the pydantic
schemas.

| Model          | Key fields                                                                 |
|----------------|----------------------------------------------------------------------------|
| `Organization` | `name`, `slug` (unique), `plan`, `license_tier`, `created_at`              |
| `User`         | `email` (unique, lower), `password_hash`, `full_name`, `is_active`, `mfa_secret`, `mfa_enabled` |
| `Membership`   | `user_id`, `org_id`, `role`                                                |
| `Workspace`    | `org_id`, `name`, `slug`, `description`, `scope` (JSON list)               |
| `ApiKey`       | `org_id`, `name`, `prefix`, `key_hash`, `created_by`, `last_used_at`, `revoked` |
| `Asset`        | `workspace_id`, `value`, `atype`, `verified`, `verification_method`, `verification_token`, `verified_at` |
| `Scan`         | `workspace_id`, `created_by`, `tool`, `target`, `status`, `options`, `logs`, `result`, `error`, `started_at`, `finished_at`, `duration` |
| `Finding`      | `scan_id`, `workspace_id`, `source`, `severity`, `name`, `location`, `description`, `cve`, `cwe`, `cvss`, `status` |
| `AuditLog`     | `org_id?`, `user_id?`, `action`, `detail`, `created_at`                    |

Persistence layers:

- `database.py` — the engine (`check_same_thread=False` only for SQLite),
  `SessionLocal`, `Base`, the `get_db` FastAPI dependency, and `init_models()`
  (`create_all`) for dev bootstrap.
- **Alembic** (`alembic.ini`, `migrations/env.py` reading `settings.DATABASE_URL`,
  `versions/0001_initial.py`) is the source of truth for production schema. The
  app also `create_all()`s on startup so it runs even without migrations.
- `crud.py` — all tenant-aware operations, including `save_scan` and
  `derive_findings` (nuclei / nmap / dirbuster derivation ported verbatim from
  the original `db.py`, now writing `Finding` rows with `workspace_id` and
  `status="open"`). The old `db.py` is a thin deprecation shim re-exporting
  `derive_findings` / `save_scan` / `init_db`.

---

## 5. Asset ownership verification (the moat)

Before a tenant should be trusted to scan a target, they prove they own it.
`routers/assets.py` implements the flow:

1. `POST /workspaces/{ws_id}/assets` registers a domain/IP and returns a
   verification **token** plus instructions to publish a DNS TXT record at
   `_reconx-verify.<domain>`.
2. `POST /assets/{asset_id}/verify` resolves that TXT record (via `dnspython`
   when available; best-effort otherwise) and, on a token match, sets
   `verified = True`.

The registration/verification flow is complete and audited; the DNS check is
best-effort (`dnspython` when available). **Phase 2** promotes verification to a
hard, opt-in **verified-asset gate** on scanning — see §7. With
`REQUIRE_VERIFIED_ASSET` enabled, `crud.is_target_authorized` requires every host
in a scan target to exactly match, or be a subdomain of, a **verified** asset in
the workspace before the scan is allowed; a denied scan is audited as
`asset-denied` and returns **403**. The gate defaults **off**, so Phase 0/1
behavior is unchanged unless an operator turns it on.

---

## 6. Configuration & startup

`app/config.py` exposes a pydantic-settings `settings` singleton plus
backward-compatible module constants (`PROJECT_ROOT`, `WORDLIST`,
`ALLOWED_ORIGINS`, `SCAN_TIMEOUT`, `MAX_CONCURRENT_SCANS`, `API_KEY`) so the
scanner engine's `from .. import config` imports keep working. A default
`JWT_SECRET` in a non-`DEBUG` environment logs a warning.

`app/main.py` builds the FastAPI app (`title="RECON-X"`, `version="4.0.0"`),
configures CORS (explicit origins + a `localhost`/`127.0.0.1` regex), and on
startup calls `init_models()` and an optional bootstrap seed (creates the
`BOOTSTRAP_ADMIN` user + org + default workspace when configured and the DB has
no users). `GET /` and `GET /health` are unauthenticated liveness endpoints.

---

## 7. Phase 2 — execution backends, sandboxing & safety gates

Phase 2 shipped as a set of **additive, flag-gated** modules. Every new
capability defaults **off**, so the verified Phase 0/1 flow — SQLite, in-process
scans, no Redis, no Docker — is the zero-dependency default and runs byte-for-byte
as before. Queue mode and the Docker sandbox are opt-in and require
`docker compose` (Redis, and a scanner image).

### 7.1 The execution abstraction

`execution.py` is the single scan-execution core both entrypoints now share. The
REST router calls `run_to_completion()` (synchronous drain-and-persist) and the
WebSocket router calls `stream()` (async event generator); each dispatches to one
of two backends based on `settings.EXECUTION_BACKEND`:

- **`inline` (default)** — reproduces the original behavior exactly: a threaded
  scanner generator bridged onto an `asyncio.Queue` for the WebSocket, or a
  straight synchronous drain for REST. Concurrency is capped by the shared
  `scan_slots = threading.Semaphore(MAX_CONCURRENT_SCANS)` that lives here now
  (both routers import it), so the cap still spans REST + WebSocket together.
- **`queue`** — enqueues the job (`queue.enqueue_scan`) onto **arq**'s Redis
  queue and forwards the worker's live events. Requires Redis + arq.

A `Job` dataclass carries the tool/target/options/workspace plus a
`threading.Event` cancel handle (set by the WebSocket router on
`{"action":"stop"}` for inline runs). Persistence stays out of this module: the
caller passes a DB-backed `on_persist` closure, keeping `execution.py` free of any
session/ORM coupling.

### 7.2 The worker process (queue mode)

`worker.py` is the out-of-process arq entrypoint, run with
`arq app.worker.WorkerSettings` (also re-exported as `app.queue.WorkerSettings`).
It drives the scanner generator, publishes each event onto the job's Redis
**stream**, persists the finished scan through a **fresh** `SessionLocal`
(`crud.save_scan` + audit + commit), then emits a `saved` event and a terminal
stream marker. All Redis/arq imports are lazy and guarded, so `import app.worker`
(and therefore `import app.main`) succeeds on a machine with neither installed.

`streaming.py` is the transport: **Redis Streams** (`XADD`/`XREAD BLOCK`), not
pub/sub. Streams *persist* their entries, so a WebSocket that attaches a few
hundred milliseconds after the worker starts replays the full backlog from
`0-0` rather than missing the opening lines. `SyncPublisher` writes from the
worker thread and, on close, appends the terminal marker and sets a
`STREAM_TTL_SECONDS` TTL; `tail()` is the async consumer, guarded by an overall
`SCAN_TIMEOUT` wall-clock deadline so an orphaned stream never blocks forever.

### 7.3 Sandboxed container workers

`sandbox.py` provides the seam for running scanner tools inside **ephemeral,
hardened Docker containers** instead of directly on the host. When
`SANDBOX_MODE="docker"`, `maybe_wrap()` wraps a scanner command in a
`docker run` against `SCANNER_IMAGE` (built from `Dockerfile.worker`, which
bundles `nmap`/`nuclei`/`httpx`/`ffuf`/`subfinder`) with hardening flags:

- `--rm` — the container is destroyed the instant the tool exits.
- `--network bridge` — outbound access for recon, but off the host netns.
- `--memory 512m` / `--cpus 1` / `--pids-limit 256` — resource caps so one scan
  can't starve the host.
- `--read-only` + `--tmpfs /tmp` — immutable root FS with only a scratch `/tmp`.
- `--cap-drop ALL` + `--security-opt no-new-privileges` — no Linux capabilities,
  no privilege escalation.

At its `SANDBOX_MODE="none"` default `maybe_wrap()` is a no-op, preserving inline
behavior. (A per-container egress allowlist is an operational TODO; the
hardening flags and ephemerality are real today.)

### 7.4 SSRF netguard

`netguard.py` is a dependency-light (stdlib-only) choke point that both execution
entrypoints run **first**, before any packet leaves the box. It refuses targets
that resolve to `localhost`, private/RFC-1918/loopback/link-local/reserved ranges,
or cloud-metadata endpoints (`169.254.169.254`, `fd00:ec2::254`) — defeating the
service being used as an SSRF primitive. It is **DNS-aware**: a hostname is
resolved via `getaddrinfo` and *every* returned address is vetted, which defeats
DNS-rebinding tricks. `BLOCK_PRIVATE_TARGETS=false` relaxes the private/loopback
checks for on-prem installs that deliberately scan internal ranges, but
unresolvable hosts and cloud-metadata IPs are **always** rejected.

### 7.5 Verified-asset authorization gate

`crud.is_target_authorized` (invoked from `routers/scans.py`, and applicable on
both paths) enforces asset ownership as a hard precondition when
`REQUIRE_VERIFIED_ASSET=true`: every host in a scan target must exactly match, or
be a subdomain of, a **verified** `Asset` in the workspace. A denied scan is
audited as `asset-denied` and returns **403**. It defaults **off** (a no-op), so
this is opt-in on top of the always-on scope check (§2) and netguard (§7.4).

### 7.6 New environment flags

| Flag (env alias)                         | Default              | Effect                                                     |
|------------------------------------------|----------------------|------------------------------------------------------------|
| `RECONX_EXECUTION_BACKEND`               | `inline`             | `inline` (in-process) or `queue` (arq + Redis worker)      |
| `RECONX_SANDBOX`                         | `none`               | `none` or `docker` (hardened ephemeral scanner containers) |
| `RECONX_SCANNER_IMAGE`                   | `reconx-scanner:latest` | Image used for sandboxed scanner containers             |
| `RECONX_REQUIRE_VERIFIED_ASSET`          | `false`              | When true, only verified assets may be scanned             |
| `RECONX_BLOCK_PRIVATE_TARGETS`           | `true`               | When true, refuse private/loopback targets (metadata always blocked) |
| `RECONX_STREAM_TTL_SECONDS`              | `900`                | TTL for a job's Redis output stream (queue mode)           |

`settings.use_queue` and `settings.use_docker_sandbox` are the derived
properties the code branches on. `inline` mode needs none of these; `queue` and
`docker` sandbox modes require the `docker compose` stack (Redis + a built
scanner image + the worker service).

---

## 8. Phase 4 — AI triage, risk scoring, diffing, schedules & alerting

Phase 4 layers a **premium/analytics tier** on top of the scanner core. Like
Phase 2, every capability is **additive and flag-gated**: with no API key, no
Redis, and no SMTP configured, RECON-X behaves exactly as in Phase 0/1 — the AI
paths degrade to deterministic fallbacks and the scheduler/alerting stay dormant.
None of these features change how a scan is executed; they consume the findings a
scan already produces.

### 8.1 AI triage via the Anthropic Claude SDK

`ai.py` wraps the official **Anthropic Claude SDK** to enrich and triage
findings. `POST /triage` sends a finding (or a batch) to model **`claude-opus-4-8`**
and requests **structured output** — a JSON schema (or tool-use) response with a
fixed shape (`suggested_severity`, `is_false_positive`, `confidence`, `rationale`,
`remediation`, `references`) — so callers get typed fields, never free-form prose
to parse.

- **Gated on `ANTHROPIC_API_KEY`.** The client is constructed lazily; the key is
  read from the environment (`ANTHROPIC_API_KEY`) and never persisted.
- **Model/effort are configurable** via `RECONX_AI_MODEL` (default
  `claude-opus-4-8`) and `RECONX_AI_EFFORT` (reasoning effort / budget), so an
  operator can trade cost against depth without a code change.
- **Graceful no-key fallback.** When `ANTHROPIC_API_KEY` is unset (or the SDK
  isn't installed), `triage` returns a **heuristic** result derived from the
  existing severity/CVSS/source signals and marks it `ai_enabled=false`. No route
  errors, and the deterministic Phase 0/1 findings pipeline is untouched.
- **External dependency:** the Anthropic API (network + a paid key). This is the
  only Phase 4 feature that calls out to a third party.

### 8.2 Unified risk score

`risk.py` computes a single **workspace risk score** (0–100, banded
critical/high/medium/low) by rolling up findings with severity/CVSS weighting,
exposure counts, and (when available) AI confidence. `GET /risk` returns the
current score plus its component breakdown, giving the dashboard and reports one
comparable number per workspace. It is pure-Python and always available — it
reads persisted findings, so it needs no external service.

### 8.3 Scan-to-scan diff engine

`diff.py` compares two scans (or a scan against the workspace's prior baseline)
and classifies each finding as **new**, **resolved**, or **unchanged** using a
stable finding identity (source + name + location + CVE). `GET /diff` powers
"what changed since last scan" views and feeds the alerting channels (§8.5). Like
the risk score it is deterministic and dependency-free.

### 8.4 Continuous-scan schedules

`scheduler.py` adds **recurring scans** on a cron cadence. A schedule binds a
tool + target + options to a **cron expression** and a workspace; a background
**worker** wakes on each tick, enforces the same scope + netguard + verified-asset
gates as an interactive scan, runs it through the shared execution core (§7.1),
and records the result (optionally diffing against the previous run and firing
alerts). `GET/POST/DELETE /schedules` manage them.

- **Gated on `RECONX_SCHEDULER_ENABLED`** (default off). When disabled, the cron
  loop never starts and the routes still allow CRUD but nothing fires.
- **External dependency:** the continuous-scan worker reuses the Phase 2 queue
  path, so production scheduling expects **Redis** (arq) + the worker process.

### 8.5 Alerting & notification channels

`notifications.py` delivers events — a completed scheduled scan, a new
critical/high finding in a diff, or a risk-score threshold crossing — to one or
more channels. `GET/POST /notifications` register and list channel configs:

- **Slack** — incoming-webhook POST (no scopes; just a webhook URL).
- **Generic webhook** — signed JSON POST to an arbitrary endpoint.
- **Email** — SMTP, configured via `RECONX_SMTP_*` (host, port, user, password,
  from). Disabled until SMTP is set.

Each channel is opt-in per workspace and best-effort (a failing channel is logged
and audited, never blocking a scan). **External dependencies:** a Slack webhook
URL and/or a reachable SMTP server; the generic webhook needs only network egress.

### 8.6 New environment flags

| Flag                          | Default          | Effect                                                        |
|-------------------------------|------------------|---------------------------------------------------------------|
| `ANTHROPIC_API_KEY`           | *(empty)*        | Enables AI triage (§8.1); no key → heuristic fallback         |
| `RECONX_AI_MODEL`             | `claude-opus-4-8`| Anthropic model id used for triage                            |
| `RECONX_AI_EFFORT`            | `medium`         | Reasoning effort / token budget for triage calls              |
| `RECONX_SCHEDULER_ENABLED`    | `false`          | When true, start the continuous-scan cron worker (§8.4)       |
| `RECONX_SMTP_HOST` / `_PORT` / `_USER` / `_PASSWORD` / `_FROM` | *(empty)* | SMTP settings for the email alert channel (§8.5) |

**What needs external services:** AI triage needs an **Anthropic API key**;
continuous schedules (in production) and queue-mode scans need **Redis**; the
email channel needs an **SMTP server**. Everything else in Phase 4 (risk score,
diff, Slack/generic webhooks) is pure-Python and runs in the zero-dependency
default build.

---

## 9. Phase 3 — Monetization & Licensing

Phase 3 adds an entitlement layer that decides **what an org is allowed to do**
without touching how a scan runs. Like every earlier phase it is **additive and
flag-gated**: the master switch is `RECONX_BILLING_MODE`, which defaults to
`none`. In `none` mode every quota and feature check short-circuits to
"allowed / unlimited", so the existing inline scanning and auth flows — and the
whole test suite, which never sets a billing mode — behave byte-for-byte as
before.

Two productization models sit behind one internal API (`app/billing.py`), chosen
by `BILLING_MODE`:

- **`cloud`** — hosted SaaS. The effective plan is read from the org's active
  **Stripe** subscription, which is kept in sync by a signature-verified webhook.
- **`self_hosted`** — offline, air-gapped installs. The effective plan comes from
  an **Ed25519-signed license key** verified locally against an embedded vendor
  public key. **No phone-home, no network** is ever required to validate it.

### 9.1 Plan catalog

`plans.py` is a **pure, stdlib-only** catalog (no DB, no network, always
import-safe) that both billing modes map onto. It declares four tiers and their
concrete limits; a limit of `None` means **unlimited** and feature limits are
booleans. Entitlement decisions never need an external service because the
catalog is duplicated here rather than derived from Stripe or a license.

| Plan      | $/mo | assets | seats | scans/mo | ai  | continuous | integrations | white-label |
|-----------|-----:|:------:|:-----:|:--------:|:---:|:----------:|:------------:|:-----------:|
| `free`    |    0 |   1    |   2   |    20    | no  |     no     |     no       |     no      |
| `starter` |   49 |   3    |   3   |   200    | no  |    yes     |     no       |     no      |
| `pro`     |  299 |  25    |  10   |  2000    | yes |    yes     |    yes       |     no      |
| `mssp`    |  999 |   ∞    |   ∞   |    ∞     | yes |    yes     |    yes       |    yes      |

`plan_limits()` and `feature_enabled()` are the read helpers; both fall back to
`free` for any unknown/empty plan id. Numeric quota keys are `assets`, `seats`,
`scans_per_month`; boolean feature keys are `ai`, `continuous`, `integrations`,
`white_label`.

### 9.2 Effective plan, limits & quota enforcement

`billing.py` is the single decision point. `effective_plan()` resolves the
governing plan per mode:

- `self_hosted` → the `tier` of a valid, unexpired license (else `free`), and a
  license may **override** the base plan's numeric quotas and feature list via
  `current_limits()`.
- `cloud` → the plan of the org's `Subscription` when its status is
  `active`/`trialing`, else the org's stored `plan` (or `free`).
- `none` → the org's stored `plan`, but callers gate on `settings.billing_enabled`
  first, so nothing is enforced.

Usage is counted from persisted data (`crud.count_org_scans_this_month`,
`count_org_assets`, `count_org_seats`). `check_quota(db, org, resource)` compares
current usage against the effective-plan limit for `resource ∈ {scan, asset,
seat}` and returns `(allowed, reason)`; a `None` limit is unlimited. The scan
entrypoint (`routers/scans.py`) calls it **before** running, audits a
`quota-denied` event, and refuses an over-limit scan with **402 Payment
Required**. When billing is off `check_quota` returns `(True, "billing
disabled")`, so the gate is inert. `feature_allowed()` gates boolean features
the same way (honoring license overrides in self-hosted mode).

### 9.3 Cloud mode — Stripe

Stripe is imported **lazily** and every Stripe entry point returns an
`{"error": ...}` dict rather than raising, so the module is safe when `stripe`
is absent or unconfigured (no API key). The flow:

- **Checkout** — `create_checkout_session()` ensures a Stripe `Customer` (id
  persisted on the org's `Subscription` row), then creates a `mode="subscription"`
  Checkout session for the plan's configured price id (`starter`/`pro`).
- **Portal** — `create_portal_session()` opens the Stripe Billing Portal so an
  admin can manage or cancel the plan.
- **Webhook** — `handle_webhook()` verifies the `Stripe-Signature` against
  `STRIPE_WEBHOOK_SECRET` and, on `checkout.session.completed` and
  `customer.subscription.updated|deleted`, **upserts the org's `Subscription`**
  (plan, status, customer/subscription id, current period end). It opens its own
  short-lived session, never raises, and maps everything back to our `org_id` via
  Stripe metadata (falling back to the customer id). The webhook is the single
  source of truth that keeps the local `Subscription` synced with Stripe.

### 9.4 Self-hosted mode — offline signed licenses

`licensing.py` issues and verifies **offline** entitlement grants. A token is
`base64url(json_payload) + "." + base64url(ed25519_signature)`; the JSON payload
carries `tier`, optional `org` binding, quota overrides (`assets`/`seats`/
`scans`, `null` = unlimited), an enabled-`features` list, `iat`/`exp`/`jti`.

- **Vendor side** — `generate_keypair()` and `issue_license()` sign a token with
  an Ed25519 private key (`LICENSE_PRIVATE_KEY`; these helpers raise if
  `cryptography` is missing, since that is a build-tooling error on the issuer).
- **Customer side** — `verify_license()` / `load_active_license()` structurally
  parse the token, check the Ed25519 signature against the **resolved public
  key** (explicit arg > `LICENSE_PUBLIC_KEY` > the embedded development
  `DEFAULT_PUBLIC_PEM`), and reject expired tokens. `cryptography` is imported
  **lazily** and any missing dependency or malformed input degrades to a
  `(False, reason)` / `None` result — `import app.licensing` always succeeds.

The embedded public key lets verification work out of the box; a production build
overrides it with `RECONX_LICENSE_PUBLIC_KEY`. Verification is entirely local, so
an air-gapped install never contacts the vendor.

### 9.5 Routes & schema

`routers/billing.py` surfaces the core over HTTP and is safe in every mode:
`GET /billing/plans` is public pure-data; per-org status/checkout/portal/license
routes are tenant-scoped by the usual `require_role` gate (reads `viewer+`,
state changes `admin+`); `POST /billing/webhook` is unauthenticated at the HTTP
layer but authenticated by Stripe signature inside the core. New persistence:
a `Subscription` row per org (Stripe customer/subscription id, plan, status,
period end) and a `License` row (tier, entitlements JSON, expiry, revoked).

### 9.6 New environment flags & dependencies

| Flag (env alias)                     | Default | Effect                                                     |
|--------------------------------------|---------|------------------------------------------------------------|
| `RECONX_BILLING_MODE`                | `none`  | `none` (inert) / `cloud` (Stripe) / `self_hosted` (license) |
| `RECONX_STRIPE_SECRET_KEY`           | *(empty)* | Stripe API key; enables the Stripe integration when set  |
| `RECONX_STRIPE_WEBHOOK_SECRET`       | *(empty)* | Signing secret for `POST /billing/webhook` verification  |
| `RECONX_STRIPE_PRICE_STARTER`        | *(empty)* | Stripe price id mapped to the `starter` plan             |
| `RECONX_STRIPE_PRICE_PRO`            | *(empty)* | Stripe price id mapped to the `pro` plan                 |
| `RECONX_BILLING_SUCCESS_URL` / `_CANCEL_URL` | `…/billing` | Checkout/portal redirect targets                |
| `RECONX_LICENSE_KEY`                 | *(empty)* | Signed license token installed on a self-hosted deployment |
| `RECONX_LICENSE_PUBLIC_KEY`          | *(empty)* | Overrides the embedded vendor public key for verification |
| `RECONX_LICENSE_PRIVATE_KEY`         | *(empty)* | Ed25519 issuer key — **vendor side only**, never on a customer install |

`settings.billing_enabled` (`BILLING_MODE != "none"`) and `settings.stripe_enabled`
(an API key is set) are the derived properties the code branches on. New optional
dependencies: **`stripe`** (cloud mode) and **`cryptography`** (self-hosted
license signing/verification) — both imported lazily, so the zero-dependency
default build (`BILLING_MODE=none`) needs neither.

---

## 10. Phase 5 — Enterprise & Compliance

Phase 5 makes RECON-X deployable inside an enterprise: federated sign-in, HTTP
security hardening, first-class observability, session/token revocation, a
compliance-grade audit trail with GDPR data-subject tooling, and MSSP
white-label branding that flows through to client reports. Consistent with every
earlier phase, all of it is **additive and flag-gated** — each capability
defaults **off** (or, for the audit trail, transparently extends the existing
`AuditLog`), so the zero-dependency default build and the full test suite behave
exactly as before.

### 10.1 SSO — OIDC & SAML

`sso.py` adds an **enterprise single sign-on** framework that provisions users
into an org without a password, gated by `RECONX_SSO_ENABLED` (default off).

- **OIDC (authorization-code flow)** — the primary, fully-wired path.
  `/auth/sso/login` redirects to the identity provider's authorize endpoint;
  `/auth/sso/callback` exchanges the code for tokens, validates the ID token, and
  resolves the user by verified email. Redirect URIs are built from
  `RECONX_OIDC_REDIRECT_BASE` so the callback URL is stable behind a proxy.
- **JIT provisioning** — on first successful SSO login the user (and their
  org **Membership** at a configured default role) is **just-in-time
  provisioned**: no pre-created account is required, and an existing user is
  matched by email and linked rather than duplicated.
- **SAML (ACS scaffold)** — a `/auth/sso/saml/acs` assertion-consumer-service
  endpoint is scaffolded for SAML 2.0 IdPs. **Caveat:** full assertion
  signature validation depends on **`xmlsec`** (and its native `libxml2`/
  `xmlsec1` libraries), which is an optional, environment-sensitive dependency;
  where `xmlsec` is unavailable the ACS path stays inert rather than accepting
  unverified assertions. OIDC is the recommended, dependency-light default.

Per-org SSO configuration (issuer, client id/secret, default role, enabled
protocol) is stored and managed via `GET/PUT /orgs/{id}/sso` (`admin+`).

### 10.2 Security hardening

`middleware.py` adds defense-in-depth HTTP middleware, gated by
`RECONX_SECURITY_HEADERS` and `RECONX_RATE_LIMIT_ENABLED`:

- **Security headers / CSP** — when `SECURITY_HEADERS` is on, every response
  carries a hardened header set: a restrictive **Content-Security-Policy**,
  `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
  `Referrer-Policy`, and (behind TLS) `Strict-Transport-Security`.
- **Rate limiting** — `RATE_LIMIT_ENABLED` turns on a per-principal/IP limiter
  capped at `RECONX_RATE_LIMIT_PER_MINUTE` requests/minute; an exceeded bucket
  returns **429 Too Many Requests**. It is in-process by default and can share
  the Redis backend when present.
- **Request IDs** — every request is tagged with a correlation **request id**
  (accepted from an inbound `X-Request-ID` or generated), echoed on the response
  and attached to structured log lines so a request can be traced end-to-end.

### 10.3 Observability

`observability.py` exposes operational signals gated by `RECONX_METRICS_ENABLED`
and `RECONX_JSON_LOGS`:

- **Prometheus metrics** — `GET /metrics` publishes request counts/latencies,
  in-flight scans, and scan outcomes in Prometheus text format when
  `METRICS_ENABLED` is set (otherwise the route is absent).
- **Readiness** — `GET /ready` is a dependency-aware readiness probe (DB, and
  Redis when configured), distinct from the always-public liveness `GET /health`;
  it returns **503** until dependencies are reachable.
- **Structured logging** — `JSON_LOGS=true` switches logging to single-line JSON
  records (including the request id from §10.2), suitable for shipping to a log
  aggregator; unset, human-readable console logging is preserved.

### 10.4 Session & token revocation

Access/refresh JWTs were previously valid until expiry with no server-side kill
switch. Phase 5 adds a **`token_version`** integer on the `User`: it is embedded
as a claim at issue time and re-checked on every authenticated request. Bumping a
user's `token_version` **immediately invalidates all outstanding tokens** for
that user. `POST /auth/logout-all` performs that bump, giving users and admins a
"sign out everywhere" / compromise-response control. Verification stays stateless
(no per-token denylist) — a single integer comparison against the persisted user
record.

### 10.5 Audit trail, GDPR export & retention

Phase 5 promotes the existing append-only `AuditLog` into a **compliance
surface**:

- **Audit trail** — `GET /orgs/{id}/audit` (`admin+`) exposes the org's
  security-relevant events (logins, SSO provisioning, role changes, scan
  denials, billing changes, data exports) with filtering and pagination.
- **GDPR data export** — `GET /orgs/{id}/export` (`admin+`) produces a
  structured **data-subject export** of the org's users, workspaces, assets,
  scans and findings for portability / access-request obligations. The export
  action is itself audited.
- **Retention** — `RECONX_DATA_RETENTION_DAYS` (default off / `0` = keep
  forever) drives a retention sweep that prunes scans, findings and audit
  records older than the window, so operators can honor data-minimization
  policies without manual cleanup.

### 10.6 MSSP white-label branding

`branding.py` lets an **MSSP** org present RECON-X and its deliverables under its
own brand. `GET/PUT /orgs/{id}/branding` (`admin+`) stores per-org branding
(product/company name, logo, primary color, report footer). The
`report.py` generator reads the org branding so a **client-ready report** renders
with the MSSP's name, logo and colors instead of the RECON-X defaults. Branding
is a `white_label` plan feature (the `mssp` tier, §9.1); on plans without it the
setter is gated and reports fall back to default branding.

### 10.7 New environment flags

| Flag                          | Default   | Effect                                                          |
|-------------------------------|-----------|-----------------------------------------------------------------|
| `RECONX_SSO_ENABLED`          | `false`   | Enable OIDC/SAML single sign-on + JIT provisioning (§10.1)      |
| `RECONX_OIDC_REDIRECT_BASE`   | *(empty)* | Public base URL used to build the OIDC callback / ACS URIs      |
| `RECONX_SECURITY_HEADERS`     | `false`   | Emit hardened security headers + CSP on every response (§10.2)  |
| `RECONX_RATE_LIMIT_ENABLED`   | `false`   | Turn on per-principal/IP rate limiting (§10.2)                  |
| `RECONX_RATE_LIMIT_PER_MINUTE`| `120`     | Request/minute ceiling when rate limiting is enabled            |
| `RECONX_METRICS_ENABLED`      | `false`   | Expose `GET /metrics` in Prometheus format (§10.3)              |
| `RECONX_JSON_LOGS`            | `false`   | Emit single-line structured JSON logs (§10.3)                   |
| `RECONX_DATA_RETENTION_DAYS`  | `0`       | Prune scans/findings/audit older than N days (`0` = keep) (§10.5) |

Every flag defaults to the inert value, so a default deployment is byte-for-byte
the Phase 0/1 build. SSO with SAML is the only feature with an environment-
sensitive optional dependency (**`xmlsec`**, §10.1); OIDC, hardening,
observability, revocation, audit/GDPR and branding are stdlib- or
already-vendored and always import-safe.

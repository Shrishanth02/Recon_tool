// API endpoints + auth wiring for the RECON-X frontend.
//
// Every REST call carries the current access token as an `Authorization:
// Bearer <token>` header (see `authHeader`). The browser WebSocket API cannot
// set custom headers, so the access token is passed via the
// `Sec-WebSocket-Protocol` subprotocol (see `wsAuthProtocols`) — NOT the URL
// query string, which reverse-proxy/gunicorn access logs and browser history
// would otherwise capture.
//
// Override the base with VITE_API_BASE in a .env file if your backend runs
// somewhere other than http://127.0.0.1:8002 (the backend's default port).
export const HTTP_BASE =
  import.meta.env.VITE_API_BASE || "http://127.0.0.1:8002";

const WS_BASE = HTTP_BASE.replace(/^http/, "ws") + "/ws/scan";
const PIPELINE_WS_BASE = HTTP_BASE.replace(/^http/, "ws") + "/ws/pipeline";

// `WS_URL` is an ESM live binding: `useScan` imports it and reads it at
// connect-time, so reassigning it here (via setAuthToken) transparently makes
// every subsequent WebSocket carry the freshest access token — no change to the
// scan hook required.
export let WS_URL = WS_BASE;

// Pipeline WS URL — updated in sync with the auth token.
export let PIPELINE_WS_URL = PIPELINE_WS_BASE;

/** Returns the pipeline WebSocket URL with the current auth token baked in. */
export function getPipelineWsUrl() {
  return PIPELINE_WS_URL;
}

// --------------------------------------------------------------------------- //
// Auth token wiring
// --------------------------------------------------------------------------- //
let accessToken = null;
let onUnauthorized = null; // async () => boolean  (true == token refreshed)

// Called by AuthContext whenever the access token changes (login / refresh /
// logout). The WS URLs are plain base URLs (no credential); the token is carried
// out-of-band via the subprotocol (see `wsAuthProtocols`).
export function setAuthToken(token) {
  accessToken = token || null;
}

export function getAuthToken() {
  return accessToken;
}

// The Sec-WebSocket-Protocol list a WebSocket is opened with. The access token
// travels here — in a header, never the URL — so it is not exposed via access
// logs, proxy logs, or browser history. The server reads the value after the
// "reconx.token" marker and echoes back only that (safe) protocol name.
export function wsAuthProtocols() {
  return accessToken ? ["reconx.token", accessToken] : [];
}

// The header object mixed into every authed fetch — also handy for callers that
// build their own requests.
export function authHeader() {
  return accessToken ? { Authorization: `Bearer ${accessToken}` } : {};
}

// AuthContext registers a refresh routine here. On a 401 we call it once; if it
// resolves truthy (a new access token was installed) the request is retried.
export function setUnauthorizedHandler(fn) {
  onUnauthorized = fn;
}

async function request(path, { method = "GET", body, headers, raw, skipAuthRetry } = {}) {
  const build = () => {
    // `credentials: "include"` so the httpOnly refresh cookie is received on
    // login/register and sent on /auth/refresh. The cookie is path-scoped to
    // /auth/refresh, so it never rides ordinary API calls; access auth stays the
    // Bearer header.
    const opts = {
      method,
      credentials: "include",
      headers: { ...authHeader(), ...(headers || {}) },
    };
    if (body !== undefined) {
      opts.headers["Content-Type"] = "application/json";
      opts.body = JSON.stringify(body);
    }
    return opts;
  };

  let res = await fetch(`${HTTP_BASE}${path}`, build());

  if (res.status === 401 && onUnauthorized && !skipAuthRetry) {
    let refreshed;
    try {
      refreshed = await onUnauthorized();
    } catch {
      refreshed = false;
    }
    if (refreshed) res = await fetch(`${HTTP_BASE}${path}`, build());
  }

  if (!res.ok) {
    let detail;
    try {
      detail = (await res.json())?.detail;
    } catch {
      /* non-JSON error body */
    }
    const err = new Error(detail || `${method} ${path} failed (${res.status})`);
    err.status = res.status;
    throw err;
  }

  if (raw) return res;
  if (res.status === 204) return null;
  return res.json();
}

// --------------------------------------------------------------------------- //
// Auth
// --------------------------------------------------------------------------- //
export function registerUser({ email, password, full_name = "", org_name }) {
  return request("/auth/register", {
    method: "POST",
    body: { email, password, full_name, org_name },
  });
}

export function loginUser({ email, password, mfa_code }) {
  return request("/auth/login", {
    method: "POST",
    body: { email, password, ...(mfa_code ? { mfa_code } : {}) },
  });
}

// Rotates the session via the httpOnly refresh cookie (sent by credentials:
// "include") — the refresh token never lives in JS. Returns { access_token };
// the rotated refresh token is delivered only in the re-set cookie. Never itself
// triggers the 401 refresh path.
export function refreshTokens() {
  return request("/auth/refresh", {
    method: "POST",
    skipAuthRetry: true,
  });
}

// Single-device sign-out: clears the httpOnly refresh cookie server-side and
// revokes the session family. Best-effort (204/no body); the caller still clears
// local access state regardless.
export function logoutSession() {
  return request("/auth/logout", { method: "POST", skipAuthRetry: true, raw: true });
}

export function fetchMe() {
  return request("/auth/me");
}

// --------------------------------------------------------------------------- //
// Tools
// --------------------------------------------------------------------------- //
export async function fetchTools() {
  return (await request("/tools")).tools;
}

// --------------------------------------------------------------------------- //
// Organizations
// --------------------------------------------------------------------------- //
export function fetchOrgs() {
  return request("/orgs"); // -> OrgOut[]
}

export function createOrg(name) {
  return request("/orgs", { method: "POST", body: { name } });
}

// --------------------------------------------------------------------------- //
// Workspaces (engagements)
// --------------------------------------------------------------------------- //
export function fetchWorkspaces(orgId) {
  return request(`/orgs/${orgId}/workspaces`); // -> WorkspaceOut[]
}

export function fetchWorkspace(wsId) {
  return request(`/workspaces/${wsId}`);
}

export function createWorkspace(orgId, { name, description = "", scope = [] }) {
  return request(`/orgs/${orgId}/workspaces`, {
    method: "POST",
    body: { name, description, scope },
  });
}

export function updateScope(wsId, scope) {
  return request(`/workspaces/${wsId}/scope`, { method: "PUT", body: { scope } });
}

// --------------------------------------------------------------------------- //
// Assets
// --------------------------------------------------------------------------- //
export function fetchAssets(wsId) {
  return request(`/workspaces/${wsId}/assets`); // -> AssetOut[]
}

export function createAsset(wsId, { value, atype = "domain" }) {
  return request(`/workspaces/${wsId}/assets`, {
    method: "POST",
    body: { value, atype },
  });
}

export function verifyAsset(assetId) {
  return request(`/assets/${assetId}/verify`, { method: "POST" });
}

// --------------------------------------------------------------------------- //
// Scans / findings (workspace-scoped)
// --------------------------------------------------------------------------- //
export function fetchWorkspaceScans(wsId) {
  return request(`/workspaces/${wsId}/scans`); // -> ScanSummaryOut[]
}

export function fetchWorkspaceFindings(wsId) {
  return request(`/workspaces/${wsId}/findings`); // -> FindingOut[]
}

export function fetchScan(scanId) {
  return request(`/scans/${scanId}`);
}

// Delete a single stored scan (+ its findings). Analyst+.
export function deleteScan(scanId) {
  return request(`/scans/${scanId}`, { method: "DELETE" });
}

// Clear ALL scan history + findings for a workspace. Admin+.
export function clearWorkspaceScans(wsId) {
  return request(`/workspaces/${wsId}/scans`, { method: "DELETE" });
}

export function patchFinding(findingId, status) {
  return request(`/findings/${findingId}`, { method: "PATCH", body: { status } });
}

// MITRE ATT&CK coverage matrix for a workspace (P1). Returns
// { tactics:[{ tactic, name, techniques:[{ technique_id, name, count, severities }] }],
//   total_techniques, total_findings }. Only tactics/techniques with >=1 mapped
// finding are present; an empty coverage yields empty `tactics` + zero totals.
export function fetchAttackCoverage(wsId) {
  return request(`/workspaces/${wsId}/attack-coverage`);
}

// --------------------------------------------------------------------------- //
// Purple-Team P2: SAFE ATT&CK emulation (workspace-scoped)
// --------------------------------------------------------------------------- //

// Run a set of SAFE, non-destructive ATT&CK technique emulations against an
// authorized target (analyst+). Body: { target, techniques? } where `techniques`
// is an optional list of emu ids (E1..E5); omit/undefined runs all. The backend
// scope-checks + netguard-checks + quota-checks first, then returns the completed
// run: EmulationRunOut { id, target, status, executed, blocked, failed, summary,
// started_at, finished_at, technique_results:[{ technique_id, technique_name,
// tactic, status, evidence, detail }] }.
export function runEmulation(wsId, { target, techniques } = {}) {
  return request(`/workspaces/${wsId}/emulate`, {
    method: "POST",
    body: { target, ...(techniques ? { techniques } : {}) },
  });
}

// List the workspace's past emulation runs, newest-first (member+).
export function fetchEmulations(wsId) {
  return request(`/workspaces/${wsId}/emulations`); // -> EmulationRunOut[]
}

// One emulation run with its ordered technique results (member via the run's ws).
export function fetchEmulation(runId) {
  return request(`/emulations/${runId}`);
}

// --------------------------------------------------------------------------- //
// Purple-Team P3: detection validation / SIEM connectors
// --------------------------------------------------------------------------- //

// List an org's detection connectors (member/viewer+). Secrets are masked by the
// backend: each DetectionConnectorOut exposes { id, org_id, name, ctype, enabled,
// created_at, config_keys:[...], config:{...redacted...} } — secret-bearing keys
// (token/api_key/auth/password/secret/headers) come back as "***", never the value.
export function fetchConnectors(orgId) {
  return request(`/orgs/${orgId}/detection-connectors`);
}

// Create a detection connector (admin+). `body` is DetectionConnectorIn:
// { name, ctype: "mock"|"http"|"splunk"|"elastic", config:{...}, enabled }. The
// config may carry secrets on the way in; they are never echoed back out.
export function createConnector(orgId, body) {
  return request(`/orgs/${orgId}/detection-connectors`, { method: "POST", body });
}

// Delete a detection connector by id (admin+). Historical detection results are
// preserved (their FK is SET NULL on the backend).
export function deleteConnector(connectorId) {
  return request(`/detection-connectors/${connectorId}`, { method: "DELETE" });
}

// Validate an emulation run against a connector (analyst+). Asks the defender
// SIEM/EDR "did you detect each emulated technique?", persists the verdicts, and
// returns the envelope { results: DetectionResultOut[], summary: DetectionSummaryOut }
// where summary = { total, detected, missed, coverage_pct, window_seconds, source }.
export function validateEmulation(runId, connectorId) {
  const qs = new URLSearchParams({ connector_id: connectorId }).toString();
  return request(`/emulations/${runId}/validate?${qs}`, { method: "POST" });
}

// The persisted detection results for an emulation run (member read) ->
// DetectionResultOut[] { technique_id, technique_name, tactic, detected, count,
// source, evidence, ... }.
export function fetchDetections(runId) {
  return request(`/emulations/${runId}/detections`);
}

// --------------------------------------------------------------------------- //
// Purple-Team P4: continuous purple loop + coverage dashboard (workspace-scoped)
// --------------------------------------------------------------------------- //

// Run ONE continuous purple loop against an authorized target (analyst+):
// emulate SAFE ATT&CK techniques, then — when `connector_id` is given — validate
// each against that org SIEM/EDR connector in a single request. The backend
// scope-checks + netguard-checks + quota-checks first, persists the emulation run
// (+ detection results), evaluates coverage drift vs. the previous purple run, and
// returns the envelope { emulation_run: EmulationRunOut, detections:
// DetectionResultOut[], summary: { emulation_run_id, target, executed, blocked,
// failed, validated, detected|null, missed|null, coverage_pct|null, total, source,
// window_seconds, drift }, drift? } — `detected`/`coverage_pct` are null when no
// connector was supplied (emulate-only). `techniques` optionally limits the emu
// ids (E1..E5); omit to run all.
export function runPurple(wsId, { target, connector_id, techniques } = {}) {
  return request(`/workspaces/${wsId}/purple-run`, {
    method: "POST",
    body: {
      target,
      ...(connector_id ? { connector_id: Number(connector_id) } : {}),
      ...(techniques ? { techniques } : {}),
    },
  });
}

// The workspace's rolled-up detection-coverage dashboard (member+). Returns
// { summary: { techniques_emulated, detected, missed, not_validated,
//   coverage_pct: int|null },
//   techniques: [{ technique_id, name, tactic, emulated, detected: bool|null,
//     last_run_id, last_at }],           // latest status per technique
//   tactics: [{ tactic, name, total, detected, missed }],  // ATT&CK order
//   trend: [{ run_id, at, coverage_pct }],                 // validated runs, last ~20
//   gaps: [{ technique_id, name, tactic }] }.              // emulated but missed
// An empty workspace yields zeroed summary + empty arrays (a clean empty state).
export function fetchCoverage(wsId) {
  return request(`/workspaces/${wsId}/coverage`);
}

// Auto-pentest run history (newest first) + full run detail + delete.
export function fetchPentestRuns(wsId) {
  return request(`/workspaces/${wsId}/pentest-runs`); // -> PentestRunOut[]
}
export function fetchPentestRun(wsId, runId) {
  return request(`/workspaces/${wsId}/pentest-runs/${runId}`); // -> PentestRunDetailOut (with process)
}
export function deletePentestRun(wsId, runId) {
  return request(`/workspaces/${wsId}/pentest-runs/${runId}`, { method: "DELETE" });
}

// --------------------------------------------------------------------------- //
// Phase 4: intel — risk, diff, AI triage, schedules, notifications
// --------------------------------------------------------------------------- //

// Aggregate risk score for a workspace -> RiskOut { score, rating, counts, total }.
export function fetchRisk(wsId) {
  return request(`/workspaces/${wsId}/risk`);
}

// Diff the two most recent scans of tool/target -> DiffOut { new, resolved, unchanged, counts }.
export function fetchDiff(wsId, { tool, target }) {
  const qs = new URLSearchParams({ tool, target }).toString();
  return request(`/workspaces/${wsId}/diff?${qs}`);
}

// Run AI triage over the workspace's findings (analyst+). Returns the structured
// envelope: { enabled, model?, reason?, refused, result? }. `enabled === false`
// means AI is not configured — render a graceful note rather than an error.
export function runTriage(wsId) {
  return request(`/workspaces/${wsId}/triage`, { method: "POST" });
}

// Most recent persisted triage, if any: { enabled, model?, summary?, result?, ... }.
export function fetchTriage(wsId) {
  return request(`/workspaces/${wsId}/triage`);
}

// ---- Schedules (workspace-scoped) ---------------------------------------- //
export function fetchSchedules(wsId) {
  return request(`/workspaces/${wsId}/schedules`); // -> ScheduleOut[]
}

export function createSchedule(wsId, { tool, target, cron, options = {}, enabled = true }) {
  return request(`/workspaces/${wsId}/schedules`, {
    method: "POST",
    body: { tool, target, cron, options, enabled },
  });
}

export function deleteSchedule(scheduleId) {
  return request(`/schedules/${scheduleId}`, { method: "DELETE" });
}

export function toggleSchedule(scheduleId, enabled) {
  return request(`/schedules/${scheduleId}`, { method: "PATCH", body: { enabled } });
}

// ---- Notification channels (org-scoped) ---------------------------------- //
export function fetchNotifications(orgId) {
  return request(`/orgs/${orgId}/notifications`); // -> ChannelOut[]
}

export function createNotification(orgId, { ctype, config = {}, events = ["new_finding"], enabled = true }) {
  return request(`/orgs/${orgId}/notifications`, {
    method: "POST",
    body: { ctype, config, events, enabled },
  });
}

export function deleteNotification(channelId) {
  return request(`/notifications/${channelId}`, { method: "DELETE" });
}

// --------------------------------------------------------------------------- //
// Phase 3: billing — plans, org billing status, Stripe checkout/portal, license
// --------------------------------------------------------------------------- //

// Public static plan catalog -> PlanOut[] { id, name, price_usd_month, limits }.
export function fetchPlans() {
  return request("/billing/plans");
}

// Org billing posture -> { mode, plan, limits, usage, features }. `mode` is one
// of "none" | "cloud" | "self_hosted"; usage keys are scans_this_period / assets
// / seats; a limit value of null means unlimited.
export function fetchBilling(orgId) {
  return request(`/orgs/${orgId}/billing`);
}

// Start a Stripe Checkout session for `plan` -> { url } (admin+). When Stripe is
// off/unconfigured the backend responds 400 and request() throws — callers
// should catch and surface the message as the {error} note.
export function startCheckout(orgId, plan) {
  return request(`/orgs/${orgId}/billing/checkout`, {
    method: "POST",
    body: { plan },
  });
}

// Open a Stripe Billing Portal session -> { url } (admin+). Throws on 400 when
// Stripe is unavailable, same as startCheckout.
export function openPortal(orgId) {
  return request(`/orgs/${orgId}/billing/portal`, { method: "POST" });
}

// The install's active / stored license -> LicenseOut { tier, entitlements,
// expires_at, valid } (viewer+).
export function fetchLicense(orgId) {
  return request(`/orgs/${orgId}/license`);
}

// Verify + record a signed license token -> LicenseOut (admin+). Throws on 400
// with the verification reason for an invalid/expired token.
export function installLicense(orgId, token) {
  return request(`/orgs/${orgId}/license`, { method: "POST", body: { token } });
}

// --------------------------------------------------------------------------- //
// Phase 5: enterprise — branding, SSO, audit log, org export, session controls
// --------------------------------------------------------------------------- //

// Org white-label branding -> { name, color, logo_url, footer, ... } (viewer+).
export function fetchBranding(orgId) {
  return request(`/orgs/${orgId}/branding`);
}

// Persist branding (admin+). `body` is the branding shape
// { name, color, logo_url, footer }. Returns the saved record.
export function saveBranding(orgId, body) {
  return request(`/orgs/${orgId}/branding`, { method: "PUT", body });
}

// Org audit log -> AuditEntry[] { id, actor, action, target, ip, created_at }
// (admin+). Ordered newest-first by the backend.
export function fetchAudit(orgId) {
  return request(`/orgs/${orgId}/audit`);
}

// Full org data export as a JSON object (admin+). The Settings panel serializes
// this to a downloadable blob.
export function exportOrg(orgId) {
  return request(`/orgs/${orgId}/export`);
}

// SSO configuration -> { enabled, provider, issuer, client_id, ... } (admin+).
// Secrets are never returned; the backend masks/omits them.
export function fetchSso(orgId) {
  return request(`/orgs/${orgId}/sso`);
}

// Persist SSO config (admin+). `body` carries { enabled, provider, issuer,
// client_id, client_secret? }; an empty/absent client_secret leaves the stored
// secret untouched (write-only). Returns the saved (masked) config.
export function saveSso(orgId, body) {
  return request(`/orgs/${orgId}/sso`, { method: "PUT", body });
}

// Revoke every refresh token / session for the current user across all devices
// (self-service). After this resolves the caller must re-authenticate.
export function logoutAll() {
  return request("/auth/logout-all", { method: "POST" });
}

// URL for the workspace's HTML engagement report. NOTE: this endpoint requires a
// Bearer JWT, which a plain <a href> / new-tab navigation cannot send, so the
// token is not embedded in the URL (never put credentials in a query string).
// Consumers that need the rendered report should use `fetchReportHtml` below.
export function reportUrl(wsId) {
  return `${HTTP_BASE}/workspaces/${wsId}/report`;
}

// Fetch the rendered HTML report WITH the auth header. The caller turns this
// into a blob URL and opens it in a new tab (a plain link can't carry the JWT).
export async function fetchReportHtml(wsId) {
  const res = await fetch(reportUrl(wsId), { headers: { ...authHeader() } });
  if (!res.ok) throw new Error(`Report failed (${res.status})`);
  return res.text();
}

// --------------------------------------------------------------------------- //
// Purple-Team P5: human-gated, non-destructive exploit validation
// --------------------------------------------------------------------------- //
//
// The honest market boundary of RECON-X: the platform *proposes* exploit
// candidates from a workspace's findings and *validates reachability* with SAFE,
// non-destructive probes (benign TCP connect / HTTP GET / X-RECONX marker — the
// same philosophy as app/emulation). It NEVER auto-exploits: every proposal is
// human-gated (must be explicitly `approved` before `execute` is allowed), each
// execution passes scope + SSRF checks and runs sandboxed, and no destructive
// payload, shell, or data-exfil is ever sent.

// Ask the backend to propose exploit candidates from the workspace's findings
// (analyst+). Returns { proposals:[...] } OR a bare list — callers handle both.
// Each proposal: { id, finding_id, technique_id, title, rationale, status,
// approved_by, result, created_at }; fresh proposals come back as status
// "proposed" (awaiting human approval).
export function proposeExploits(wsId) {
  return request(`/workspaces/${wsId}/exploit/propose`, { method: "POST" });
}

// List the workspace's exploit proposals, newest-first (member+) ->
// ExploitProposalOut[] (see shape above).
export function fetchExploitProposals(wsId) {
  return request(`/workspaces/${wsId}/exploit/proposals`);
}

// Approve a proposal for execution (admin+ — the human gate). May respond 403
// for non-admins; request() throws with the backend `detail`, which the panel
// surfaces cleanly. Returns the updated proposal (status -> "approved").
export function approveExploit(wsId, pid) {
  return request(`/workspaces/${wsId}/exploit/${pid}/approve`, { method: "POST" });
}

// Reject a proposal (admin+). Returns the updated proposal (status -> "rejected").
export function rejectExploit(wsId, pid) {
  return request(`/workspaces/${wsId}/exploit/${pid}/reject`, { method: "POST" });
}

// Execute an APPROVED proposal's SAFE validation probe against `target`
// (analyst+). The backend refuses unless the proposal is already `approved`,
// then scope- + SSRF-checks and sandboxes the probe. Returns the updated proposal
// with `result` (the evidence JSON) and status "executed"/"failed".
export function executeExploit(wsId, pid, target) {
  return request(`/workspaces/${wsId}/exploit/${pid}/execute`, {
    method: "POST",
    body: { target },
  });
}

// Fetch the workspace's purple-team HTML report WITH the auth header, turn it
// into a blob URL and open it in a new tab (a plain <a>/new-tab nav can't carry
// the JWT). Mirrors fetchReportHtml's blob+auth pattern.
export async function fetchPurpleReport(wsId) {
  const res = await fetch(`${HTTP_BASE}/workspaces/${wsId}/purple-report`, {
    headers: { ...authHeader() },
  });
  if (!res.ok) throw new Error(`Purple-team report failed (${res.status})`);
  const html = await res.text();
  const blob = new Blob([html], { type: "text/html" });
  const url = URL.createObjectURL(blob);
  const win = window.open(url, "_blank", "noopener,noreferrer");
  // Revoke a little later so the new tab has time to load the document.
  setTimeout(() => URL.revokeObjectURL(url), 60000);
  return win;
}

// Return the purple-team report HTML (auth-carried) so the caller can render it
// in-app (iframe/modal) — reliable regardless of popup blockers.
export async function fetchPurpleReportHtml(wsId) {
  // The report reflects live findings — never serve a cached copy. A unique
  // query param busts any HTTP/browser cache (the backend ignores it).
  const res = await fetch(
    `${HTTP_BASE}/workspaces/${wsId}/purple-report?_=${Date.now()}`,
    { headers: { ...authHeader() }, cache: "no-store" }
  );
  if (!res.ok) throw new Error(`Purple-team report failed (${res.status})`);
  return res.text();
}

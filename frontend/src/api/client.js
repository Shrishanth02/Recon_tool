// API endpoints + auth wiring for the RECON-X frontend.
//
// Every REST call carries the current access token as an `Authorization:
// Bearer <token>` header (see `authHeader`). The WebSocket cannot set headers,
// so the access token is appended to `WS_URL` as `?token=<access>` instead.
//
// Override the base with VITE_API_BASE in a .env file if your backend runs
// somewhere other than http://127.0.0.1:8002 (the backend's default port).
export const HTTP_BASE =
  import.meta.env.VITE_API_BASE || "http://127.0.0.1:8002";

const WS_BASE = HTTP_BASE.replace(/^http/, "ws") + "/ws/scan";

// `WS_URL` is an ESM live binding: `useScan` imports it and reads it at
// connect-time, so reassigning it here (via setAuthToken) transparently makes
// every subsequent WebSocket carry the freshest access token — no change to the
// scan hook required.
export let WS_URL = WS_BASE;

// --------------------------------------------------------------------------- //
// Auth token wiring
// --------------------------------------------------------------------------- //
let accessToken = null;
let onUnauthorized = null; // async () => boolean  (true == token refreshed)

// Called by AuthContext whenever the access token changes (login / refresh /
// logout). Keeps both the REST header source and the WS query token in sync.
export function setAuthToken(token) {
  accessToken = token || null;
  WS_URL = accessToken
    ? `${WS_BASE}?token=${encodeURIComponent(accessToken)}`
    : WS_BASE;
}

export function getAuthToken() {
  return accessToken;
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
    const opts = { method, headers: { ...authHeader(), ...(headers || {}) } };
    if (body !== undefined) {
      opts.headers["Content-Type"] = "application/json";
      opts.body = JSON.stringify(body);
    }
    return opts;
  };

  let res = await fetch(`${HTTP_BASE}${path}`, build());

  if (res.status === 401 && onUnauthorized && !skipAuthRetry) {
    let refreshed = false;
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

// Uses the refresh token directly; never itself triggers the 401 refresh path.
export function refreshTokens(refresh_token) {
  return request("/auth/refresh", {
    method: "POST",
    body: { refresh_token },
    skipAuthRetry: true,
  });
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

export function patchFinding(findingId, status) {
  return request(`/findings/${findingId}`, { method: "PATCH", body: { status } });
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

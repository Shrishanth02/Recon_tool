import { useCallback, useEffect, useState } from "react";
import Icon from "./Icon";
import { useAuth } from "../auth/AuthContext";
import {
  fetchBranding,
  saveBranding,
  fetchSso,
  saveSso,
  fetchAudit,
  exportOrg,
  logoutAll,
  fetchConnectors,
  createConnector,
  deleteConnector,
} from "../api/client";

// Phase 5 / Settings — the org-admin enterprise console. Five sections:
//   Branding  — white-label name/color/logo/footer with a live preview swatch.
//   SSO       — OIDC provider/issuer/client id + enable toggle (secret is
//               write-only: never returned, only sent when re-entered).
//   Detection — Purple-Team P3 SIEM/EDR connectors (mock/http/splunk/elastic):
//               list + add (secret config fields are write-only) + delete.
//   Security  — "Sign out everywhere" (revoke all sessions) then re-login.
//   Audit     — scrollable audit table + a one-click org JSON export.
// Every remote call is admin-gated on the backend; a 403 (or any failure) is
// surfaced inline rather than crashing the panel. Matches the dark console
// styling used across RECON-X.

const TABS = [
  { key: "branding", label: "Branding", icon: "shield" },
  { key: "sso", label: "SSO", icon: "id" },
  { key: "detection", label: "Detection", icon: "radar" },
  { key: "security", label: "Security", icon: "bolt" },
  { key: "audit", label: "Audit", icon: "history" },
];

const SSO_PROVIDERS = ["oidc", "saml", "google", "okta", "azuread"];

// --------------------------------------------------------------------------- //
// Detection connector type catalog (Purple-Team P3)
// --------------------------------------------------------------------------- //
// Each connector type declares its config fields. `secret: true` fields are
// write-only — rendered as password inputs and only ever sent to the backend,
// never displayed (the OUT schema masks them to "***"). `kind` drives light
// parsing so numbers / lists reach the backend in the right shape.
const CONNECTOR_TYPES = [
  {
    ctype: "mock",
    label: "Mock (demo / testing)",
    blurb: "Deterministic connector for demos + tests. Detects a technique when it is listed, or by coverage probability.",
    fields: [
      { key: "coverage", label: "Coverage", kind: "number", placeholder: "0.0 – 1.0", hint: "Fraction of techniques detected (0–1)." },
      { key: "detect_technique_ids", label: "Always-detect technique IDs", kind: "list", placeholder: "T1071, T1595", hint: "Comma-separated ATT&CK IDs." },
    ],
  },
  {
    ctype: "http",
    label: "Generic HTTP / webhook",
    blurb: "POST/GET a search query to any HTTP SIEM API. Detected when the hit count at count_path is > 0.",
    fields: [
      { key: "search_url", label: "Search URL", kind: "text", placeholder: "https://siem.example.com/api/search" },
      { key: "method", label: "HTTP method", kind: "text", placeholder: "POST" },
      { key: "count_path", label: "Count path", kind: "text", placeholder: "total", hint: "Dot-path to the hit count in the JSON response." },
      { key: "body_template", label: "Body template", kind: "text", placeholder: '{"q":"{marker} {technique_id} since {since}"}', hint: "Supports {technique_id} / {marker} / {since}." },
      { key: "headers", label: "Headers (JSON)", kind: "json", secret: true, placeholder: '{"Authorization":"Bearer …"}' },
      { key: "auth", label: "Auth", kind: "text", secret: true, placeholder: "user:pass or token" },
    ],
  },
  {
    ctype: "splunk",
    label: "Splunk",
    blurb: "Runs a oneshot search via the Splunk REST API, filtered by marker + time. Needs live credentials to return hits.",
    fields: [
      { key: "base_url", label: "Base URL", kind: "text", placeholder: "https://splunk.example.com:8089" },
      { key: "index", label: "Index", kind: "text", placeholder: "main" },
      { key: "token", label: "Token", kind: "text", secret: true, placeholder: "Splunk auth token" },
    ],
  },
  {
    ctype: "elastic",
    label: "Elastic",
    blurb: "Queries {index}/_search on the marker + @timestamp. Needs live credentials to return hits.",
    fields: [
      { key: "base_url", label: "Base URL", kind: "text", placeholder: "https://es.example.com:9200" },
      { key: "index", label: "Index", kind: "text", placeholder: "logs-*" },
      { key: "api_key", label: "API key", kind: "text", secret: true, placeholder: "base64 API key" },
    ],
  },
];

function connectorMeta(ctype) {
  return CONNECTOR_TYPES.find((c) => c.ctype === ctype) || null;
}

function fmtWhen(iso) {
  if (!iso) return "";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? String(iso) : d.toLocaleString();
}

// Normalize a hex-ish color so the preview swatch never renders garbage.
function safeColor(c) {
  if (typeof c !== "string") return "#2dd4bf";
  const v = c.trim();
  return /^#?[0-9a-fA-F]{3,8}$/.test(v) ? (v[0] === "#" ? v : `#${v}`) : "#2dd4bf";
}

export default function SettingsPanel({ orgId }) {
  const { logout } = useAuth();
  const [tab, setTab] = useState("branding");

  return (
    <section className="panel settings-panel">
      <header className="panel-head">
        <span className="panel-title">
          <Icon name="shield" size={15} /> Settings
        </span>
        <nav className="settings-tabs">
          {TABS.map((t) => (
            <button
              key={t.key}
              className={tab === t.key ? "settings-tab active" : "settings-tab"}
              onClick={() => setTab(t.key)}
            >
              <Icon name={t.icon} size={13} /> {t.label}
            </button>
          ))}
        </nav>
      </header>

      <div className="results-body">
        {!orgId ? (
          <div className="results-empty">
            <Icon name="shield" size={28} />
            <p>Select an organization to manage its settings.</p>
          </div>
        ) : (
          <>
            {tab === "branding" && <BrandingSection orgId={orgId} />}
            {tab === "sso" && <SsoSection orgId={orgId} />}
            {tab === "detection" && <DetectionSection orgId={orgId} />}
            {tab === "security" && <SecuritySection logout={logout} />}
            {tab === "audit" && <AuditSection orgId={orgId} />}
          </>
        )}
      </div>
    </section>
  );
}

// --------------------------------------------------------------------------- //
// Branding
// --------------------------------------------------------------------------- //
function BrandingSection({ orgId }) {
  const [form, setForm] = useState({ name: "", color: "", logo_url: "", footer: "" });
  const [loading, setLoading] = useState(false);
  const [loadErr, setLoadErr] = useState(null);
  const [saving, setSaving] = useState(false);
  const [saveNote, setSaveNote] = useState(null); // { kind: "ok"|"err", text }

  const load = useCallback(async () => {
    setLoading(true);
    setLoadErr(null);
    try {
      const b = await fetchBranding(orgId);
      setForm({
        name: b?.name || "",
        color: b?.color || "",
        logo_url: b?.logo_url || "",
        footer: b?.footer || "",
      });
    } catch (e) {
      setLoadErr(e?.message || "Failed to load branding");
    } finally {
      setLoading(false);
    }
  }, [orgId]);

  useEffect(() => {
    load();
  }, [load]);

  const set = (key) => (e) => setForm((f) => ({ ...f, [key]: e.target.value }));

  const onSave = useCallback(async () => {
    if (saving) return;
    setSaving(true);
    setSaveNote(null);
    try {
      const saved = await saveBranding(orgId, {
        name: form.name.trim(),
        color: form.color.trim(),
        logo_url: form.logo_url.trim(),
        footer: form.footer.trim(),
      });
      if (saved && typeof saved === "object") {
        setForm({
          name: saved.name ?? form.name,
          color: saved.color ?? form.color,
          logo_url: saved.logo_url ?? form.logo_url,
          footer: saved.footer ?? form.footer,
        });
      }
      setSaveNote({ kind: "ok", text: "Branding saved." });
    } catch (e) {
      setSaveNote({ kind: "err", text: e?.message || "Failed to save branding" });
    } finally {
      setSaving(false);
    }
  }, [orgId, form, saving]);

  const swatch = safeColor(form.color);

  if (loading) return <div className="muted sched-empty">Loading branding…</div>;
  if (loadErr)
    return (
      <div className="result-error">
        <Icon name="x" size={16} /> {loadErr}
      </div>
    );

  return (
    <div className="settings-section">
      <div className="settings-grid">
        <label className="settings-field">
          <span>Display name</span>
          <input
            type="text"
            value={form.name}
            onChange={set("name")}
            placeholder="Acme Security"
          />
        </label>

        <label className="settings-field">
          <span>Accent color</span>
          <div className="settings-color-row">
            <input
              type="color"
              className="settings-color"
              value={swatch.length === 7 ? swatch : "#2dd4bf"}
              onChange={set("color")}
              aria-label="Accent color picker"
            />
            <input
              type="text"
              className="mono"
              value={form.color}
              onChange={set("color")}
              placeholder="#2dd4bf"
            />
          </div>
        </label>

        <label className="settings-field settings-field-wide">
          <span>Logo URL</span>
          <input
            type="url"
            value={form.logo_url}
            onChange={set("logo_url")}
            placeholder="https://cdn.example.com/logo.svg"
          />
        </label>

        <label className="settings-field settings-field-wide">
          <span>Report footer</span>
          <input
            type="text"
            value={form.footer}
            onChange={set("footer")}
            placeholder="© Acme Security — Confidential"
          />
        </label>
      </div>

      {/* Live preview swatch */}
      <div className="settings-preview" style={{ borderLeftColor: swatch }}>
        <div className="settings-preview-head">
          {form.logo_url ? (
            <img
              className="settings-preview-logo"
              src={form.logo_url}
              alt=""
              onError={(e) => {
                e.currentTarget.style.display = "none";
              }}
            />
          ) : (
            <span className="settings-preview-dot" style={{ background: swatch }} />
          )}
          <span className="settings-preview-name" style={{ color: swatch }}>
            {form.name.trim() || "Your organization"}
          </span>
        </div>
        <div className="settings-preview-body">
          <span className="settings-preview-tag" style={{ background: swatch }}>
            live preview
          </span>
          <span className="settings-preview-footer">
            {form.footer.trim() || "Report footer appears here."}
          </span>
        </div>
      </div>

      {saveNote && (
        <div
          className={
            saveNote.kind === "ok"
              ? "settings-ok triage-note"
              : "result-error triage-note"
          }
        >
          <Icon name={saveNote.kind === "ok" ? "check" : "x"} size={16} /> {saveNote.text}
        </div>
      )}

      <div className="settings-actions">
        <button className="btn btn-run settings-save" onClick={onSave} disabled={saving}>
          {saving ? (
            <>
              <span className="rec-dot" /> Saving…
            </>
          ) : (
            <>
              <Icon name="check" size={13} /> Save branding
            </>
          )}
        </button>
      </div>
    </div>
  );
}

// --------------------------------------------------------------------------- //
// SSO
// --------------------------------------------------------------------------- //
function SsoSection({ orgId }) {
  const [form, setForm] = useState({
    enabled: false,
    provider: "oidc",
    issuer: "",
    client_id: "",
    client_secret: "",
  });
  const [hasSecret, setHasSecret] = useState(false); // a secret is already stored
  const [loading, setLoading] = useState(false);
  const [loadErr, setLoadErr] = useState(null);
  const [saving, setSaving] = useState(false);
  const [saveNote, setSaveNote] = useState(null);

  const load = useCallback(async () => {
    setLoading(true);
    setLoadErr(null);
    try {
      const s = await fetchSso(orgId);
      setForm({
        enabled: !!s?.enabled,
        provider: s?.provider || "oidc",
        issuer: s?.issuer || "",
        client_id: s?.client_id || "",
        client_secret: "",
      });
      // Backend signals a stored secret via a flag or a masked placeholder.
      setHasSecret(!!(s?.has_secret || s?.client_secret_set || s?.client_secret));
    } catch (e) {
      setLoadErr(e?.message || "Failed to load SSO configuration");
    } finally {
      setLoading(false);
    }
  }, [orgId]);

  useEffect(() => {
    load();
  }, [load]);

  const set = (key) => (e) =>
    setForm((f) => ({
      ...f,
      [key]: e.target.type === "checkbox" ? e.target.checked : e.target.value,
    }));

  const onSave = useCallback(async () => {
    if (saving) return;
    setSaving(true);
    setSaveNote(null);
    try {
      const body = {
        enabled: form.enabled,
        provider: form.provider,
        issuer: form.issuer.trim(),
        client_id: form.client_id.trim(),
      };
      // Write-only: only send the secret when the admin actually typed one.
      if (form.client_secret.trim()) body.client_secret = form.client_secret.trim();
      const saved = await saveSso(orgId, body);
      if (saved && typeof saved === "object") {
        setForm((f) => ({
          ...f,
          enabled: !!saved.enabled,
          provider: saved.provider || f.provider,
          issuer: saved.issuer ?? f.issuer,
          client_id: saved.client_id ?? f.client_id,
          client_secret: "",
        }));
        setHasSecret(
          !!(saved.has_secret || saved.client_secret_set || saved.client_secret) ||
            !!body.client_secret
        );
      } else {
        setForm((f) => ({ ...f, client_secret: "" }));
        if (body.client_secret) setHasSecret(true);
      }
      setSaveNote({ kind: "ok", text: "SSO configuration saved." });
    } catch (e) {
      setSaveNote({ kind: "err", text: e?.message || "Failed to save SSO configuration" });
    } finally {
      setSaving(false);
    }
  }, [orgId, form, saving]);

  if (loading) return <div className="muted sched-empty">Loading SSO configuration…</div>;
  if (loadErr)
    return (
      <div className="result-error">
        <Icon name="x" size={16} /> {loadErr}
      </div>
    );

  return (
    <div className="settings-section">
      <label className="settings-toggle">
        <input type="checkbox" checked={form.enabled} onChange={set("enabled")} />
        <span className="settings-toggle-track" aria-hidden="true">
          <span className="settings-toggle-knob" />
        </span>
        <span className="settings-toggle-label">
          Single sign-on {form.enabled ? "enabled" : "disabled"}
        </span>
      </label>

      <div className="settings-grid">
        <label className="settings-field">
          <span>Provider</span>
          <select value={form.provider} onChange={set("provider")}>
            {SSO_PROVIDERS.map((p) => (
              <option key={p} value={p}>
                {p.toUpperCase()}
              </option>
            ))}
          </select>
        </label>

        <label className="settings-field">
          <span>Client ID</span>
          <input
            type="text"
            className="mono"
            value={form.client_id}
            onChange={set("client_id")}
            placeholder="reconx-web"
          />
        </label>

        <label className="settings-field settings-field-wide">
          <span>Issuer / metadata URL</span>
          <input
            type="url"
            className="mono"
            value={form.issuer}
            onChange={set("issuer")}
            placeholder="https://idp.example.com/realms/acme"
          />
        </label>

        <label className="settings-field settings-field-wide">
          <span>
            Client secret{" "}
            <em className="auth-optional">
              {hasSecret ? "stored — leave blank to keep" : "write-only"}
            </em>
          </span>
          <input
            type="password"
            className="mono"
            autoComplete="new-password"
            value={form.client_secret}
            onChange={set("client_secret")}
            placeholder={hasSecret ? "••••••••  (unchanged)" : "Paste client secret"}
          />
        </label>
      </div>

      <p className="settings-hint">
        <Icon name="shield" size={13} /> Secrets are never sent back to the browser.
        Leave the field blank to keep the stored value.
      </p>

      {saveNote && (
        <div
          className={
            saveNote.kind === "ok"
              ? "settings-ok triage-note"
              : "result-error triage-note"
          }
        >
          <Icon name={saveNote.kind === "ok" ? "check" : "x"} size={16} /> {saveNote.text}
        </div>
      )}

      <div className="settings-actions">
        <button className="btn btn-run settings-save" onClick={onSave} disabled={saving}>
          {saving ? (
            <>
              <span className="rec-dot" /> Saving…
            </>
          ) : (
            <>
              <Icon name="check" size={13} /> Save SSO
            </>
          )}
        </button>
      </div>
    </div>
  );
}

// --------------------------------------------------------------------------- //
// Detection connectors (Purple-Team P3)
// --------------------------------------------------------------------------- //
// List the org's SIEM/EDR connectors, add a new one (type-specific config with
// write-only secret fields), and delete. Secrets are never returned by the
// backend — the OUT schema masks them to "***" and reports only `config_keys`,
// so this panel never re-displays a stored secret.
function DetectionSection({ orgId }) {
  const [rows, setRows] = useState([]);
  const [loading, setLoading] = useState(false);
  const [loadErr, setLoadErr] = useState(null);

  // Add-connector form state.
  const [ctype, setCtype] = useState(CONNECTOR_TYPES[0].ctype);
  const [name, setName] = useState("");
  const [config, setConfig] = useState({}); // { fieldKey: rawString }
  const [enabled, setEnabled] = useState(true);
  const [saving, setSaving] = useState(false);
  const [saveNote, setSaveNote] = useState(null); // { kind, text }
  const [deletingId, setDeletingId] = useState(null);

  const meta = connectorMeta(ctype);

  const load = useCallback(async () => {
    setLoading(true);
    setLoadErr(null);
    try {
      const data = await fetchConnectors(orgId);
      setRows(Array.isArray(data) ? data : []);
    } catch (e) {
      setLoadErr(e?.message || "Failed to load detection connectors");
    } finally {
      setLoading(false);
    }
  }, [orgId]);

  useEffect(() => {
    load();
  }, [load]);

  // Switching type resets the type-specific config so stale fields don't leak.
  const onTypeChange = (e) => {
    setCtype(e.target.value);
    setConfig({});
    setSaveNote(null);
  };

  const setField = (key) => (e) =>
    setConfig((c) => ({ ...c, [key]: e.target.value }));

  // Turn the raw string form into the typed config the backend expects.
  const buildConfig = () => {
    const out = {};
    for (const f of meta.fields) {
      const raw = (config[f.key] ?? "").trim();
      if (!raw) continue; // omit empties — keeps secrets write-only + config clean
      if (f.kind === "number") {
        const n = Number(raw);
        if (!Number.isNaN(n)) out[f.key] = n;
      } else if (f.kind === "list") {
        const items = raw.split(",").map((s) => s.trim()).filter(Boolean);
        if (items.length) out[f.key] = items;
      } else if (f.kind === "json") {
        try {
          out[f.key] = JSON.parse(raw);
        } catch {
          throw new Error(`"${f.label}" must be valid JSON.`);
        }
      } else {
        out[f.key] = raw;
      }
    }
    return out;
  };

  const onAdd = useCallback(async () => {
    if (saving) return;
    const nm = name.trim();
    if (!nm) {
      setSaveNote({ kind: "err", text: "Give the connector a name." });
      return;
    }
    let cfg;
    try {
      cfg = buildConfig();
    } catch (e) {
      setSaveNote({ kind: "err", text: e.message });
      return;
    }
    setSaving(true);
    setSaveNote(null);
    try {
      await createConnector(orgId, { name: nm, ctype, config: cfg, enabled });
      setName("");
      setConfig({});
      setEnabled(true);
      setSaveNote({ kind: "ok", text: "Connector added." });
      load();
    } catch (e) {
      setSaveNote({ kind: "err", text: e?.message || "Failed to add connector" });
    } finally {
      setSaving(false);
    }
  }, [orgId, name, ctype, config, enabled, saving, meta, load]);

  const onDelete = useCallback(
    async (id) => {
      if (deletingId) return;
      setDeletingId(id);
      try {
        await deleteConnector(id);
        setRows((rs) => rs.filter((r) => r.id !== id));
      } catch (e) {
        setSaveNote({ kind: "err", text: e?.message || "Failed to delete connector" });
      } finally {
        setDeletingId(null);
      }
    },
    [deletingId]
  );

  return (
    <div className="settings-section">
      {/* Existing connectors */}
      <div className="settings-audit-bar">
        <span className="bill-section-label" style={{ margin: 0 }}>
          Connectors{rows.length ? ` · ${rows.length}` : ""}
        </span>
        <div className="panel-actions">
          <button className="btn-ghost" onClick={load} disabled={loading} title="Reload">
            <Icon name="history" size={14} /> Refresh
          </button>
        </div>
      </div>

      {loading ? (
        <div className="muted sched-empty">Loading connectors…</div>
      ) : loadErr ? (
        <div className="result-error">
          <Icon name="x" size={16} /> {loadErr}
        </div>
      ) : rows.length === 0 ? (
        <div className="results-empty">
          <Icon name="radar" size={28} />
          <p>No detection connectors yet. Add one below to validate emulations.</p>
        </div>
      ) : (
        <div className="conn-list">
          {rows.map((r) => (
            <div className="conn-item" key={r.id}>
              <div className="conn-item-main">
                <span className="conn-name">{r.name}</span>
                <span className="pill pill-info conn-ctype">{r.ctype}</span>
                {!r.enabled && <span className="pill pill-dim">disabled</span>}
              </div>
              {Array.isArray(r.config_keys) && r.config_keys.length > 0 && (
                <div className="conn-keys">
                  {r.config_keys.map((k) => (
                    <span className="conn-key mono" key={k}>
                      {k}
                    </span>
                  ))}
                </div>
              )}
              <button
                className="btn-ghost conn-del"
                onClick={() => onDelete(r.id)}
                disabled={deletingId === r.id}
                title="Delete connector"
              >
                {deletingId === r.id ? (
                  <span className="rec-dot" />
                ) : (
                  <Icon name="trash" size={14} />
                )}
              </button>
            </div>
          ))}
        </div>
      )}

      {/* Add connector */}
      <div className="conn-add">
        <div className="conn-add-head">Add connector</div>

        <div className="settings-grid">
          <label className="settings-field">
            <span>Name</span>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Prod Splunk"
            />
          </label>

          <label className="settings-field">
            <span>Type</span>
            <select value={ctype} onChange={onTypeChange}>
              {CONNECTOR_TYPES.map((c) => (
                <option key={c.ctype} value={c.ctype}>
                  {c.label}
                </option>
              ))}
            </select>
          </label>
        </div>

        {meta?.blurb && (
          <p className="settings-hint">
            <Icon name="shield" size={13} /> {meta.blurb}
          </p>
        )}

        <div className="settings-grid">
          {meta.fields.map((f) => (
            <label
              key={f.key}
              className={
                f.kind === "json" || f.kind === "list" || f.key === "body_template"
                  ? "settings-field settings-field-wide"
                  : "settings-field"
              }
            >
              <span>
                {f.label}{" "}
                {f.secret && <em className="auth-optional">write-only</em>}
              </span>
              <input
                type={f.secret ? "password" : "text"}
                className={f.kind === "text" && !f.secret ? undefined : "mono"}
                autoComplete={f.secret ? "new-password" : "off"}
                value={config[f.key] ?? ""}
                onChange={setField(f.key)}
                placeholder={f.placeholder || ""}
              />
              {f.hint && <span className="conn-field-hint">{f.hint}</span>}
            </label>
          ))}
        </div>

        <label className="settings-toggle">
          <input
            type="checkbox"
            checked={enabled}
            onChange={(e) => setEnabled(e.target.checked)}
          />
          <span className="settings-toggle-track" aria-hidden="true">
            <span className="settings-toggle-knob" />
          </span>
          <span className="settings-toggle-label">
            Connector {enabled ? "enabled" : "disabled"}
          </span>
        </label>

        <p className="settings-hint">
          <Icon name="shield" size={13} /> Secret fields are write-only — they are
          sent once and never returned to the browser.
        </p>

        {saveNote && (
          <div
            className={
              saveNote.kind === "ok"
                ? "settings-ok triage-note"
                : "result-error triage-note"
            }
          >
            <Icon name={saveNote.kind === "ok" ? "check" : "x"} size={16} />{" "}
            {saveNote.text}
          </div>
        )}

        <div className="settings-actions">
          <button className="btn btn-run settings-save" onClick={onAdd} disabled={saving}>
            {saving ? (
              <>
                <span className="rec-dot" /> Adding…
              </>
            ) : (
              <>
                <Icon name="check" size={13} /> Add connector
              </>
            )}
          </button>
        </div>
      </div>

      <style>{DETECTION_CSS}</style>
    </div>
  );
}

// Component-scoped styles for the Detection section — token-driven, no hardcoded
// greys, so it tracks the app's light/dark themes.
const DETECTION_CSS = `
.conn-list { display: flex; flex-direction: column; gap: 8px; }
.conn-item {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 10px 12px;
  border-radius: var(--radius-sm);
  border: 1px solid var(--border);
  background: var(--bg-elev);
}
.conn-item-main { display: inline-flex; align-items: center; gap: 8px; flex-wrap: wrap; }
.conn-name { font-weight: 600; font-size: 13.5px; color: var(--text); }
.conn-ctype { text-transform: uppercase; letter-spacing: 0.04em; }
.conn-keys { display: inline-flex; gap: 5px; flex-wrap: wrap; flex: 1; }
.conn-key {
  font-size: 11px;
  color: var(--text-faint);
  background: var(--panel-2);
  border: 1px solid var(--border-soft);
  border-radius: 6px;
  padding: 1px 7px;
}
.conn-del { margin-left: auto; color: var(--danger); flex: 0 0 auto; }
.conn-del:hover:not(:disabled) { color: var(--danger); opacity: 0.8; }

.conn-add {
  margin-top: 6px;
  padding-top: 14px;
  border-top: 1px solid var(--border-soft);
  display: flex;
  flex-direction: column;
  gap: 12px;
}
.conn-add-head {
  font-size: 11px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  color: var(--text-faint);
}
.conn-field-hint { font-size: 11px; color: var(--text-faint); line-height: 1.4; }
`;

// --------------------------------------------------------------------------- //
// Security
// --------------------------------------------------------------------------- //
function SecuritySection({ logout }) {
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState(false);
  const [err, setErr] = useState(null);

  const onLogoutAll = useCallback(async () => {
    if (busy) return;
    setBusy(true);
    setErr(null);
    try {
      await logoutAll();
      setDone(true);
    } catch (e) {
      setErr(e?.message || "Failed to sign out everywhere");
    } finally {
      setBusy(false);
    }
  }, [busy]);

  return (
    <div className="settings-section">
      <div className="settings-danger">
        <div className="settings-danger-head">
          <Icon name="bolt" size={15} />
          <span>Sign out everywhere</span>
        </div>
        <p className="settings-danger-body">
          Revoke every active session for your account across all browsers and devices.
          You will need to sign in again to continue.
        </p>

        {err && (
          <div className="result-error triage-note">
            <Icon name="x" size={16} /> {err}
          </div>
        )}

        {done ? (
          <div className="settings-relogin">
            <div className="settings-ok triage-note">
              <Icon name="check" size={16} /> All sessions revoked. Please sign in again.
            </div>
            <button className="btn btn-run settings-save" onClick={logout}>
              <Icon name="swap" size={13} /> Back to sign in
            </button>
          </div>
        ) : (
          <button className="btn btn-stop settings-danger-btn" onClick={onLogoutAll} disabled={busy}>
            {busy ? (
              <>
                <span className="rec-dot" /> Revoking…
              </>
            ) : (
              <>
                <Icon name="swap" size={13} /> Sign out everywhere
              </>
            )}
          </button>
        )}
      </div>
    </div>
  );
}

// --------------------------------------------------------------------------- //
// Audit + export
// --------------------------------------------------------------------------- //
function AuditSection({ orgId }) {
  const [rows, setRows] = useState([]);
  const [loading, setLoading] = useState(false);
  const [loadErr, setLoadErr] = useState(null);
  const [exporting, setExporting] = useState(false);
  const [exportNote, setExportNote] = useState(null);

  const load = useCallback(async () => {
    setLoading(true);
    setLoadErr(null);
    try {
      const data = await fetchAudit(orgId);
      setRows(Array.isArray(data) ? data : data?.entries || []);
    } catch (e) {
      setLoadErr(e?.message || "Failed to load audit log");
    } finally {
      setLoading(false);
    }
  }, [orgId]);

  useEffect(() => {
    load();
  }, [load]);

  const onExport = useCallback(async () => {
    if (exporting) return;
    setExporting(true);
    setExportNote(null);
    try {
      const data = await exportOrg(orgId);
      const blob = new Blob([JSON.stringify(data, null, 2)], {
        type: "application/json",
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `reconx-org-${orgId}-export.json`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (e) {
      setExportNote(e?.message || "Failed to export org data");
    } finally {
      setExporting(false);
    }
  }, [orgId, exporting]);

  return (
    <div className="settings-section">
      <div className="settings-audit-bar">
        <span className="bill-section-label" style={{ margin: 0 }}>
          Audit log{rows.length ? ` · ${rows.length}` : ""}
        </span>
        <div className="panel-actions">
          <button className="btn-ghost" onClick={load} disabled={loading} title="Reload">
            <Icon name="history" size={14} /> Refresh
          </button>
          <button
            className="btn-ghost"
            onClick={onExport}
            disabled={exporting}
            title="Download the full org data export as JSON"
          >
            {exporting ? (
              <>
                <span className="rec-dot" /> Exporting…
              </>
            ) : (
              <>
                <Icon name="download" size={14} /> Export org data
              </>
            )}
          </button>
        </div>
      </div>

      {exportNote && (
        <div className="result-error triage-note">
          <Icon name="x" size={16} /> {exportNote}
        </div>
      )}

      {loading ? (
        <div className="muted sched-empty">Loading audit log…</div>
      ) : loadErr ? (
        <div className="result-error">
          <Icon name="x" size={16} /> {loadErr}
        </div>
      ) : rows.length === 0 ? (
        <div className="results-empty">
          <Icon name="history" size={28} />
          <p>No audit activity recorded yet.</p>
        </div>
      ) : (
        <div className="settings-audit-scroll">
          <table className="data-table settings-audit-table">
            <thead>
              <tr>
                <th>When</th>
                <th>Actor</th>
                <th>Action</th>
                <th>Detail</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r, i) => (
                <tr key={r.id ?? i}>
                  <td className="mono dim">{fmtWhen(r.created_at || r.at || r.timestamp)}</td>
                  <td className="mono dim">
                    {r.actor || r.actor_email || (r.user_id != null ? `user #${r.user_id}` : "system")}
                  </td>
                  <td>
                    <span className="pill pill-info">{r.action || r.event || "—"}</span>
                  </td>
                  <td className="mono dim">{r.detail || r.target || r.resource || "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

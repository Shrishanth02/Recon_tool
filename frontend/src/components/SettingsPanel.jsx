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
} from "../api/client";

// Phase 5 / Settings — the org-admin enterprise console. Four sections:
//   Branding — white-label name/color/logo/footer with a live preview swatch.
//   SSO       — OIDC provider/issuer/client id + enable toggle (secret is
//               write-only: never returned, only sent when re-entered).
//   Security  — "Sign out everywhere" (revoke all sessions) then re-login.
//   Audit     — scrollable audit table + a one-click org JSON export.
// Every remote call is admin-gated on the backend; a 403 (or any failure) is
// surfaced inline rather than crashing the panel. Matches the dark console
// styling used across RECON-X.

const TABS = [
  { key: "branding", label: "Branding", icon: "shield" },
  { key: "sso", label: "SSO", icon: "id" },
  { key: "security", label: "Security", icon: "bolt" },
  { key: "audit", label: "Audit", icon: "history" },
];

const SSO_PROVIDERS = ["oidc", "saml", "google", "okta", "azuread"];

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

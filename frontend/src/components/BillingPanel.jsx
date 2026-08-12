import { useCallback, useEffect, useState } from "react";
import Icon from "./Icon";
import {
  fetchBilling,
  fetchPlans,
  startCheckout,
  openPortal,
  fetchLicense,
  installLicense,
} from "../api/client";

// Phase 3 / Billing — plan + usage overview, plan catalog with self-serve
// upgrades (Stripe), a billing-portal shortcut, and the self-hosted license
// installer. Every remote shape is treated as optional: when Stripe or licensing
// is off the backend answers with a graceful mode/error and we render a note
// rather than an error state.

// The three metered quotas, mapping a usage counter to its plan-limit key.
const METERS = [
  { key: "scans", label: "Scans this month", usageKey: "scans_this_period", limitKey: "scans_per_month", icon: "radar" },
  { key: "assets", label: "Assets", usageKey: "assets", limitKey: "assets", icon: "shield" },
  { key: "seats", label: "Seats", usageKey: "seats", limitKey: "seats", icon: "id" },
];

// The boolean feature flags surfaced on each plan card / current status.
const FEATURES = [
  { key: "ai", label: "AI triage" },
  { key: "continuous", label: "Continuous scanning" },
  { key: "integrations", label: "Integrations" },
  { key: "white_label", label: "White-label" },
];

function fmtLimit(v) {
  return v == null ? "∞" : String(v);
}

// Percent-full for a bar, clamped 0..100. Unlimited (null) reads as 0 fill.
function pct(used, limit) {
  if (limit == null || limit <= 0) return 0;
  return Math.min(100, Math.round((used / limit) * 100));
}

function barFlavor(used, limit) {
  if (limit == null) return "ok";
  const p = used / limit;
  if (p >= 1) return "danger";
  if (p >= 0.75) return "warn";
  return "ok";
}

function fmtDate(iso) {
  if (!iso) return null;
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? null : d.toLocaleDateString();
}

export default function BillingPanel({ orgId }) {
  const [billing, setBilling] = useState(null); // { mode, plan, limits, usage, features }
  const [plans, setPlans] = useState([]);
  const [license, setLicense] = useState(null); // { tier, entitlements, expires_at, valid }
  const [loading, setLoading] = useState(false);
  const [loadErr, setLoadErr] = useState(null);

  const [checkoutBusy, setCheckoutBusy] = useState(null); // plan id in flight
  const [checkoutNote, setCheckoutNote] = useState(null); // Stripe-off / error note

  const [portalBusy, setPortalBusy] = useState(false);
  const [portalNote, setPortalNote] = useState(null);

  const [token, setToken] = useState("");
  const [installing, setInstalling] = useState(false);
  const [licenseErr, setLicenseErr] = useState(null);

  const load = useCallback(async () => {
    if (!orgId) {
      setBilling(null);
      setPlans([]);
      setLicense(null);
      return;
    }
    setLoading(true);
    setLoadErr(null);
    try {
      // Plans are public; billing + license are org-scoped. Fetch in parallel
      // but tolerate an individual failure (e.g. licensing endpoint disabled).
      const [b, p, l] = await Promise.all([
        fetchBilling(orgId),
        fetchPlans().catch(() => []),
        fetchLicense(orgId).catch(() => null),
      ]);
      setBilling(b);
      setPlans(Array.isArray(p) ? p : []);
      setLicense(l);
    } catch (e) {
      setLoadErr(e?.message || "Failed to load billing");
    } finally {
      setLoading(false);
    }
  }, [orgId]);

  useEffect(() => {
    load();
  }, [load]);

  const onUpgrade = useCallback(
    async (planId) => {
      if (!orgId || checkoutBusy) return;
      setCheckoutBusy(planId);
      setCheckoutNote(null);
      try {
        const res = await startCheckout(orgId, planId);
        if (res?.url) {
          window.location = res.url;
          return;
        }
        setCheckoutNote("Checkout is unavailable right now.");
      } catch (e) {
        // Stripe off / not admin / plan not purchasable — surface the reason.
        setCheckoutNote(e?.message || "Checkout is unavailable.");
      } finally {
        setCheckoutBusy(null);
      }
    },
    [orgId, checkoutBusy]
  );

  const onPortal = useCallback(async () => {
    if (!orgId || portalBusy) return;
    setPortalBusy(true);
    setPortalNote(null);
    try {
      const res = await openPortal(orgId);
      if (res?.url) {
        window.location = res.url;
        return;
      }
      setPortalNote("Billing portal is unavailable right now.");
    } catch (e) {
      setPortalNote(e?.message || "Billing portal is unavailable.");
    } finally {
      setPortalBusy(false);
    }
  }, [orgId, portalBusy]);

  const onInstall = useCallback(async () => {
    if (!orgId || !token.trim() || installing) return;
    setInstalling(true);
    setLicenseErr(null);
    try {
      const lic = await installLicense(orgId, token.trim());
      setLicense(lic);
      setToken("");
      // Entitlements may change the effective plan/limits — refresh status.
      try {
        setBilling(await fetchBilling(orgId));
      } catch {
        /* keep existing status */
      }
    } catch (e) {
      setLicenseErr(e?.message || "License token was rejected");
    } finally {
      setInstalling(false);
    }
  }, [orgId, token, installing]);

  const mode = billing?.mode || "none";
  const currentPlan = billing?.plan || "free";
  const usage = billing?.usage || {};
  const limits = billing?.limits || {};
  const features = billing?.features || {};

  return (
    <section className="panel billing-panel">
      <header className="panel-head">
        <span className="panel-title">
          <Icon name="shield" size={15} /> Billing
          {billing && (
            <span className={`bill-mode-pill pill pill-${mode === "none" ? "dim" : "ok"}`}>
              {mode === "none" ? "disabled" : mode === "self_hosted" ? "self-hosted" : "cloud"}
            </span>
          )}
        </span>
        {mode === "cloud" && (
          <div className="panel-actions">
            <button
              className="btn-ghost"
              onClick={onPortal}
              disabled={portalBusy}
              title="Open the Stripe billing portal"
            >
              {portalBusy ? (
                <>
                  <span className="rec-dot" /> Opening…
                </>
              ) : (
                <>
                  <Icon name="swap" size={14} /> Manage billing
                </>
              )}
            </button>
          </div>
        )}
      </header>

      <div className="results-body">
        {loading && !billing ? (
          <div className="muted sched-empty">Loading billing…</div>
        ) : loadErr ? (
          <div className="result-error">
            <Icon name="x" size={16} /> {loadErr}
          </div>
        ) : !billing ? (
          <div className="results-empty">
            <Icon name="shield" size={28} />
            <p>Select an organization to view its plan and usage.</p>
          </div>
        ) : (
          <>
            {mode === "none" && (
              <div className="triage-note triage-disabled">
                <Icon name="cpu" size={16} />
                <span>
                  Billing is disabled on this deployment — all limits are lifted and
                  every feature is available.
                </span>
              </div>
            )}
            {portalNote && (
              <div className="result-error triage-note">
                <Icon name="x" size={16} /> {portalNote}
              </div>
            )}

            {/* -------- Current plan + usage -------- */}
            <div className="bill-current">
              <div className="bill-current-head">
                <span className="bill-current-plan">
                  {plans.find((p) => p.id === currentPlan)?.name || currentPlan}
                </span>
                <span className="bill-current-tag">current plan</span>
              </div>

              <div className="bill-meters">
                {METERS.map((m) => {
                  const used = Number(usage[m.usageKey] || 0);
                  const limit = limits[m.limitKey];
                  return (
                    <div className="bill-meter" key={m.key}>
                      <div className="bill-meter-top">
                        <span className="bill-meter-label">
                          <Icon name={m.icon} size={12} /> {m.label}
                        </span>
                        <span className="bill-meter-val mono">
                          {used} / {fmtLimit(limit)}
                        </span>
                      </div>
                      <div className="bill-bar">
                        <div
                          className={`bill-bar-fill bar-${barFlavor(used, limit)}`}
                          style={{ width: `${pct(used, limit)}%` }}
                        />
                      </div>
                    </div>
                  );
                })}
              </div>

              <div className="bill-feats">
                {FEATURES.map((f) => (
                  <span
                    key={f.key}
                    className={`bill-feat ${features[f.key] ? "on" : "off"}`}
                    title={features[f.key] ? "Enabled" : "Not included"}
                  >
                    <Icon name={features[f.key] ? "check" : "x"} size={11} /> {f.label}
                  </span>
                ))}
              </div>
            </div>

            {/* -------- Plan catalog -------- */}
            {plans.length > 0 && (
              <>
                <div className="bill-section-label">Plans</div>
                {checkoutNote && (
                  <div className="result-error triage-note">
                    <Icon name="x" size={16} /> {checkoutNote}
                  </div>
                )}
                <div className="bill-plan-grid">
                  {plans.map((p) => {
                    const isCurrent = p.id === currentPlan;
                    return (
                      <div className={`bill-plan ${isCurrent ? "bill-plan-current" : ""}`} key={p.id}>
                        <div className="bill-plan-head">
                          <span className="bill-plan-name">{p.name}</span>
                          {isCurrent && <span className="pill pill-ok bill-plan-badge">current</span>}
                        </div>
                        <div className="bill-plan-price">
                          <b>${p.price_usd_month}</b>
                          <span className="bill-plan-per">/mo</span>
                        </div>
                        <ul className="bill-plan-limits">
                          <li>
                            <span className="mono">{fmtLimit(p.limits?.scans_per_month)}</span> scans / mo
                          </li>
                          <li>
                            <span className="mono">{fmtLimit(p.limits?.assets)}</span> assets
                          </li>
                          <li>
                            <span className="mono">{fmtLimit(p.limits?.seats)}</span> seats
                          </li>
                          {FEATURES.filter((f) => p.limits?.[f.key]).map((f) => (
                            <li key={f.key} className="bill-plan-feat">
                              <Icon name="check" size={11} /> {f.label}
                            </li>
                          ))}
                        </ul>
                        <button
                          className="btn btn-run bill-plan-btn"
                          onClick={() => onUpgrade(p.id)}
                          disabled={isCurrent || checkoutBusy === p.id || mode === "self_hosted"}
                          title={
                            mode === "self_hosted"
                              ? "Cloud checkout is disabled in self-hosted mode"
                              : isCurrent
                              ? "This is your current plan"
                              : `Upgrade to ${p.name}`
                          }
                        >
                          {checkoutBusy === p.id ? (
                            <>
                              <span className="rec-dot" /> Redirecting…
                            </>
                          ) : isCurrent ? (
                            "Current"
                          ) : (
                            <>
                              <Icon name="bolt" size={13} /> Choose {p.name}
                            </>
                          )}
                        </button>
                      </div>
                    );
                  })}
                </div>
              </>
            )}

            {/* -------- Self-hosted license -------- */}
            {(mode === "self_hosted" || license?.valid) && (
              <div className="bill-license">
                <div className="bill-section-label">Self-hosted license</div>

                {license && (
                  <div className="bill-license-status">
                    <span className={`pill pill-${license.valid ? "ok" : "dim"}`}>
                      {license.valid ? "valid" : "none"}
                    </span>
                    <span className="bill-license-tier">
                      tier <b>{license.tier || "free"}</b>
                    </span>
                    {fmtDate(license.expires_at) && (
                      <span className="bill-license-exp">
                        expires {fmtDate(license.expires_at)}
                      </span>
                    )}
                  </div>
                )}

                <textarea
                  className="bill-license-input mono"
                  placeholder="Paste your signed license token here…"
                  value={token}
                  onChange={(e) => setToken(e.target.value)}
                  rows={4}
                  spellCheck={false}
                />
                {licenseErr && (
                  <div className="result-error triage-note">
                    <Icon name="x" size={16} /> {licenseErr}
                  </div>
                )}
                <div className="bill-license-actions">
                  <button
                    className="btn btn-run bill-license-btn"
                    onClick={onInstall}
                    disabled={!token.trim() || installing}
                  >
                    {installing ? (
                      <>
                        <span className="rec-dot" /> Installing…
                      </>
                    ) : (
                      <>
                        <Icon name="shield" size={13} /> Install license
                      </>
                    )}
                  </button>
                </div>
              </div>
            )}
          </>
        )}
      </div>
    </section>
  );
}

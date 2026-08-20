import { useCallback, useEffect, useMemo, useState } from "react";
import Icon from "./Icon";
import { useAuth } from "../auth/AuthContext";
import { fetchCoverage, fetchConnectors, runPurple, fetchPurpleReport } from "../api/client";

/**
 * CoveragePanel — RECON-X Purple-Team P4 continuous-coverage dashboard.
 *
 * The blue+red rollup: "are we exposed, and would we catch it?" answered for the
 * whole workspace in one view. It renders
 *
 *   • a big coverage-% gauge (detected / validated), color-graded green→amber→red,
 *     with the emulated / detected / missed / not-validated tallies beside it;
 *   • a tactic-by-tactic ATT&CK grid — one column per tactic (kill-chain order),
 *     each technique a cell colored green=detected · red=missed · gray=not-
 *     validated · dim=not-emulated;
 *   • a detection-gaps list (techniques emulated but NOT detected — the exposure);
 *   • a small coverage trend sparkline over the workspace's validated purple runs;
 *   • a "Run purple loop" control (target + optional SIEM/EDR connector) that fires
 *     one continuous emulate→validate pass and refreshes the dashboard.
 *
 * Data:
 *   GET  /workspaces/{id}/coverage                 -> fetchCoverage   (the rollup)
 *   GET  /orgs/{org_id}/detection-connectors       -> fetchConnectors (validate picker)
 *   POST /workspaces/{id}/purple-run               -> runPurple       (the loop)
 *
 * Theming is entirely token-driven (--text / --panel / --border + the semantic
 * --ok / --warn / --danger / --info / --purple tokens), so the panel tracks the
 * app's light/dark themes with no hardcoded greys.
 */

// Cell / accent state → semantic color token. `detected` is a tri-state:
//   true  → detected (green) · false → missed (red) · null → emulated-but-not-
// validated (faint). `emulated===false` (a catalog technique never fired) → dim.
function cellToken(emulated, detected) {
  if (!emulated) return "var(--text-faint)";
  if (detected === true) return "var(--ok)";
  if (detected === false) return "var(--danger)";
  return "var(--text-faint)"; // emulated but not validated
}

// Whole-percent coverage → grade token: strong green, mid amber, low red.
function coverageToken(pct) {
  if (pct == null) return "var(--text-faint)";
  if (pct >= 80) return "var(--ok)";
  if (pct >= 40) return "var(--warn)";
  return "var(--danger)";
}

// Compact ISO → local timestamp for the trend / run meta.
function fmtWhen(iso) {
  if (!iso) return "";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "";
  return d.toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

// A circular coverage gauge (SVG ring). `pct` may be null (nothing validated).
function CoverageGauge({ pct }) {
  const known = pct != null;
  const value = known ? Math.max(0, Math.min(100, pct)) : 0;
  const R = 42;
  const C = 2 * Math.PI * R;
  const dash = (value / 100) * C;
  const color = coverageToken(known ? pct : null);
  return (
    <div className="cov-gauge" title={known ? `${value}% of validated techniques detected` : "No techniques validated yet"}>
      <svg viewBox="0 0 100 100" className="cov-gauge-svg" aria-hidden="true">
        <circle cx="50" cy="50" r={R} className="cov-gauge-track" />
        <circle
          cx="50"
          cy="50"
          r={R}
          className="cov-gauge-arc"
          style={{
            stroke: color,
            strokeDasharray: `${dash} ${C}`,
          }}
        />
      </svg>
      <div className="cov-gauge-center">
        <span className="cov-gauge-pct" style={{ color }}>
          {known ? `${value}%` : "—"}
        </span>
        <span className="cov-gauge-label">detected</span>
      </div>
    </div>
  );
}

// A tiny sparkline of per-run coverage_pct over time. Renders nothing for <2 pts.
function TrendSparkline({ trend }) {
  const pts = (trend || []).map((t) => t.coverage_pct ?? 0);
  if (pts.length < 2) return null;
  const W = 220;
  const H = 44;
  const pad = 4;
  const max = 100;
  const min = 0;
  const stepX = (W - pad * 2) / (pts.length - 1);
  const y = (v) => H - pad - ((v - min) / (max - min)) * (H - pad * 2);
  const d = pts
    .map((v, i) => `${i === 0 ? "M" : "L"} ${(pad + i * stepX).toFixed(1)} ${y(v).toFixed(1)}`)
    .join(" ");
  const last = pts[pts.length - 1];
  const color = coverageToken(last);
  return (
    <div className="cov-trend">
      <div className="cov-trend-head">
        <span className="cov-sub-title">Coverage trend</span>
        <span className="cov-trend-latest" style={{ color }}>{last}%</span>
      </div>
      <svg viewBox={`0 0 ${W} ${H}`} className="cov-trend-svg" preserveAspectRatio="none">
        <line x1={pad} y1={y(50)} x2={W - pad} y2={y(50)} className="cov-trend-mid" />
        <path d={d} className="cov-trend-line" style={{ stroke: color }} />
        <circle cx={pad + (pts.length - 1) * stepX} cy={y(last)} r="2.6" style={{ fill: color }} />
      </svg>
      <div className="cov-trend-foot">
        <span>{fmtWhen(trend[0]?.at)}</span>
        <span>{trend.length} run{trend.length === 1 ? "" : "s"}</span>
        <span>{fmtWhen(trend[trend.length - 1]?.at)}</span>
      </div>
    </div>
  );
}

export default function CoveragePanel({ workspaceId }) {
  const { activeOrg } = useAuth();
  const orgId = activeOrg?.id ?? null;

  const [cov, setCov] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  // --- Run-purple-loop control state ---------------------------------------- //
  const [target, setTarget] = useState("");
  const [connectors, setConnectors] = useState([]);
  const [connectorId, setConnectorId] = useState(""); // "" == emulate-only
  const [running, setRunning] = useState(false);
  const [runError, setRunError] = useState(null);
  const [lastRun, setLastRun] = useState(null); // { summary, drift } of the last loop

  // Purple-team report (opens the rendered HTML in a new tab, auth-carried).
  const [reporting, setReporting] = useState(false);
  const onReport = useCallback(async () => {
    if (!workspaceId || reporting) return;
    setReporting(true);
    try {
      await fetchPurpleReport(workspaceId);
    } catch (e) {
      setRunError(e?.message || "Could not open the purple-team report.");
    } finally {
      setReporting(false);
    }
  }, [workspaceId, reporting]);

  // Load the coverage rollup for the active workspace.
  const load = useCallback(async (wsId) => {
    if (!wsId) {
      setCov(null);
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const data = await fetchCoverage(wsId);
      setCov(data);
    } catch (e) {
      setError(e?.message || "Could not load coverage dashboard.");
      setCov(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    setCov(null);
    setError(null);
    setLastRun(null);
    setRunError(null);
    if (workspaceId) load(workspaceId);
  }, [workspaceId, load]);

  // Load the org's detection connectors (optional validate picker).
  useEffect(() => {
    if (!orgId) {
      setConnectors([]);
      return;
    }
    let alive = true;
    (async () => {
      try {
        const list = await fetchConnectors(orgId);
        if (!alive) return;
        const arr = Array.isArray(list) ? list : [];
        setConnectors(arr);
        setConnectorId((prev) => {
          if (prev && arr.some((c) => String(c.id) === prev)) return prev;
          const pick = arr.find((c) => c.enabled) || arr[0];
          return pick ? String(pick.id) : "";
        });
      } catch {
        /* connectors optional — the loop still runs emulate-only */
      }
    })();
    return () => {
      alive = false;
    };
  }, [orgId]);

  const onRun = useCallback(async () => {
    const t = target.trim();
    if (!t || !workspaceId || running) return;
    setRunning(true);
    setRunError(null);
    try {
      const out = await runPurple(workspaceId, {
        target: t,
        connector_id: connectorId || undefined,
      });
      setLastRun({ summary: out?.summary || null, drift: out?.drift || null });
      await load(workspaceId); // refresh the rollup with the new run
    } catch (e) {
      setRunError(e?.message || "Purple run failed.");
    } finally {
      setRunning(false);
    }
  }, [target, workspaceId, connectorId, running, load]);

  const summary = cov?.summary || null;
  const tactics = cov?.tactics || [];
  const techniques = cov?.techniques || [];
  const trend = cov?.trend || [];
  const gaps = cov?.gaps || [];

  // Group emulated techniques under their tactic for the ATT&CK grid columns.
  const byTactic = useMemo(() => {
    const m = new Map();
    for (const tech of techniques) {
      const key = tech.tactic || "";
      if (!m.has(key)) m.set(key, []);
      m.get(key).push(tech);
    }
    return m;
  }, [techniques]);

  const hasData = techniques.length > 0;

  return (
    <section className="panel cov-panel">
      <style>{COV_CSS}</style>
      <header className="panel-head">
        <span className="panel-title">
          <Icon name="radar" size={15} /> Coverage Dashboard
        </span>
        <button
          className="cov-report-btn"
          onClick={onReport}
          disabled={reporting || !workspaceId}
          title="Open the workspace's purple-team HTML report in a new tab"
        >
          {reporting ? (
            <>
              <span className="rec-dot" /> Report…
            </>
          ) : (
            <>
              <Icon name="report" size={13} /> Purple-team report
            </>
          )}
        </button>
        {summary && (
          <div className="cov-head-tallies">
            <span className="pill pill-info" title="Techniques with attributable telemetry">
              {summary.techniques_emulated} emulated
            </span>
            <span className="pill pill-ok" title="Detected by a connector">
              {summary.detected} detected
            </span>
            <span className="pill pill-danger" title="Emulated but missed — the exposure">
              {summary.missed} missed
            </span>
            <span className="pill pill-dim" title="Emulated but never validated">
              {summary.not_validated} unvalidated
            </span>
          </div>
        )}
      </header>

      <div className="results-body cov-body">
        {/* Run-purple-loop control */}
        <div className="cov-run">
          <div className="cov-run-label">
            <Icon name="bolt" size={14} /> Run purple loop
          </div>
          <div className="cov-run-row">
            <input
              className="cov-target-input"
              type="text"
              placeholder="https://target.com  or  target.com"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && !running && onRun()}
              disabled={running || !workspaceId}
              autoComplete="off"
              spellCheck={false}
            />
            <select
              className="cov-connector-select"
              value={connectorId}
              onChange={(e) => setConnectorId(e.target.value)}
              disabled={running}
              aria-label="Detection connector"
              title="Validate against this SIEM/EDR — or emulate only"
            >
              <option value="">Emulate only (no validation)</option>
              {connectors.map((c) => (
                <option key={c.id} value={String(c.id)} disabled={!c.enabled}>
                  {c.name} ({c.ctype}){c.enabled ? "" : " — disabled"}
                </option>
              ))}
            </select>
            <button
              className="cov-run-btn"
              onClick={onRun}
              disabled={running || !target.trim() || !workspaceId}
            >
              {running ? (
                <>
                  <span className="rec-dot" /> Running…
                </>
              ) : (
                <>
                  <Icon name="radar" size={13} /> Run loop
                </>
              )}
            </button>
          </div>
          <p className="cov-run-hint">
            Fires one continuous <b>emulate → validate</b> pass — SAFE, non-destructive
            telemetry, then asks the connector whether each technique was caught. Scope +
            SSRF + quota are checked before anything runs.
          </p>
          {runError && (
            <div className="result-error cov-error">
              <Icon name="x" size={16} /> {runError}
            </div>
          )}
          {lastRun?.summary && (
            <div className="cov-lastrun">
              <span className="cov-lastrun-target mono">{lastRun.summary.target}</span>
              <span className="pill pill-info">{lastRun.summary.executed} executed</span>
              <span className="pill pill-warn">{lastRun.summary.blocked} blocked</span>
              {lastRun.summary.coverage_pct != null ? (
                <span
                  className="cov-lastrun-cov"
                  style={{
                    color: coverageToken(lastRun.summary.coverage_pct),
                    borderColor: coverageToken(lastRun.summary.coverage_pct),
                  }}
                >
                  {lastRun.summary.coverage_pct}% detected
                </span>
              ) : (
                <span className="cov-lastrun-note">emulate-only (no connector)</span>
              )}
            </div>
          )}
          {lastRun?.drift && (
            <div className="cov-drift">
              <Icon name="shield" size={15} />
              <span>
                <b>Detection drift:</b>{" "}
                {lastRun.drift.message ||
                  `coverage ${lastRun.drift.coverage_before ?? "?"}% → ${
                    lastRun.drift.coverage_after ?? "?"
                  }%`}
                {Array.isArray(lastRun.drift.regressions) && lastRun.drift.regressions.length > 0 && (
                  <> · {lastRun.drift.regressions.length} regression
                    {lastRun.drift.regressions.length === 1 ? "" : "s"}</>
                )}
              </span>
            </div>
          )}
        </div>

        {/* Dashboard body */}
        {loading ? (
          <div className="results-empty">
            <span className="rec-dot" />
            <p>Loading coverage…</p>
          </div>
        ) : error ? (
          <div className="results-empty">
            <Icon name="x" size={28} />
            <p>{error}</p>
          </div>
        ) : !hasData ? (
          <div className="results-empty">
            <Icon name="radar" size={28} />
            <p>
              No emulation coverage yet. Run a purple loop above (or the Emulate tab) to
              generate SAFE ATT&amp;CK telemetry, then validate it against a connector to
              light up this dashboard.
            </p>
          </div>
        ) : (
          <>
            {/* Gauge + trend row */}
            <div className="cov-top">
              <CoverageGauge pct={summary?.coverage_pct ?? null} />
              <div className="cov-top-right">
                <div className="cov-stat-grid">
                  <div className="cov-stat">
                    <span className="cov-stat-val" style={{ color: "var(--info)" }}>
                      {summary?.techniques_emulated ?? 0}
                    </span>
                    <span className="cov-stat-label">Emulated</span>
                  </div>
                  <div className="cov-stat">
                    <span className="cov-stat-val" style={{ color: "var(--ok)" }}>
                      {summary?.detected ?? 0}
                    </span>
                    <span className="cov-stat-label">Detected</span>
                  </div>
                  <div className="cov-stat">
                    <span className="cov-stat-val" style={{ color: "var(--danger)" }}>
                      {summary?.missed ?? 0}
                    </span>
                    <span className="cov-stat-label">Missed</span>
                  </div>
                  <div className="cov-stat">
                    <span className="cov-stat-val" style={{ color: "var(--text-faint)" }}>
                      {summary?.not_validated ?? 0}
                    </span>
                    <span className="cov-stat-label">Unvalidated</span>
                  </div>
                </div>
                <TrendSparkline trend={trend} />
              </div>
            </div>

            {/* Legend */}
            <div className="cov-legend">
              <span className="cov-legend-item"><i style={{ background: "var(--ok)" }} /> Detected</span>
              <span className="cov-legend-item"><i style={{ background: "var(--danger)" }} /> Missed</span>
              <span className="cov-legend-item"><i className="cov-legend-open" style={{ borderColor: "var(--text-faint)" }} /> Not validated</span>
              <span className="cov-legend-item cov-legend-dim"><i className="cov-legend-dim-dot" /> Not emulated</span>
            </div>

            {/* Tactic-by-tactic ATT&CK grid */}
            <div className="cov-grid">
              {tactics.map((tac) => {
                const cells = byTactic.get(tac.tactic) || [];
                const covPct =
                  tac.detected + tac.missed > 0
                    ? Math.round((100 * tac.detected) / (tac.detected + tac.missed))
                    : null;
                return (
                  <div className="cov-col" key={tac.tactic || "unmapped"}>
                    <div className="cov-col-head">
                      <span className="cov-tactic-name">{tac.name}</span>
                      <span className="cov-tactic-meta">
                        <span className="cov-tactic-total">{tac.total}</span>
                        {covPct != null && (
                          <span className="cov-tactic-pct" style={{ color: coverageToken(covPct) }}>
                            {covPct}%
                          </span>
                        )}
                      </span>
                    </div>
                    <div className="cov-col-body">
                      {cells.map((tech) => {
                        const color = cellToken(tech.emulated, tech.detected);
                        const state =
                          tech.detected === true
                            ? "detected"
                            : tech.detected === false
                            ? "missed"
                            : "not validated";
                        return (
                          <div
                            className="cov-cell"
                            key={tech.technique_id}
                            style={{ "--cell": color }}
                            title={`${tech.technique_id} · ${tech.name} — ${state}${
                              tech.last_at ? ` · last ${fmtWhen(tech.last_at)}` : ""
                            }`}
                          >
                            <span className="cov-cell-dot" />
                            <span className="cov-cell-id">{tech.technique_id}</span>
                            <span className="cov-cell-name">{tech.name}</span>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                );
              })}
            </div>

            {/* Detection gaps */}
            <div className="cov-gaps">
              <div className="cov-sub-title">
                Detection gaps
                {gaps.length > 0 && <span className="cov-gaps-count">{gaps.length}</span>}
              </div>
              {gaps.length === 0 ? (
                <div className="cov-gaps-clean">
                  <Icon name="shield" size={15} /> No open gaps — every emulated technique
                  that was validated is being detected.
                </div>
              ) : (
                <div className="cov-gaps-list">
                  {gaps.map((g) => (
                    <div className="cov-gap" key={g.technique_id}>
                      <span className="cov-gap-id">{g.technique_id}</span>
                      <span className="cov-gap-name">{g.name}</span>
                      <span className="cov-gap-tactic">{g.tactic}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </>
        )}
      </div>
    </section>
  );
}

// Component-scoped styles — every color references a theme token (no hardcoded
// greys), so the panel tracks the app's light/dark themes.
const COV_CSS = `
.cov-body { padding: 14px; display: flex; flex-direction: column; gap: 14px; }
.cov-head-tallies { display: inline-flex; gap: 6px; flex-wrap: wrap; }
.cov-report-btn {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 6px 12px;
  border-radius: var(--radius-sm);
  border: 1px solid var(--purple);
  background: var(--panel);
  color: var(--purple);
  font-size: 12px;
  font-weight: 600;
  white-space: nowrap;
  transition: opacity 0.15s, background 0.15s, transform 0.15s;
}
.cov-report-btn:hover:not(:disabled) { background: var(--purple); color: #04211d; transform: translateY(-1px); }
.cov-report-btn:disabled { opacity: 0.45; cursor: not-allowed; transform: none; }
.cov-report-btn .rec-dot { background: currentColor; }

/* --- Run purple loop control --------------------------------------------- */
.cov-run {
  display: flex;
  flex-direction: column;
  gap: 9px;
  padding: 12px 13px;
  border-radius: var(--radius-sm);
  background: var(--accent-glow);
  border: 1px solid var(--border);
}
.cov-run-label {
  display: inline-flex;
  align-items: center;
  gap: 7px;
  font-size: 12.5px;
  font-weight: 600;
  color: var(--text);
}
.cov-run-label svg { color: var(--accent); }
.cov-run-row { display: flex; gap: 8px; flex-wrap: wrap; }
.cov-target-input {
  flex: 1;
  min-width: 180px;
  padding: 9px 12px;
  border-radius: var(--radius-sm);
  border: 1px solid var(--border);
  background: var(--panel);
  color: var(--text);
  font-size: 13px;
  font-family: var(--font-mono);
  outline: none;
  transition: border-color 0.15s;
}
.cov-target-input:focus { border-color: var(--accent); }
.cov-target-input:disabled { opacity: 0.55; cursor: not-allowed; }
.cov-connector-select {
  padding: 9px 10px;
  border-radius: var(--radius-sm);
  border: 1px solid var(--border);
  background: var(--panel);
  color: var(--text);
  font-size: 12.5px;
  outline: none;
  max-width: 100%;
}
.cov-connector-select:focus { border-color: var(--accent); }
.cov-connector-select:disabled { opacity: 0.55; cursor: not-allowed; }
.cov-run-btn {
  display: inline-flex;
  align-items: center;
  gap: 7px;
  padding: 9px 16px;
  border-radius: var(--radius-sm);
  background: var(--accent);
  color: #04211d;
  font-size: 13px;
  font-weight: 600;
  white-space: nowrap;
  transition: opacity 0.15s, transform 0.15s;
}
.cov-run-btn:hover:not(:disabled) { opacity: 0.9; transform: translateY(-1px); }
.cov-run-btn:disabled { opacity: 0.45; cursor: not-allowed; transform: none; }
.cov-run-btn .rec-dot { background: #04211d; }
.cov-run-hint { margin: 0; font-size: 11.5px; color: var(--text-dim); line-height: 1.5; }
.cov-run-hint b { color: var(--text); }
.cov-error { margin: 0; }
.cov-lastrun {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
  padding-top: 2px;
}
.cov-lastrun-target { font-size: 12px; color: var(--accent); word-break: break-all; }
.cov-lastrun-cov {
  font-size: 12px;
  font-weight: 700;
  padding: 2px 9px;
  border-radius: 999px;
  border: 1px solid;
  font-variant-numeric: tabular-nums;
}
.cov-lastrun-note { font-size: 11.5px; color: var(--text-faint); }
.cov-drift {
  display: flex;
  align-items: flex-start;
  gap: 8px;
  padding: 9px 11px;
  border-radius: var(--radius-sm);
  border: 1px solid var(--warn);
  background: var(--panel);
  color: var(--text-dim);
  font-size: 12px;
  line-height: 1.5;
}
.cov-drift b { color: var(--warn); }
.cov-drift svg { color: var(--warn); flex: 0 0 auto; margin-top: 1px; }

/* --- Gauge + stats + trend ------------------------------------------------ */
.cov-top {
  display: flex;
  gap: 16px;
  align-items: center;
  flex-wrap: wrap;
  padding: 4px 2px;
}
.cov-gauge { position: relative; width: 120px; height: 120px; flex: 0 0 auto; }
.cov-gauge-svg { width: 120px; height: 120px; transform: rotate(-90deg); }
.cov-gauge-track {
  fill: none;
  stroke: var(--border);
  stroke-width: 9;
}
.cov-gauge-arc {
  fill: none;
  stroke-width: 9;
  stroke-linecap: round;
  transition: stroke-dasharray 0.5s ease, stroke 0.3s ease;
}
.cov-gauge-center {
  position: absolute;
  inset: 0;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 1px;
}
.cov-gauge-pct { font-size: 26px; font-weight: 700; font-variant-numeric: tabular-nums; line-height: 1; }
.cov-gauge-label {
  font-size: 10px;
  text-transform: uppercase;
  letter-spacing: 0.09em;
  color: var(--text-faint);
}
.cov-top-right { flex: 1; min-width: 240px; display: flex; flex-direction: column; gap: 12px; }
.cov-stat-grid {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 8px;
}
.cov-stat {
  display: flex;
  flex-direction: column;
  gap: 2px;
  padding: 8px 6px;
  border-radius: var(--radius-sm);
  border: 1px solid var(--border-soft);
  background: var(--bg-elev);
  text-align: center;
}
.cov-stat-val { font-size: 19px; font-weight: 700; font-variant-numeric: tabular-nums; line-height: 1; }
.cov-stat-label {
  font-size: 10px;
  text-transform: uppercase;
  letter-spacing: 0.06em;
  color: var(--text-faint);
}

.cov-trend {
  border-radius: var(--radius-sm);
  border: 1px solid var(--border-soft);
  background: var(--bg-elev);
  padding: 9px 11px;
}
.cov-trend-head { display: flex; align-items: baseline; justify-content: space-between; }
.cov-sub-title {
  font-size: 11px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  color: var(--text-faint);
  display: inline-flex;
  align-items: center;
  gap: 7px;
}
.cov-trend-latest { font-size: 13px; font-weight: 700; font-variant-numeric: tabular-nums; }
.cov-trend-svg { width: 100%; height: 44px; margin-top: 4px; display: block; }
.cov-trend-mid { stroke: var(--border); stroke-width: 1; stroke-dasharray: 3 3; }
.cov-trend-line { fill: none; stroke-width: 2; stroke-linejoin: round; stroke-linecap: round; }
.cov-trend-foot {
  display: flex;
  justify-content: space-between;
  margin-top: 3px;
  font-size: 10px;
  color: var(--text-faint);
}

/* --- Legend --------------------------------------------------------------- */
.cov-legend {
  display: flex;
  gap: 14px;
  flex-wrap: wrap;
  padding: 8px 10px;
  border-radius: var(--radius-sm);
  border: 1px solid var(--border-soft);
  background: var(--panel-2);
}
.cov-legend-item {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  font-size: 11.5px;
  color: var(--text-dim);
}
.cov-legend-item i { width: 11px; height: 11px; border-radius: 3px; display: inline-block; }
.cov-legend-open { background: transparent !important; border: 1.5px solid var(--text-faint); }
.cov-legend-dim { color: var(--text-faint); }
.cov-legend-dim-dot {
  background: var(--border) !important;
  opacity: 0.6;
}

/* --- ATT&CK grid ---------------------------------------------------------- */
.cov-grid {
  display: flex;
  gap: 12px;
  align-items: flex-start;
  overflow-x: auto;
  padding-bottom: 6px;
}
.cov-col {
  flex: 0 0 200px;
  min-width: 200px;
  display: flex;
  flex-direction: column;
  gap: 8px;
}
.cov-col-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 6px;
  padding: 8px 10px;
  border-radius: var(--radius-sm);
  background: var(--bg-elev);
  border: 1px solid var(--border-soft);
  border-top: 2px solid var(--purple);
  position: sticky;
  top: 0;
}
.cov-tactic-name {
  font-size: 12px;
  font-weight: 600;
  color: var(--text);
  text-transform: capitalize;
  line-height: 1.3;
}
.cov-tactic-meta { display: inline-flex; align-items: center; gap: 7px; flex: 0 0 auto; }
.cov-tactic-total {
  font-size: 11px;
  font-weight: 700;
  color: var(--text-faint);
  font-variant-numeric: tabular-nums;
}
.cov-tactic-pct { font-size: 11px; font-weight: 700; font-variant-numeric: tabular-nums; }
.cov-col-body { display: flex; flex-direction: column; gap: 7px; }
.cov-cell {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px 10px;
  border-radius: var(--radius-sm);
  background: var(--panel);
  border: 1px solid var(--border);
  border-left: 3px solid var(--cell);
  animation: fadeIn 0.18s ease;
}
.cov-cell-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: var(--cell);
  flex: 0 0 auto;
}
.cov-cell-id {
  font-family: var(--font-mono);
  font-size: 11px;
  font-weight: 700;
  color: var(--cell);
  letter-spacing: 0.02em;
  flex: 0 0 auto;
}
.cov-cell-name {
  font-size: 12px;
  color: var(--text-dim);
  line-height: 1.3;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

/* --- Detection gaps ------------------------------------------------------- */
.cov-gaps {
  border-top: 1px solid var(--border-soft);
  padding-top: 12px;
  display: flex;
  flex-direction: column;
  gap: 8px;
}
.cov-gaps-count {
  font-family: var(--font-mono);
  font-size: 10.5px;
  font-weight: 700;
  color: var(--danger);
  background: var(--panel-2);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 1px 7px;
}
.cov-gaps-clean {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  font-size: 12.5px;
  color: var(--ok);
}
.cov-gaps-list { display: flex; flex-direction: column; gap: 6px; }
.cov-gap {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 8px 11px;
  border-radius: var(--radius-sm);
  background: var(--panel);
  border: 1px solid var(--border);
  border-left: 3px solid var(--danger);
}
.cov-gap-id {
  font-family: var(--font-mono);
  font-size: 11.5px;
  font-weight: 700;
  color: var(--danger);
  flex: 0 0 auto;
}
.cov-gap-name { font-size: 12.5px; color: var(--text); flex: 1; word-break: break-word; }
.cov-gap-tactic {
  font-size: 10.5px;
  text-transform: capitalize;
  letter-spacing: 0.03em;
  color: var(--text-faint);
  flex: 0 0 auto;
}
`;

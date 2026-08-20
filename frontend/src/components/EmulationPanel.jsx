import { useCallback, useEffect, useMemo, useState } from "react";
import Icon from "./Icon";
import { useAuth } from "../auth/AuthContext";
import {
  runEmulation,
  fetchEmulations,
  fetchEmulation,
  fetchConnectors,
  validateEmulation,
  fetchDetections,
} from "../api/client";

/**
 * EmulationPanel — RECON-X Purple-Team P2 (SAFE ATT&CK emulation).
 *
 * A target input + "Run Emulation" button that fires a set of SAFE, entirely
 * non-destructive ATT&CK technique emulations (E1..E5) at an authorized target
 * and renders each technique as a card: ATT&CK id + name + tactic + a status
 * pill + the recorded evidence/detail. The point is to generate the telemetry a
 * real attack would — so blue-team detections can later be validated — WITHOUT
 * exploiting or mutating the target.
 *
 * Purple-Team P3 (blue side): once a run is shown, an operator can pick an org
 * SIEM/EDR connector and "Validate detection" — RECON-X asks the defender whether
 * each emulated technique was detected, then renders a coverage % summary + a
 * detected/missed pill on every technique card. Prior verdicts are rehydrated
 * from the run's persisted detections on open.
 *
 * Data:
 *   POST /workspaces/{id}/emulate      -> runEmulation      (the fresh run)
 *   GET  /workspaces/{id}/emulations   -> fetchEmulations    (past-runs list)
 *   GET  /emulations/{run_id}          -> fetchEmulation     (a selected past run)
 *   GET  /orgs/{org_id}/detection-connectors -> fetchConnectors (validation picker)
 *   POST /emulations/{run_id}/validate?connector_id=... -> validateEmulation
 *   GET  /emulations/{run_id}/detections -> fetchDetections  (rehydrate verdicts)
 *
 * Status → pill flavor:
 *   executed -> info  · blocked -> warn (a WAF/target refusal is a useful signal)
 *   failed   -> danger · skipped -> dim
 *
 * Theming is token-driven (--text / --panel / --border + the semantic
 * --info/--warn/--danger tokens via the shared .pill-* classes), so the panel
 * tracks the app's light/dark themes with no hardcoded greys.
 */

// Map an emulation technique status to one of the app's shared pill flavors.
function statusFlavor(status) {
  switch ((status || "").toLowerCase()) {
    case "executed":
      return "info";
    case "blocked":
      return "warn";
    case "failed":
      return "danger";
    default: // skipped / unknown
      return "dim";
  }
}

// Left-accent color token for a technique card, keyed off its status.
function statusToken(status) {
  switch ((status || "").toLowerCase()) {
    case "executed":
      return "var(--info)";
    case "blocked":
      return "var(--warn)";
    case "failed":
      return "var(--danger)";
    default:
      return "var(--text-faint)";
  }
}

// Format an ISO timestamp compactly for the past-runs list.
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

// Compute a coverage summary from persisted DetectionResultOut[] — used to
// prehydrate the summary badge when reopening a run (the backend only returns a
// summary from the /validate call). Mirrors the backend's coverage_pct math.
function summarize(results) {
  const total = results.length;
  const detected = results.filter((r) => r.detected).length;
  return {
    total,
    detected,
    missed: total - detected,
    coverage_pct: total === 0 ? 0 : Math.round((100 * detected) / total),
    source: results.find((r) => r.source)?.source || "",
  };
}

// Semantic token for a coverage percentage: green when strong, amber mid, red low.
function coverageToken(pct) {
  if (pct >= 80) return "var(--ok)";
  if (pct >= 40) return "var(--warn)";
  return "var(--danger)";
}

export default function EmulationPanel({ workspaceId }) {
  const { activeOrg } = useAuth();
  const orgId = activeOrg?.id ?? null;

  const [target, setTarget] = useState("");
  const [run, setRun] = useState(null); // the currently-displayed EmulationRunOut
  const [runs, setRuns] = useState([]); // past-runs list (summaries)
  const [running, setRunning] = useState(false);
  const [loadingRun, setLoadingRun] = useState(false);
  const [error, setError] = useState(null);

  // --- Purple-Team P3: detection validation state --------------------------- //
  const [connectors, setConnectors] = useState([]); // org's DetectionConnectorOut[]
  const [connectorId, setConnectorId] = useState(""); // selected connector id (string)
  const [validating, setValidating] = useState(false);
  const [detResults, setDetResults] = useState([]); // DetectionResultOut[] for this run
  const [detSummary, setDetSummary] = useState(null); // DetectionSummaryOut | null
  const [detError, setDetError] = useState(null);

  // Load the past-runs list whenever the workspace changes.
  const loadRuns = useCallback(async (wsId) => {
    if (!wsId) {
      setRuns([]);
      return;
    }
    try {
      const list = await fetchEmulations(wsId);
      setRuns(Array.isArray(list) ? list : []);
    } catch {
      /* backend may be momentarily unavailable */
    }
  }, []);

  useEffect(() => {
    setRun(null);
    setError(null);
    setRuns([]);
    setDetResults([]);
    setDetSummary(null);
    setDetError(null);
    if (workspaceId) loadRuns(workspaceId);
  }, [workspaceId, loadRuns]);

  // Load the org's detection connectors (for the validation picker).
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
        // Default-select the first enabled connector (or first overall).
        setConnectorId((prev) => {
          if (prev && arr.some((c) => String(c.id) === prev)) return prev;
          const pick = arr.find((c) => c.enabled) || arr[0];
          return pick ? String(pick.id) : "";
        });
      } catch {
        /* connectors are optional — validation control just stays empty */
      }
    })();
    return () => {
      alive = false;
    };
  }, [orgId]);

  // Whenever the displayed run changes, clear stale detection state and load any
  // previously-persisted detection results for that run.
  const loadDetections = useCallback(async (runId) => {
    setDetError(null);
    setDetSummary(null);
    if (!runId) {
      setDetResults([]);
      return;
    }
    try {
      const list = await fetchDetections(runId);
      const arr = Array.isArray(list) ? list : [];
      setDetResults(arr);
      setDetSummary(arr.length ? summarize(arr) : null);
    } catch {
      setDetResults([]);
    }
  }, []);

  useEffect(() => {
    loadDetections(run?.id ?? null);
  }, [run?.id, loadDetections]);

  // Run the selected connector against the current run, then show the verdicts.
  const onValidate = useCallback(async () => {
    if (!run?.id || !connectorId || validating) return;
    setValidating(true);
    setDetError(null);
    try {
      const out = await validateEmulation(run.id, connectorId);
      const results = Array.isArray(out?.results) ? out.results : [];
      setDetResults(results);
      setDetSummary(out?.summary || summarize(results));
    } catch (e) {
      setDetError(e?.message || "Detection validation failed.");
    } finally {
      setValidating(false);
    }
  }, [run?.id, connectorId, validating]);

  // Map technique_id -> detection verdict, so each technique card can show a
  // detected/missed pill. Newer entries win (validate re-persists per technique).
  const detByTech = useMemo(() => {
    const m = new Map();
    for (const d of detResults) m.set(d.technique_id, d);
    return m;
  }, [detResults]);

  const onRun = useCallback(async () => {
    const t = target.trim();
    if (!t || !workspaceId || running) return;
    setRunning(true);
    setError(null);
    try {
      const result = await runEmulation(workspaceId, { target: t });
      setRun(result);
      loadRuns(workspaceId); // refresh the history with the new run
    } catch (e) {
      setError(e?.message || "Emulation failed.");
    } finally {
      setRunning(false);
    }
  }, [target, workspaceId, running, loadRuns]);

  const openRun = useCallback(async (runId) => {
    if (!runId || loadingRun) return;
    setLoadingRun(true);
    setError(null);
    try {
      const full = await fetchEmulation(runId);
      setRun(full);
    } catch (e) {
      setError(e?.message || "Could not load that run.");
    } finally {
      setLoadingRun(false);
    }
  }, [loadingRun]);

  const results = run?.technique_results || [];

  return (
    <section className="panel emu-panel">
      <style>{EMU_CSS}</style>
      <header className="panel-head">
        <span className="panel-title">
          <Icon name="shield" size={15} /> ATT&amp;CK Emulation
        </span>
        {run && (
          <div className="emu-tallies">
            <span className="pill pill-info" title="Techniques that executed">
              {run.executed ?? 0} executed
            </span>
            <span className="pill pill-warn" title="Refused by the target/WAF — a detection signal">
              {run.blocked ?? 0} blocked
            </span>
            <span className="pill pill-danger" title="Techniques that errored">
              {run.failed ?? 0} failed
            </span>
          </div>
        )}
      </header>

      <div className="results-body emu-body">
        {/* Safety banner */}
        <div className="emu-banner">
          <Icon name="shield" size={16} />
          <span>
            These are <b>SAFE, non-destructive</b> emulations — they generate the
            telemetry a real attack would (so defenses can be validated) without
            exploiting or altering the target. Scope + SSRF checked before running.
          </span>
        </div>

        {/* Input row */}
        <div className="emu-input-row">
          <input
            className="emu-target-input"
            type="text"
            placeholder="https://target.com  or  target.com"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && !running && onRun()}
            disabled={running || !workspaceId}
            autoComplete="off"
            spellCheck={false}
          />
          <button
            className="emu-run-btn"
            onClick={onRun}
            disabled={running || !target.trim() || !workspaceId}
          >
            {running ? (
              <>
                <span className="rec-dot" /> Emulating…
              </>
            ) : (
              <>
                <Icon name="bolt" size={14} /> Run Emulation
              </>
            )}
          </button>
        </div>

        {error && (
          <div className="result-error emu-error">
            <Icon name="x" size={16} /> {error}
          </div>
        )}

        {/* Results / empty / loading */}
        {loadingRun ? (
          <div className="results-empty">
            <span className="rec-dot" />
            <p>Loading run…</p>
          </div>
        ) : run ? (
          <>
            <div className="emu-run-meta">
              <span className="emu-run-target mono">{run.target}</span>
              {run.finished_at && (
                <span className="emu-run-when">{fmtWhen(run.finished_at || run.created_at)}</span>
              )}
            </div>

            {/* Purple-Team P3 — detection validation (blue side) */}
            <div className="emu-validate">
              <div className="emu-validate-row">
                <span className="emu-validate-label">
                  <Icon name="radar" size={14} /> Validate detection
                </span>
                {connectors.length === 0 ? (
                  <span className="emu-validate-hint">
                    No SIEM/EDR connectors — add one in Settings › Detection.
                  </span>
                ) : (
                  <>
                    <select
                      className="emu-connector-select"
                      value={connectorId}
                      onChange={(e) => setConnectorId(e.target.value)}
                      disabled={validating}
                      aria-label="Detection connector"
                    >
                      {connectors.map((c) => (
                        <option key={c.id} value={String(c.id)}>
                          {c.name} ({c.ctype}){c.enabled ? "" : " — disabled"}
                        </option>
                      ))}
                    </select>
                    <button
                      className="emu-validate-btn"
                      onClick={onValidate}
                      disabled={validating || !connectorId}
                    >
                      {validating ? (
                        <>
                          <span className="rec-dot" /> Validating…
                        </>
                      ) : (
                        <>
                          <Icon name="radar" size={13} /> Validate
                        </>
                      )}
                    </button>
                  </>
                )}
                {detSummary && (
                  <span
                    className="emu-coverage"
                    style={{
                      color: coverageToken(detSummary.coverage_pct),
                      borderColor: coverageToken(detSummary.coverage_pct),
                    }}
                    title={`${detSummary.detected}/${detSummary.total} techniques detected`}
                  >
                    {detSummary.coverage_pct}% detected
                  </span>
                )}
              </div>
              {detSummary && (
                <div className="emu-validate-tallies">
                  <span className="pill pill-ok" title="Detected by the connector">
                    {detSummary.detected} detected
                  </span>
                  <span className="pill pill-danger" title="Missed — no detection">
                    {detSummary.missed} missed
                  </span>
                  {detSummary.source && (
                    <span className="emu-validate-source mono">via {detSummary.source}</span>
                  )}
                </div>
              )}
              {detError && (
                <div className="result-error emu-error">
                  <Icon name="x" size={16} /> {detError}
                </div>
              )}
            </div>

            {results.length === 0 ? (
              <div className="results-empty">
                <Icon name="shield" size={28} />
                <p>This run recorded no technique results.</p>
              </div>
            ) : (
              <div className="emu-cards">
                {results.map((r) => {
                  const accent = statusToken(r.status);
                  const det = detByTech.get(r.technique_id);
                  return (
                    <div
                      className="emu-card"
                      key={r.id ?? `${r.technique_id}-${r.tactic}`}
                      style={{ borderLeftColor: accent }}
                    >
                      <div className="emu-card-head">
                        <span className="emu-tech-id" style={{ color: accent }}>
                          {r.technique_id}
                        </span>
                        <span className="emu-tech-name">{r.technique_name}</span>
                        {det && (
                          <span
                            className={`pill ${det.detected ? "pill-ok" : "pill-danger"} emu-det-pill`}
                            title={det.evidence || (det.detected ? "Detected" : "No detection")}
                          >
                            {det.detected ? "detected" : "missed"}
                            {det.detected && det.count ? ` · ${det.count}` : ""}
                          </span>
                        )}
                        <span className={`pill pill-${statusFlavor(r.status)} emu-status`}>
                          {r.status}
                        </span>
                      </div>
                      {r.tactic && <div className="emu-tactic">{r.tactic}</div>}
                      {r.evidence && <div className="emu-evidence mono">{r.evidence}</div>}
                      {r.detail && <div className="emu-detail">{r.detail}</div>}
                    </div>
                  );
                })}
              </div>
            )}
          </>
        ) : (
          <div className="results-empty">
            <Icon name="shield" size={28} />
            <p>
              Enter an authorized target above and click <b>Run Emulation</b> to
              generate SAFE ATT&amp;CK telemetry across recon, initial-access, C2,
              discovery and exfiltration techniques.
            </p>
          </div>
        )}

        {/* Past runs */}
        {runs.length > 0 && (
          <div className="emu-history">
            <div className="emu-history-head">Past runs</div>
            <div className="emu-history-list">
              {runs.map((h) => (
                <button
                  className={`emu-history-item${run?.id === h.id ? " active" : ""}`}
                  key={h.id}
                  onClick={() => openRun(h.id)}
                  title={`Open run · ${h.target}`}
                >
                  <span className="emu-history-target mono">{h.target}</span>
                  <span className="emu-history-tallies">
                    <span className="emu-mini emu-mini-info">{h.executed ?? 0}</span>
                    <span className="emu-mini emu-mini-warn">{h.blocked ?? 0}</span>
                    <span className="emu-mini emu-mini-danger">{h.failed ?? 0}</span>
                  </span>
                  <span className="emu-history-when">{fmtWhen(h.finished_at || h.created_at)}</span>
                </button>
              ))}
            </div>
          </div>
        )}
      </div>
    </section>
  );
}

// Component-scoped styles — every color references a theme token (no hardcoded
// greys), so the panel tracks the app's light/dark themes.
const EMU_CSS = `
.emu-body { padding: 14px; display: flex; flex-direction: column; gap: 14px; }
.emu-tallies { display: inline-flex; gap: 6px; flex-wrap: wrap; }

.emu-banner {
  display: flex;
  align-items: flex-start;
  gap: 9px;
  padding: 10px 12px;
  border-radius: var(--radius-sm);
  background: var(--accent-glow);
  border: 1px solid var(--border);
  color: var(--text-dim);
  font-size: 12.5px;
  line-height: 1.5;
}
.emu-banner b { color: var(--text); }
.emu-banner svg { color: var(--accent); flex: 0 0 auto; margin-top: 1px; }

.emu-input-row { display: flex; gap: 8px; }
.emu-target-input {
  flex: 1;
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
.emu-target-input:focus { border-color: var(--accent); }
.emu-target-input:disabled { opacity: 0.55; cursor: not-allowed; }
.emu-run-btn {
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
.emu-run-btn:hover:not(:disabled) { opacity: 0.9; transform: translateY(-1px); }
.emu-run-btn:disabled { opacity: 0.45; cursor: not-allowed; transform: none; }
.emu-run-btn .rec-dot { background: #04211d; }

.emu-error { margin: 0; }

.emu-run-meta {
  display: flex;
  align-items: baseline;
  justify-content: space-between;
  gap: 10px;
}
.emu-run-target { font-size: 12.5px; color: var(--accent); word-break: break-all; }
.emu-run-when { font-size: 11.5px; color: var(--text-faint); white-space: nowrap; }

.emu-cards { display: flex; flex-direction: column; gap: 10px; }
.emu-card {
  padding: 11px 13px;
  border-radius: var(--radius-sm);
  background: var(--bg-elev);
  border: 1px solid var(--border);
  border-left: 3px solid var(--border);
  animation: fadeIn 0.18s ease;
}
.emu-card-head { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
.emu-tech-id {
  font-family: var(--font-mono);
  font-size: 12px;
  font-weight: 700;
  letter-spacing: 0.02em;
}
.emu-tech-name { font-weight: 600; font-size: 13.5px; color: var(--text); }
.emu-status { margin-left: auto; text-transform: capitalize; }
.emu-tactic {
  margin-top: 4px;
  font-size: 11px;
  text-transform: capitalize;
  letter-spacing: 0.04em;
  color: var(--text-faint);
}
.emu-evidence {
  margin-top: 8px;
  font-size: 12px;
  color: var(--text-dim);
  word-break: break-word;
  line-height: 1.45;
}
.emu-detail {
  margin-top: 6px;
  font-size: 12.5px;
  color: var(--text-dim);
  line-height: 1.5;
}

.emu-history { border-top: 1px solid var(--border-soft); padding-top: 12px; }
.emu-history-head {
  font-size: 11px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  color: var(--text-faint);
  margin-bottom: 8px;
}
.emu-history-list { display: flex; flex-direction: column; gap: 6px; }
.emu-history-item {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 8px 11px;
  border-radius: var(--radius-sm);
  border: 1px solid var(--border-soft);
  background: var(--panel);
  text-align: left;
  transition: border-color 0.15s, background 0.15s;
}
.emu-history-item:hover { border-color: var(--accent); }
.emu-history-item.active { border-color: var(--accent); background: var(--accent-glow); }
.emu-history-target { flex: 1; font-size: 12px; color: var(--text); word-break: break-all; }
.emu-history-tallies { display: inline-flex; gap: 5px; }
.emu-mini {
  font-family: var(--font-mono);
  font-size: 11px;
  font-weight: 700;
  min-width: 20px;
  text-align: center;
  padding: 1px 6px;
  border-radius: 6px;
  border: 1px solid transparent;
  font-variant-numeric: tabular-nums;
}
.emu-mini-info { color: var(--info); background: rgba(96,165,250,0.1); border-color: rgba(96,165,250,0.25); }
.emu-mini-warn { color: var(--warn); background: rgba(251,191,36,0.1); border-color: rgba(251,191,36,0.25); }
.emu-mini-danger { color: var(--danger); background: rgba(248,113,113,0.1); border-color: rgba(248,113,113,0.25); }
.emu-history-when { font-size: 11px; color: var(--text-faint); white-space: nowrap; }

/* --- P3 detection validation --------------------------------------------- */
.emu-validate {
  display: flex;
  flex-direction: column;
  gap: 8px;
  padding: 10px 12px;
  border-radius: var(--radius-sm);
  background: var(--bg-elev);
  border: 1px solid var(--border);
}
.emu-validate-row {
  display: flex;
  align-items: center;
  gap: 9px;
  flex-wrap: wrap;
}
.emu-validate-label {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  font-size: 12px;
  font-weight: 600;
  color: var(--text-dim);
  white-space: nowrap;
}
.emu-validate-label svg { color: var(--accent); }
.emu-validate-hint { font-size: 12px; color: var(--text-faint); }
.emu-connector-select {
  padding: 7px 10px;
  border-radius: var(--radius-sm);
  border: 1px solid var(--border);
  background: var(--panel);
  color: var(--text);
  font-size: 12.5px;
  font-family: var(--font-mono);
  outline: none;
  max-width: 100%;
}
.emu-connector-select:focus { border-color: var(--accent); }
.emu-connector-select:disabled { opacity: 0.55; cursor: not-allowed; }
.emu-validate-btn {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 7px 14px;
  border-radius: var(--radius-sm);
  background: var(--accent);
  color: #04211d;
  font-size: 12.5px;
  font-weight: 600;
  white-space: nowrap;
  transition: opacity 0.15s, transform 0.15s;
}
.emu-validate-btn:hover:not(:disabled) { opacity: 0.9; transform: translateY(-1px); }
.emu-validate-btn:disabled { opacity: 0.45; cursor: not-allowed; transform: none; }
.emu-validate-btn .rec-dot { background: #04211d; }
.emu-coverage {
  margin-left: auto;
  font-size: 12px;
  font-weight: 700;
  padding: 3px 10px;
  border-radius: 999px;
  border: 1px solid;
  font-variant-numeric: tabular-nums;
  white-space: nowrap;
}
.emu-validate-tallies {
  display: inline-flex;
  align-items: center;
  gap: 7px;
  flex-wrap: wrap;
}
.emu-validate-source { font-size: 11px; color: var(--text-faint); }
.emu-det-pill { text-transform: capitalize; }
`;

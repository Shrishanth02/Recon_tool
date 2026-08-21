import { useCallback, useEffect, useState } from "react";
import Icon from "./Icon";
import { fetchReportHtml, fetchRisk, runTriage, fetchTriage } from "../api/client";

const SEV_ORDER = ["critical", "high", "medium", "low", "info"];

// Map a 0-100 risk rating to a pill flavor for coloring.
function ratingFlavor(rating) {
  const r = (rating || "").toLowerCase();
  if (r === "critical" || r === "high") return "danger";
  if (r === "medium" || r === "elevated") return "warn";
  if (r === "low") return "info";
  return "ok";
}

function verdictFlavor(verdict) {
  const v = (verdict || "").toLowerCase();
  if (v.includes("true") || v.includes("confirm") || v.includes("exploit")) return "danger";
  if (v.includes("false") || v.includes("benign") || v.includes("noise")) return "dim";
  if (v.includes("review")) return "warn";
  return "info";
}

export default function FindingsPanel({ projectId, findings }) {
  const counts = {};
  for (const f of findings) counts[f.severity] = (counts[f.severity] || 0) + 1;

  const [risk, setRisk] = useState(null);
  const [triage, setTriage] = useState(null); // last envelope: { enabled, result, ... }
  const [triaging, setTriaging] = useState(false);
  const [triageErr, setTriageErr] = useState(null);
  const [reporting, setReporting] = useState(false);

  // The report endpoint is auth-gated, so a plain link would 401. Open a blank
  // tab synchronously (keeps the user-gesture so it isn't popup-blocked), then
  // fetch the HTML with the auth header and point the tab at a blob URL.
  const onReport = useCallback(async () => {
    if (!projectId || reporting) return;
    setReporting(true);
    setTriageErr(null);
    const win = window.open("", "_blank");
    // STEP 4: sever the opener so the report tab can never reach back into the app
    // window (reverse-tabnabbing hardening). Report fields are already HTML-escaped.
    if (win) {
      win.opener = null;
      win.document.write("<p style='font:14px sans-serif;padding:24px'>Generating report…</p>");
    }
    try {
      const html = await fetchReportHtml(projectId);
      const url = URL.createObjectURL(new Blob([html], { type: "text/html" }));
      if (win) win.location = url;
      else window.open(url, "_blank");
      setTimeout(() => URL.revokeObjectURL(url), 60000);
    } catch (e) {
      if (win) win.close();
      setTriageErr(e?.message || "Could not open the report.");
    } finally {
      setReporting(false);
    }
  }, [projectId, reporting]);

  // Refresh the risk score whenever the workspace or its findings change.
  useEffect(() => {
    if (!projectId) {
      setRisk(null);
      return;
    }
    let alive = true;
    (async () => {
      try {
        const r = await fetchRisk(projectId);
        if (alive) setRisk(r);
      } catch {
        if (alive) setRisk(null);
      }
    })();
    return () => {
      alive = false;
    };
  }, [projectId, findings]);

  // Load any previously-persisted triage when the workspace changes.
  useEffect(() => {
    setTriage(null);
    setTriageErr(null);
    if (!projectId) return;
    let alive = true;
    (async () => {
      try {
        const t = await fetchTriage(projectId);
        if (alive && t && t.enabled) setTriage(t);
      } catch {
        /* none yet */
      }
    })();
    return () => {
      alive = false;
    };
  }, [projectId]);

  const onTriage = useCallback(async () => {
    if (!projectId || triaging) return;
    setTriaging(true);
    setTriageErr(null);
    try {
      const res = await runTriage(projectId);
      setTriage(res);
    } catch (e) {
      setTriageErr(e?.message || "Triage failed");
    } finally {
      setTriaging(false);
    }
  }, [projectId, triaging]);

  const result = triage?.result || null;
  const items = result?.items || [];
  const verdictById = {};
  for (const it of items) verdictById[it.finding_id] = it;

  return (
    <section className="panel findings-panel">
      <header className="panel-head">
        <span className="panel-title">
          <Icon name="bug" size={15} /> Findings
          {risk && (
            <span
              className={`risk-pill pill-${ratingFlavor(risk.rating)}`}
              title={`Risk ${risk.score}/100 · ${risk.total} finding${risk.total === 1 ? "" : "s"}`}
            >
              <Icon name="shield" size={12} /> {risk.score}
              <span className="risk-rating">{risk.rating}</span>
            </span>
          )}
        </span>
        <div className="panel-actions">
          {findings.length > 0 && (
            <button
              className="btn-ghost"
              onClick={onTriage}
              disabled={triaging}
              title="Run AI triage over these findings"
            >
              {triaging ? (
                <>
                  <span className="rec-dot" /> Triaging…
                </>
              ) : (
                <>
                  <Icon name="bolt" size={14} /> AI Triage
                </>
              )}
            </button>
          )}
          {findings.length > 0 && (
            <button
              className="btn-ghost"
              onClick={onReport}
              disabled={reporting}
              title="Open the client-ready HTML report"
            >
              <Icon name="report" size={14} /> {reporting ? "Opening…" : "Report"}
            </button>
          )}
        </div>
      </header>

      <div className="results-body">
        {findings.length === 0 ? (
          <div className="results-empty">
            <Icon name="bug" size={28} />
            <p>No findings yet. Run a Vuln Scan or Port Scan to populate this engagement.</p>
          </div>
        ) : (
          <>
            {triageErr && (
              <div className="result-error triage-note">
                <Icon name="x" size={16} /> {triageErr}
              </div>
            )}
            {triage && !triage.enabled && (
              <div className="triage-note triage-disabled">
                <Icon name="cpu" size={16} />
                <span>
                  AI triage is not configured{triage.reason ? ` — ${triage.reason}` : ""}.
                </span>
              </div>
            )}
            {triage && triage.enabled && triage.refused && (
              <div className="triage-note triage-disabled">
                <Icon name="cpu" size={16} />
                <span>AI triage declined to process these findings{triage.reason ? ` — ${triage.reason}` : ""}.</span>
              </div>
            )}
            {result && (result.summary || result.risk_narrative) && (
              <div className="triage-summary">
                <div className="triage-summary-head">
                  <Icon name="bolt" size={14} /> AI Triage
                  {triage?.model && <span className="triage-model">{triage.model}</span>}
                </div>
                {result.summary && <p className="triage-text">{result.summary}</p>}
                {result.risk_narrative && (
                  <p className="triage-text triage-narrative">{result.risk_narrative}</p>
                )}
              </div>
            )}

            <div className="sev-summary">
              {SEV_ORDER.map((s) =>
                counts[s] ? (
                  <span key={s} className={`sev-chip sev-${s}`}>{counts[s]} {s}</span>
                ) : null
              )}
            </div>
            <div className="findings-list">
              {findings.map((f) => {
                const v = verdictById[f.id];
                return (
                  <div className={`finding finding-${f.severity}`} key={f.id}>
                    <div className="finding-head">
                      <span className={`pill sev-${f.severity} pill-${
                        f.severity === "critical" || f.severity === "high"
                          ? "danger"
                          : f.severity === "medium"
                          ? "warn"
                          : f.severity === "low"
                          ? "info"
                          : "dim"
                      }`}>{f.severity}</span>
                      <span className="finding-name">{f.name}</span>
                      <span className="finding-src">{f.source}</span>
                      {v?.verdict && (
                        <span
                          className={`pill pill-${verdictFlavor(v.verdict)} triage-verdict`}
                          title={v.rationale || ""}
                        >
                          <Icon name="bolt" size={11} /> {v.verdict.replace(/_/g, " ")}
                        </span>
                      )}
                      {f.cvss != null && <span className="finding-cvss">CVSS {f.cvss}</span>}
                    </div>
                    {f.location && <div className="finding-at mono">{f.location}</div>}
                    {(f.cve?.length > 0 || f.cwe?.length > 0) && (
                      <div className="finding-tags">
                        {(f.cve || []).map((c) => (
                          <span className="chip chip-cve" key={c}>{(c || "").toUpperCase()}</span>
                        ))}
                        {(f.cwe || []).map((c) => (
                          <span className="chip" key={c}>{(c || "").toUpperCase()}</span>
                        ))}
                      </div>
                    )}
                    {f.description && <div className="finding-desc">{f.description}</div>}
                    {v && (v.remediation || v.suggested_severity) && (
                      <div className="triage-advice">
                        {v.suggested_severity && (
                          <span className="triage-advice-sev">
                            Suggested severity: <b>{v.suggested_severity}</b>
                          </span>
                        )}
                        {v.remediation && <div className="triage-remediation">{v.remediation}</div>}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </>
        )}
      </div>
    </section>
  );
}

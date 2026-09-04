import { useCallback, useEffect, useState } from "react";
import Icon from "./Icon";
import {
  fetchPentestRuns,
  fetchPentestRun,
  deletePentestRun,
  fetchPurpleReportHtml,
} from "../api/client";

const RISK_TONE = {
  CRITICAL: "danger",
  HIGH: "warn",
  MEDIUM: "warn",
  LOW: "ok",
  INFORMATIONAL: "info",
};

function fmtWhen(s) {
  if (!s) return "—";
  try {
    return new Date(s).toLocaleString();
  } catch {
    return String(s);
  }
}

/**
 * PurpleHistory — Auto-Pentest run history for the Purple Team section.
 * Rows are click-to-expand; the report opens IN-APP (iframe modal) so it is
 * never blocked by a popup blocker.
 */
export default function PurpleHistory({ workspaceId }) {
  const [runs, setRuns] = useState([]);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState(null);
  const [busy, setBusy] = useState({});
  const [openId, setOpenId] = useState(null);
  const [detail, setDetail] = useState(null);
  const [detailBusy, setDetailBusy] = useState(false);

  // In-app report modal state.
  const [reportOpen, setReportOpen] = useState(false);
  const [reportBusy, setReportBusy] = useState(false);
  const [reportHtml, setReportHtml] = useState("");
  const [reportErr, setReportErr] = useState(null);

  const load = useCallback(async () => {
    if (!workspaceId) {
      setRuns([]);
      return;
    }
    setLoading(true);
    setErr(null);
    try {
      setRuns((await fetchPentestRuns(workspaceId)) || []);
    } catch (e) {
      setErr(e?.message || "Could not load auto-pentest runs.");
      setRuns([]);
    } finally {
      setLoading(false);
    }
  }, [workspaceId]);

  useEffect(() => {
    load();
  }, [load]);

  const toggleOpen = async (run) => {
    if (openId === run.id) {
      setOpenId(null);
      setDetail(null);
      return;
    }
    setOpenId(run.id);
    setDetail(null);
    setDetailBusy(true);
    try {
      setDetail(await fetchPentestRun(workspaceId, run.id));
    } catch {
      setDetail(null);
    } finally {
      setDetailBusy(false);
    }
  };

  const onDelete = async (id) => {
    setBusy((p) => ({ ...p, [id]: true }));
    try {
      await deletePentestRun(workspaceId, id);
      if (openId === id) setOpenId(null);
      await load();
    } catch {
      /* ignore */
    } finally {
      setBusy((p) => ({ ...p, [id]: false }));
    }
  };

  const openReport = async () => {
    setReportOpen(true);
    setReportBusy(true);
    setReportErr(null);
    setReportHtml("");
    try {
      setReportHtml(await fetchPurpleReportHtml(workspaceId));
    } catch (e) {
      setReportErr(e?.message || "Could not load the report.");
    } finally {
      setReportBusy(false);
    }
  };

  const downloadReport = () => {
    if (!reportHtml) return;
    const blob = new Blob([reportHtml], { type: "text/html" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "redopsx-purple-report.html";
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 5000);
  };

  const stat = (label, value) => (
    <div className="ph-stat">
      <span className="ph-stat-val">{value}</span>
      <span className="ph-stat-label">{label}</span>
    </div>
  );

  return (
    <section className="panel history">
      <header className="panel-head">
        <span className="panel-title">
          <Icon name="history" size={15} /> Auto-Pentest History
        </span>
        <span className="hist-head-right">
          <span className="stream-badge">
            {runs.length} run{runs.length === 1 ? "" : "s"}
          </span>
          {runs.length > 0 && (
            <button
              className="hist-clear"
              onClick={openReport}
              title="Open the purple-team report for this engagement"
            >
              <Icon name="report" size={13} /> Report
            </button>
          )}
        </span>
      </header>

      <div className="history-body">
        {loading ? (
          <div className="history-empty">Loading…</div>
        ) : err ? (
          <div className="history-empty">{err}</div>
        ) : runs.length === 0 ? (
          <div className="history-empty">
            No auto-pentest runs yet. Launch one from the Auto-Pentest tab.
          </div>
        ) : (
          runs.map((r) => {
            const s = r.summary || {};
            const tone = RISK_TONE[r.risk_label] || "info";
            const isOpen = openId === r.id;
            const hasSummary = s && Object.keys(s).length > 0;
            return (
              <div className={`ph-run ${isOpen ? "open" : ""}`} key={r.id}>
                <div className="history-item">
                  <button className="hist-open" onClick={() => toggleOpen(r)}>
                    <span className={`hist-dot ${tone}`} />
                    <span className="hist-main">
                      <span className="hist-tool">{r.target}</span>
                      <span className="hist-target">
                        {fmtWhen(r.started_at || r.created_at)}
                        {hasSummary
                          ? ` · ${s.live_hosts ?? 0} host(s) · ${
                              s.total_findings ?? 0
                            } finding(s)`
                          : ` · ${r.status}`}
                      </span>
                    </span>
                    <span className="hist-meta">
                      {hasSummary && (
                        <span className={`ph-risk ph-risk-${tone}`}>
                          {r.risk_label || "—"} · {r.risk_score ?? 0}
                        </span>
                      )}
                      <span className="dim">{isOpen ? "▲" : "▼"}</span>
                    </span>
                  </button>
                  <button
                    className="hist-del"
                    onClick={() => onDelete(r.id)}
                    disabled={busy[r.id]}
                    title="Delete this run"
                  >
                    <Icon name="trash" size={13} />
                  </button>
                </div>

                {isOpen && (
                  <div className="ph-detail">
                    {detailBusy ? (
                      <div className="ph-loading">Loading process…</div>
                    ) : (
                      (() => {
                        const dsum = detail?.summary || s;
                        const dHasSummary =
                          dsum && Object.keys(dsum).length > 0;
                        const stages = detail?.process?.stages || {};
                        const stageEntries = Object.entries(stages).sort(
                          (a, b) => Number(a[0]) - Number(b[0])
                        );
                        return (
                          <>
                            {dHasSummary && (
                              <div className="ph-detail-grid">
                                {stat("Status", r.status)}
                                {stat(
                                  "Risk",
                                  `${r.risk_label || "—"} (${r.risk_score ?? 0})`
                                )}
                                {stat("Subdomains", dsum.subdomains_found ?? 0)}
                                {stat("Live hosts", dsum.live_hosts ?? 0)}
                                {stat("Findings", dsum.total_findings ?? 0)}
                                {stat("Finished", fmtWhen(r.finished_at))}
                              </div>
                            )}
                            {dHasSummary &&
                              dsum.severity_counts &&
                              Object.keys(dsum.severity_counts).length > 0 && (
                                <div className="ph-sev">
                                  {["critical", "high", "medium", "low", "info"]
                                    .filter((k) => dsum.severity_counts[k])
                                    .map((k) => (
                                      <span
                                        key={k}
                                        className={`pill pill-${
                                          k === "critical" || k === "high"
                                            ? "danger"
                                            : k === "medium" || k === "low"
                                            ? "warn"
                                            : "info"
                                        }`}
                                      >
                                        {dsum.severity_counts[k]} {k}
                                      </span>
                                    ))}
                                </div>
                              )}

                            {stageEntries.length > 0 ? (
                              <div className="ph-stages">
                                <div className="ph-stages-label">
                                  Process — {stageEntries.length} stage(s)
                                </div>
                                {stageEntries.map(([num, st]) => (
                                  <details className="ph-stage" key={num}>
                                    <summary className="ph-stage-head">
                                      <span className="ph-stage-num">{num}</span>
                                      <span className="ph-stage-name">
                                        {st.name || `Stage ${num}`}
                                      </span>
                                      <span
                                        className={`ph-stage-status s-${
                                          st.status || "done"
                                        }`}
                                      >
                                        {st.status}
                                      </span>
                                    </summary>
                                    {Array.isArray(st.logs) && st.logs.length > 0 && (
                                      <pre className="ph-stage-logs mono">
                                        {st.logs.join("\n")}
                                      </pre>
                                    )}
                                    {st.result != null && (
                                      <pre className="ph-stage-result mono">
                                        {JSON.stringify(st.result, null, 2)}
                                      </pre>
                                    )}
                                    {/* The Summary stage carries no logs/result
                                        (the aggregate rides a separate event) —
                                        render the run summary inside it so it is
                                        not empty like the other stages. Detected
                                        by name so it works for old (stage 9) and
                                        new (stage 14) runs alike. */}
                                    {(st.name === "Summary" || num === "9" || num === "14") &&
                                      !(Array.isArray(st.logs) && st.logs.length) &&
                                      st.result == null &&
                                      (dHasSummary ? (
                                        <div className="ph-stage-summary">
                                          <div className="ph-detail-grid">
                                            {stat(
                                              "Risk",
                                              `${r.risk_label || "—"} (${
                                                r.risk_score ?? 0
                                              })`
                                            )}
                                            {stat(
                                              "Subdomains",
                                              dsum.subdomains_found ?? 0
                                            )}
                                            {stat("Live hosts", dsum.live_hosts ?? 0)}
                                            {stat(
                                              "Findings",
                                              dsum.total_findings ?? 0
                                            )}
                                            {stat(
                                              "Finished",
                                              fmtWhen(r.finished_at)
                                            )}
                                          </div>
                                          {dsum.severity_counts &&
                                            Object.keys(dsum.severity_counts)
                                              .length > 0 && (
                                              <div className="ph-sev">
                                                {[
                                                  "critical",
                                                  "high",
                                                  "medium",
                                                  "low",
                                                  "info",
                                                ]
                                                  .filter(
                                                    (k) => dsum.severity_counts[k]
                                                  )
                                                  .map((k) => (
                                                    <span
                                                      key={k}
                                                      className={`pill pill-${
                                                        k === "critical" ||
                                                        k === "high"
                                                          ? "danger"
                                                          : k === "medium" ||
                                                            k === "low"
                                                          ? "warn"
                                                          : "info"
                                                      }`}
                                                    >
                                                      {dsum.severity_counts[k]} {k}
                                                    </span>
                                                  ))}
                                              </div>
                                            )}
                                        </div>
                                      ) : (
                                        <div className="ph-stage-summary">
                                          <p className="ph-note">
                                            No summary was captured for this run.
                                          </p>
                                        </div>
                                      ))}
                                  </details>
                                ))}
                              </div>
                            ) : (
                              <p className="ph-note">
                                No stored process for this run — it predates
                                process capture (or was stopped very early). Its
                                per-stage scans are in{" "}
                                <b>Recon Console → History</b> and findings in the{" "}
                                <b>Findings</b> tab.
                              </p>
                            )}

                            <button
                              className="ph-report-btn"
                              onClick={openReport}
                            >
                              <Icon name="report" size={14} /> Open purple-team
                              report
                            </button>
                          </>
                        );
                      })()
                    )}
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>

      {reportOpen && (
        <div
          className="report-overlay"
          onClick={() => setReportOpen(false)}
          role="presentation"
        >
          <div className="report-modal" onClick={(e) => e.stopPropagation()}>
            <div className="report-modal-head">
              <span className="report-modal-title">
                <Icon name="report" size={15} /> Purple-Team Report
              </span>
              <span className="report-modal-actions">
                <button
                  onClick={downloadReport}
                  disabled={!reportHtml || reportBusy}
                  title="Download the report as HTML"
                >
                  <Icon name="download" size={13} /> Download
                </button>
                <button onClick={() => setReportOpen(false)} title="Close">
                  <Icon name="x" size={14} /> Close
                </button>
              </span>
            </div>
            {reportBusy ? (
              <div className="report-modal-msg">Loading report…</div>
            ) : reportErr ? (
              <div className="report-modal-msg err">{reportErr}</div>
            ) : (
              <iframe
                title="Purple-Team Report"
                className="report-frame"
                srcDoc={reportHtml}
                // STEP 4: sandbox the scan-derived report HTML. An empty sandbox
                // gives the frame an opaque origin with NO script execution and NO
                // access to parent window/localStorage, so report content can never
                // reach the app's tokens even if an escaping gap were introduced.
                // Inline CSS still renders (sandbox does not police styling).
                sandbox=""
              />

            )}
          </div>
        </div>
      )}
    </section>
  );
}

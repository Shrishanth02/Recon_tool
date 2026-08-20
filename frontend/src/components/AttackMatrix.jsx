import { useEffect, useState } from "react";
import Icon from "./Icon";
import { fetchAttackCoverage } from "../api/client";

/**
 * AttackMatrix — RECON-X Purple-Team P1 coverage view.
 *
 * Renders the workspace's MITRE ATT&CK coverage as a horizontally-scrolling
 * board: one column per tactic (in kill-chain order, as returned by the
 * backend), each holding technique cards. A card is colored by its highest-
 * severity finding and shows a per-severity breakdown + total count.
 *
 * Data comes from `GET /workspaces/{id}/attack-coverage` via
 * `fetchAttackCoverage`. The endpoint only returns tactics/techniques that
 * have at least one mapped finding, so an empty board == a clean empty state.
 *
 * Theming is entirely token-driven (--text / --panel / --border and the
 * severity tokens --danger / --warn / --info / --ok) so the matrix tracks the
 * app's light/dark themes with no hardcoded greys.
 */

// Severity precedence, most→least severe. Used to pick a technique card's
// accent color from the severities it contains.
const SEV_ORDER = ["critical", "high", "medium", "low", "info"];

// Map a severity to one of the app's semantic color tokens.
function sevToken(sev) {
  switch (sev) {
    case "critical":
    case "high":
      return "var(--danger)";
    case "medium":
      return "var(--warn)";
    case "low":
      return "var(--info)";
    default:
      return "var(--text-faint)";
  }
}

// The most severe severity present in a technique's severities map.
function topSeverity(severities = {}) {
  for (const s of SEV_ORDER) {
    if (severities[s]) return s;
  }
  return "info";
}

export default function AttackMatrix({ workspaceId }) {
  const [coverage, setCoverage] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (!workspaceId) {
      setCoverage(null);
      setError(null);
      return;
    }
    let alive = true;
    setLoading(true);
    setError(null);
    (async () => {
      try {
        const data = await fetchAttackCoverage(workspaceId);
        if (alive) setCoverage(data);
      } catch (e) {
        if (alive) {
          setError(e?.message || "Could not load ATT&CK coverage.");
          setCoverage(null);
        }
      } finally {
        if (alive) setLoading(false);
      }
    })();
    return () => {
      alive = false;
    };
  }, [workspaceId]);

  const tactics = coverage?.tactics || [];
  const totalTechniques = coverage?.total_techniques ?? 0;
  const totalFindings = coverage?.total_findings ?? 0;

  return (
    <section className="panel attack-panel">
      <style>{ATTACK_CSS}</style>
      <header className="panel-head">
        <span className="panel-title">
          <Icon name="shield" size={15} /> ATT&amp;CK Coverage
        </span>
        {tactics.length > 0 && (
          <div className="attack-totals">
            <span className="attack-total-chip" title="Tactics with at least one mapped finding">
              {tactics.length} tactic{tactics.length === 1 ? "" : "s"}
            </span>
            <span className="attack-total-chip" title="Distinct ATT&CK techniques observed">
              {totalTechniques} technique{totalTechniques === 1 ? "" : "s"}
            </span>
            <span className="attack-total-chip" title="Findings mapped to a technique">
              {totalFindings} mapped
            </span>
          </div>
        )}
      </header>

      <div className="results-body attack-body">
        {loading ? (
          <div className="results-empty">
            <span className="rec-dot" />
            <p>Loading ATT&amp;CK coverage…</p>
          </div>
        ) : error ? (
          <div className="results-empty">
            <Icon name="x" size={28} />
            <p>{error}</p>
          </div>
        ) : tactics.length === 0 ? (
          <div className="results-empty">
            <Icon name="shield" size={28} />
            <p>
              No ATT&amp;CK techniques mapped yet. Run scans (recon, port, or vuln)
              to populate the coverage matrix.
            </p>
          </div>
        ) : (
          <div className="attack-board">
            {tactics.map((t) => (
              <div className="attack-col" key={t.tactic}>
                <div className="attack-col-head">
                  <span className="attack-tactic-name">{t.name}</span>
                  <span className="attack-tactic-id">{t.tactic}</span>
                </div>
                <div className="attack-col-body">
                  {(t.techniques || []).map((tech) => {
                    const top = topSeverity(tech.severities);
                    const accent = sevToken(top);
                    return (
                      <div
                        className="attack-card"
                        key={tech.technique_id}
                        style={{ borderLeftColor: accent }}
                        title={`${tech.technique_id} · ${tech.name}`}
                      >
                        <div className="attack-card-head">
                          <span className="attack-tech-id" style={{ color: accent }}>
                            {tech.technique_id}
                          </span>
                          <span className="attack-count" style={{ color: accent }}>
                            {tech.count}
                          </span>
                        </div>
                        <div className="attack-tech-name">{tech.name}</div>
                        <div className="attack-sevs">
                          {SEV_ORDER.map((s) =>
                            tech.severities?.[s] ? (
                              <span
                                key={s}
                                className="attack-sev-dot"
                                title={`${tech.severities[s]} ${s}`}
                                style={{ "--dot": sevToken(s) }}
                              >
                                <i className="attack-dot" />
                                {tech.severities[s]}
                              </span>
                            ) : null
                          )}
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </section>
  );
}

// Component-scoped styles. Kept inline (rather than in App.css) so the panel is
// self-contained; every color references a theme token — no hardcoded greys.
const ATTACK_CSS = `
.attack-body { padding: 14px; }
.attack-totals { display: inline-flex; gap: 6px; flex-wrap: wrap; }
.attack-total-chip {
  font-size: 11px;
  font-weight: 600;
  color: var(--text-dim);
  padding: 3px 9px;
  border-radius: 20px;
  border: 1px solid var(--border);
  background: var(--panel-2);
  white-space: nowrap;
}
.attack-board {
  display: flex;
  gap: 12px;
  align-items: flex-start;
  overflow-x: auto;
  padding-bottom: 6px;
}
.attack-col {
  flex: 0 0 210px;
  min-width: 210px;
  display: flex;
  flex-direction: column;
  gap: 8px;
}
.attack-col-head {
  display: flex;
  flex-direction: column;
  gap: 2px;
  padding: 8px 10px;
  border-radius: var(--radius-sm);
  background: var(--bg-elev);
  border: 1px solid var(--border-soft);
  border-top: 2px solid var(--accent);
  position: sticky;
  top: 0;
}
.attack-tactic-name {
  font-size: 12px;
  font-weight: 600;
  color: var(--text);
  text-transform: capitalize;
  line-height: 1.3;
}
.attack-tactic-id {
  font-size: 10.5px;
  font-family: var(--font-mono);
  color: var(--text-faint);
  letter-spacing: 0.04em;
}
.attack-col-body { display: flex; flex-direction: column; gap: 8px; }
.attack-card {
  padding: 9px 11px;
  border-radius: var(--radius-sm);
  background: var(--panel);
  border: 1px solid var(--border);
  border-left: 3px solid var(--border);
  animation: fadeIn 0.18s ease;
}
.attack-card-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
}
.attack-tech-id {
  font-size: 11.5px;
  font-weight: 700;
  font-family: var(--font-mono);
  letter-spacing: 0.02em;
}
.attack-count {
  font-size: 13px;
  font-weight: 700;
  font-variant-numeric: tabular-nums;
}
.attack-tech-name {
  margin-top: 4px;
  font-size: 12px;
  color: var(--text-dim);
  line-height: 1.35;
}
.attack-sevs {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  margin-top: 8px;
}
.attack-sev-dot {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  font-size: 11px;
  font-weight: 600;
  color: var(--text-dim);
  font-variant-numeric: tabular-nums;
}
.attack-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: var(--dot, var(--text-faint));
  display: inline-block;
}
`;

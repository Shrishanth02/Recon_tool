import Icon from "./Icon";

function StatusPill({ code }) {
  const c = Number(code);
  let tone = "info";
  if (c >= 200 && c < 300) tone = "ok";
  else if (c >= 300 && c < 400) tone = "warn";
  else if (c >= 400) tone = "danger";
  return <span className={`pill pill-${tone}`}>{code}</span>;
}

function PortState({ state }) {
  const tone =
    state === "open" ? "ok" : state === "filtered" ? "warn" : "dim";
  return <span className={`pill pill-${tone}`}>{state}</span>;
}

function NmapResult({ data }) {
  return (
    <div className="result-block">
      <div className="kv-summary">
        <span><b>Host</b> {data.host}</span>
        <span><b>Profile</b> {data.scan_type}</span>
        <span><b>Open</b> {data.open_ports ?? "—"}</span>
        {data.os && <span><b>OS</b> {data.os}</span>}
      </div>
      {data.ports?.length ? (
        <table className="data-table">
          <thead>
            <tr>
              <th>Port</th><th>Proto</th><th>State</th><th>Service</th>
              {data.ports[0]?.version !== undefined && <th>Version</th>}
            </tr>
          </thead>
          <tbody>
            {data.ports.map((p, i) => (
              <tr key={i}>
                <td className="mono">{p.port}</td>
                <td className="mono dim">{p.protocol}</td>
                <td><PortState state={p.state} /></td>
                <td>{p.service || "—"}</td>
                {p.version !== undefined && (
                  <td className="dim">
                    {[p.product, p.version].filter(Boolean).join(" ") || "—"}
                  </td>
                )}
              </tr>
            ))}
          </tbody>
        </table>
      ) : (
        <p className="muted">No open ports reported.</p>
      )}
    </div>
  );
}

function DirbusterResult({ data }) {
  if (!data.rows?.length) return <p className="muted">No paths discovered.</p>;
  return (
    <div className="result-block">
      <div className="kv-summary">
        <span><b>Target</b> {data.target}</span>
        <span><b>Found</b> {data.found}</span>
      </div>
      <table className="data-table">
        <thead>
          <tr><th>Path</th><th>Status</th><th>Size</th><th>Words</th><th>Lines</th></tr>
        </thead>
        <tbody>
          {data.rows.map((r, i) => (
            <tr key={i}>
              <td className="mono accent">/{r.path}</td>
              <td><StatusPill code={r.status} /></td>
              <td className="mono dim">{r.size}</td>
              <td className="mono dim">{r.words}</td>
              <td className="mono dim">{r.lines}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function ListResult({ items, label }) {
  if (!items?.length) return <p className="muted">Nothing found.</p>;
  return (
    <div className="result-block">
      <div className="kv-summary">
        <span><b>{label}</b> {items.length}</span>
      </div>
      <div className="chip-grid">
        {items.map((item, i) => (
          <span className="chip" key={i}>{item}</span>
        ))}
      </div>
    </div>
  );
}

function WhoisResult({ data }) {
  return (
    <div className="result-block kv-list">
      {Object.entries(data).map(([k, v]) => (
        <div className="kv-row" key={k}>
          <div className="kv-key">{k.replace(/_/g, " ")}</div>
          <div className="kv-val">
            {Array.isArray(v) ? (
              v.length ? (
                <div className="chip-grid">
                  {v.map((x, i) => <span className="chip" key={i}>{x}</span>)}
                </div>
              ) : "—"
            ) : (
              String(v || "—")
            )}
          </div>
        </div>
      ))}
    </div>
  );
}

function TechResult({ data }) {
  const tech = data.detected_tech || {};
  return (
    <div className="result-block">
      <div className="kv-summary">
        <span><b>URL</b> {data.url}</span>
        <span><b>Status</b> <StatusPill code={data.status_code} /></span>
      </div>
      {Object.keys(tech).length > 0 && (
        <div className="tech-grid">
          {Object.entries(tech).map(([cat, vals]) => (
            <div className="tech-card" key={cat}>
              <div className="tech-cat">{cat}</div>
              <div className="chip-grid">
                {(Array.isArray(vals) ? vals : [vals]).map((v, i) => (
                  <span className="chip" key={i}>{v}</span>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}
      {data.terminal_output && (
        <pre className="raw-headers">{data.terminal_output}</pre>
      )}
    </div>
  );
}

const SEV_TONE = {
  critical: "danger",
  high: "danger",
  medium: "warn",
  low: "info",
  info: "dim",
  unknown: "dim",
};

function SeverityBadge({ severity }) {
  return (
    <span className={`pill sev-${severity} pill-${SEV_TONE[severity] || "dim"}`}>
      {severity}
    </span>
  );
}

function HttpxResult({ data }) {
  if (!data.rows?.length) return <p className="muted">No live hosts found.</p>;
  return (
    <div className="result-block">
      <div className="kv-summary">
        <span><b>Probed</b> {data.probed}</span>
        <span><b>Alive</b> {data.alive}</span>
      </div>
      <table className="data-table">
        <thead>
          <tr><th>URL</th><th>Status</th><th>Title</th><th>Server</th><th>Tech</th></tr>
        </thead>
        <tbody>
          {data.rows.map((r, i) => (
            <tr key={i}>
              <td className="mono accent">{r.url}</td>
              <td><StatusPill code={r.status} /></td>
              <td>{r.title || "—"}</td>
              <td className="dim">{r.webserver || "—"}</td>
              <td className="dim">{(r.tech || []).join(", ") || "—"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function NucleiResult({ data }) {
  const counts = data.counts || {};
  if (!data.findings?.length) {
    return (
      <div className="result-block">
        <div className="result-ok">
          <Icon name="check" size={16} /> No vulnerabilities detected at the selected severity.
        </div>
        <p className="result-hint">
          Well-configured sites and CDN-fronted targets often have nothing at{" "}
          <b>Low&nbsp;→&nbsp;Critical</b>. To also surface informational detections
          (missing security headers, technology fingerprints, exposed paths), re-run
          with severity set to <b>“Everything (incl.&nbsp;info)”</b>.
        </p>
      </div>
    );
  }
  return (
    <div className="result-block">
      <div className="sev-summary">
        {["critical", "high", "medium", "low", "info"].map((s) =>
          counts[s] ? (
            <span key={s} className={`sev-chip sev-${s}`}>
              {counts[s]} {s}
            </span>
          ) : null
        )}
      </div>
      <div className="findings-list">
        {data.findings.map((f, i) => (
          <div className={`finding finding-${f.severity}`} key={i}>
            <div className="finding-head">
              <SeverityBadge severity={f.severity} />
              <span className="finding-name">{f.name}</span>
              {f.cvss != null && <span className="finding-cvss">CVSS {f.cvss}</span>}
            </div>
            <div className="finding-at mono">{f.matched_at}</div>
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
          </div>
        ))}
      </div>
    </div>
  );
}

function renderResult(tool, data) {
  switch (tool) {
    case "nmap": return <NmapResult data={data} />;
    case "httpx": return <HttpxResult data={data} />;
    case "nuclei": return <NucleiResult data={data} />;
    case "dirbuster": return <DirbusterResult data={data} />;
    case "subdomains": return <ListResult items={data.subdomains} label="Subdomains" />;
    case "reverse": return <ListResult items={data.domains} label="Domains" />;
    case "whois": return <WhoisResult data={data} />;
    case "tech": return <TechResult data={data} />;
    default: return <pre className="raw-headers">{JSON.stringify(data, null, 2)}</pre>;
  }
}

export default function ResultsPanel({ tool, result, error, status, onExport }) {
  return (
    <section className="panel results">
      <header className="panel-head">
        <span className="panel-title">
          <Icon name="bolt" size={15} /> Results
        </span>
        {result && (
          <button className="btn-ghost" onClick={onExport}>
            <Icon name="download" size={14} /> Export JSON
          </button>
        )}
      </header>

      <div className="results-body">
        {error && (
          <div className="result-error">
            <Icon name="x" size={16} /> {error}
          </div>
        )}
        {!error && !result && (
          <div className="results-empty">
            <Icon name="bolt" size={28} />
            <p>
              {status === "scanning"
                ? "Scan in progress — structured results will appear when ready."
                : "Run a scan to populate results."}
            </p>
          </div>
        )}
        {result && renderResult(tool, result)}
      </div>
    </section>
  );
}

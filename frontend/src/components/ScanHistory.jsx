import Icon from "./Icon";

const STATUS_TONE = {
  done: "ok",
  error: "danger",
  stopped: "warn",
};

export default function ScanHistory({ scans, toolNames, onReplay }) {
  return (
    <section className="panel history">
      <header className="panel-head">
        <span className="panel-title">
          <Icon name="history" size={15} /> Scan History
        </span>
        <span className="stream-badge">{scans.length} stored</span>
      </header>

      <div className="history-body">
        {scans.length === 0 ? (
          <div className="history-empty">No scans stored for this engagement yet.</div>
        ) : (
          scans.map((h) => (
            <button className="history-item" key={h.id} onClick={() => onReplay(h.id)}>
              <span className={`hist-dot ${STATUS_TONE[h.status] || "info"}`} />
              <span className="hist-main">
                <span className="hist-tool">{toolNames[h.tool] || h.tool}</span>
                <span className="hist-target">{h.target}</span>
              </span>
              <span className="hist-meta">
                <span>{(h.duration || 0).toFixed(1)}s</span>
                <span className="dim">#{h.id}</span>
              </span>
            </button>
          ))
        )}
      </div>
    </section>
  );
}

import Icon from "./Icon";

const STATUS_TONE = {
  done: "ok",
  error: "danger",
  stopped: "warn",
};

export default function ScanHistory({ scans, toolNames, onReplay, onDelete, onClearAll }) {
  return (
    <section className="panel history">
      <header className="panel-head">
        <span className="panel-title">
          <Icon name="history" size={15} /> Scan History
        </span>
        <span className="hist-head-right">
          <span className="stream-badge">{scans.length} stored</span>
          {scans.length > 0 && onClearAll && (
            <button
              className="hist-clear"
              onClick={onClearAll}
              title="Delete all scan history for this engagement"
            >
              <Icon name="trash" size={13} /> Clear all
            </button>
          )}
        </span>
      </header>

      <div className="history-body">
        {scans.length === 0 ? (
          <div className="history-empty">No scans stored for this engagement yet.</div>
        ) : (
          scans.map((h) => (
            <div className="history-item" key={h.id}>
              <button className="hist-open" onClick={() => onReplay(h.id)}>
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
              {onDelete && (
                <button
                  className="hist-del"
                  onClick={() => onDelete(h.id)}
                  title="Delete this scan"
                >
                  <Icon name="trash" size={13} />
                </button>
              )}
            </div>
          ))
        )}
      </div>
    </section>
  );
}

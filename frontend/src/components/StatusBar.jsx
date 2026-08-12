const LABELS = {
  idle: "Idle",
  connecting: "Connecting…",
  scanning: "Scanning",
  done: "Complete",
  error: "Error",
  stopped: "Stopped",
};

export default function StatusBar({ status, elapsed, logCount, target, tool }) {
  return (
    <footer className="statusbar">
      <span className={`status-chip status-${status}`}>
        <span className="status-led" />
        {LABELS[status] || status}
      </span>
      <span className="status-seg">
        <b>Target</b> {target || "—"}
      </span>
      <span className="status-seg">
        <b>Module</b> {tool || "—"}
      </span>
      <span className="status-spacer" />
      <span className="status-seg mono">{logCount} lines</span>
      <span className="status-seg mono">{elapsed.toFixed(1)}s</span>
    </footer>
  );
}

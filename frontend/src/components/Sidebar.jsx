import Icon from "./Icon";

export default function Sidebar({ tools, selected, onSelect, connected, disabled }) {
  return (
    <aside className="sidebar">
      <div className="brand">
        <div className="brand-mark">
          <Icon name="shield" size={20} />
        </div>
        <div className="brand-text">
          <span className="brand-name">RECON-X</span>
          <span className="brand-sub">recon console</span>
        </div>
      </div>

      <div className="nav-label">Modules</div>
      <nav className="tool-nav">
        {tools.map((tool) => (
          <button
            key={tool.id}
            className={`tool-item ${selected === tool.id ? "active" : ""}`}
            onClick={() => !disabled && onSelect(tool.id)}
            disabled={disabled}
            title={tool.description}
          >
            <span className="tool-icon">
              <Icon name={tool.icon} size={18} />
            </span>
            <span className="tool-meta">
              <span className="tool-name">{tool.name}</span>
              <span className="tool-desc">{tool.description}</span>
            </span>
          </button>
        ))}
      </nav>

      <div className="sidebar-foot">
        <span className={`conn-dot ${connected ? "online" : "offline"}`} />
        <span className="conn-text">
          {connected ? "Engine online" : "Engine offline"}
        </span>
      </div>
    </aside>
  );
}

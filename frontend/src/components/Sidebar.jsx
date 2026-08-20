import Icon from "./Icon";

// Two top-level product areas. The manual recon console and the automated
// purple-team suite are deliberately kept apart so the UI reads cleanly:
// pick an area up top, then its own navigation appears below.
const SECTIONS = [
  { id: "recon", name: "Recon Console", desc: "Manual scanners", icon: "radar" },
  { id: "purple", name: "Purple Team", desc: "Automated pentest", icon: "bolt" },
];

export default function Sidebar({
  section,
  onSection,
  tools,
  selected,
  onSelect,
  purpleItems = [],
  purpleSelected,
  onPurpleSelect,
  connected,
  disabled,
}) {
  return (
    <aside className="sidebar">
      <div className="brand">
        <img src="/logo-mark.png" alt="RedOpsX" className="brand-logo" />
        <div className="brand-text">
          <span className="brand-name">RedOpsX</span>
          <span className="brand-sub">offensive security platform</span>
        </div>
      </div>

      {/* Primary area switch */}
      <div className="nav-label">Workspace</div>
      <nav className="section-nav">
        {SECTIONS.map((s) => (
          <button
            key={s.id}
            className={`section-item ${section === s.id ? "active" : ""}`}
            onClick={() => onSection(s.id)}
            title={s.desc}
          >
            <span className="section-icon">
              <Icon name={s.icon} size={18} />
            </span>
            <span className="section-meta">
              <span className="section-name">{s.name}</span>
              <span className="section-desc">{s.desc}</span>
            </span>
          </button>
        ))}
      </nav>

      {/* Contextual navigation for the active area */}
      {section === "recon" ? (
        <>
          <div className="nav-label">Scan Modules</div>
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
        </>
      ) : (
        <>
          <div className="nav-label">Automation</div>
          <nav className="tool-nav">
            {purpleItems.map((item) => (
              <button
                key={item.id}
                className={`tool-item ${purpleSelected === item.id ? "active" : ""}`}
                onClick={() => onPurpleSelect(item.id)}
                title={item.desc}
              >
                <span className="tool-icon">
                  <Icon name={item.icon} size={18} />
                </span>
                <span className="tool-meta">
                  <span className="tool-name">{item.name}</span>
                  <span className="tool-desc">{item.desc}</span>
                </span>
              </button>
            ))}
          </nav>
        </>
      )}

      <div className="sidebar-foot">
        <span className={`conn-dot ${connected ? "online" : "offline"}`} />
        <span className="conn-text">
          {connected ? "Engine online" : "Engine offline"}
        </span>
      </div>
    </aside>
  );
}

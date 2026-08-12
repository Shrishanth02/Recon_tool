import Icon from "./Icon";

export default function ScanForm({
  tool,
  target,
  onTargetChange,
  options,
  onOptionChange,
  onRun,
  onStop,
  isRunning,
}) {
  if (!tool) return null;

  const submit = (e) => {
    e.preventDefault();
    if (!isRunning) onRun();
  };

  return (
    <form className="scanform" onSubmit={submit}>
      <div className="scanform-head">
        <span className="scanform-icon">
          <Icon name={tool.icon} size={20} />
        </span>
        <div>
          <h2 className="scanform-title">{tool.name}</h2>
          <p className="scanform-sub">{tool.description}</p>
        </div>
      </div>

      <div className="scanform-controls">
        <div className="field">
          <label>{tool.target_label}</label>
          <input
            value={target}
            onChange={(e) => onTargetChange(e.target.value)}
            placeholder={tool.placeholder}
            spellCheck={false}
            autoComplete="off"
          />
        </div>

        {(tool.options || []).map((opt) => (
          <div className="field field-select" key={opt.key}>
            <label>{opt.label}</label>
            <select
              value={options[opt.key] ?? opt.default}
              onChange={(e) => onOptionChange(opt.key, e.target.value)}
            >
              {opt.choices.map((c) => (
                <option key={c.value} value={c.value}>
                  {c.label}
                </option>
              ))}
            </select>
          </div>
        ))}

        {isRunning ? (
          <button type="button" className="btn btn-stop" onClick={onStop}>
            <Icon name="stop" size={15} /> Stop
          </button>
        ) : (
          <button type="submit" className="btn btn-run" disabled={!target.trim()}>
            <Icon name="play" size={15} /> Start Scan
          </button>
        )}
      </div>
    </form>
  );
}

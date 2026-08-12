import { useEffect, useRef, useState } from "react";
import Icon from "./Icon";

function lineClass(line) {
  if (line.startsWith("$ ")) return "ln-cmd";
  if (line.startsWith("✔")) return "ln-ok";
  if (line.startsWith("⏹")) return "ln-warn";
  const l = line.toLowerCase();
  if (l.includes("open")) return "ln-ok";
  if (l.includes("filtered") || l.includes("closed")) return "ln-dim";
  if (l.includes("error") || l.includes("failed")) return "ln-err";
  return "";
}

export default function LiveTerminal({ logs, isRunning, status }) {
  const bodyRef = useRef(null);
  const [stick, setStick] = useState(true);

  useEffect(() => {
    if (stick && bodyRef.current) {
      bodyRef.current.scrollTop = bodyRef.current.scrollHeight;
    }
  }, [logs, stick]);

  const onScroll = () => {
    const el = bodyRef.current;
    if (!el) return;
    const atBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 24;
    setStick(atBottom);
  };

  return (
    <section className="panel terminal">
      <header className="panel-head">
        <span className="panel-title">
          <Icon name="terminal" size={15} /> Live Output
        </span>
        <span className={`stream-badge ${isRunning ? "live" : ""}`}>
          {isRunning ? (
            <>
              <span className="rec-dot" /> streaming
            </>
          ) : (
            `${logs.length} lines`
          )}
        </span>
      </header>

      <div className="terminal-body" ref={bodyRef} onScroll={onScroll}>
        {logs.length === 0 && !isRunning && (
          <div className="terminal-empty">
            <Icon name="terminal" size={28} />
            <p>Awaiting target. Console output will stream here in real time.</p>
          </div>
        )}
        {logs.map((line, i) => (
          <div className={`term-line ${lineClass(line)}`} key={i}>
            {line}
          </div>
        ))}
        {isRunning && (
          <div className="term-line cursor-line">
            <span className="cursor" />
          </div>
        )}
      </div>

      {!stick && (
        <button className="jump-bottom" onClick={() => setStick(true)}>
          Jump to latest ↓
        </button>
      )}
    </section>
  );
}

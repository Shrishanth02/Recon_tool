import { useCallback, useEffect, useState } from "react";
import Icon from "./Icon";
import {
  fetchSchedules,
  createSchedule,
  deleteSchedule,
  toggleSchedule,
} from "../api/client";

// Small panel: list a workspace's recurring scans and create / delete / toggle
// them. Cron is entered as a raw string (validated server-side) — the placeholder
// shows the common "every day at 02:00" form.
export default function SchedulesPanel({ workspaceId, tools = [] }) {
  const [schedules, setSchedules] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [busyId, setBusyId] = useState(null);

  const [tool, setTool] = useState("");
  const [target, setTarget] = useState("");
  const [cron, setCron] = useState("");
  const [creating, setCreating] = useState(false);

  const load = useCallback(async () => {
    if (!workspaceId) {
      setSchedules([]);
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const list = await fetchSchedules(workspaceId);
      setSchedules(list);
    } catch (e) {
      setError(e?.message || "Failed to load schedules");
    } finally {
      setLoading(false);
    }
  }, [workspaceId]);

  useEffect(() => {
    load();
  }, [load]);

  // Seed the tool select once the tool list arrives.
  useEffect(() => {
    if (!tool && tools.length) setTool(tools[0].id);
  }, [tools, tool]);

  const onCreate = useCallback(
    async (e) => {
      e.preventDefault();
      if (!workspaceId || !tool || !target.trim() || !cron.trim() || creating) return;
      setCreating(true);
      setError(null);
      try {
        await createSchedule(workspaceId, {
          tool,
          target: target.trim(),
          cron: cron.trim(),
        });
        setTarget("");
        setCron("");
        await load();
      } catch (err) {
        setError(err?.message || "Failed to create schedule");
      } finally {
        setCreating(false);
      }
    },
    [workspaceId, tool, target, cron, creating, load]
  );

  const onToggle = useCallback(
    async (s) => {
      setBusyId(s.id);
      setError(null);
      try {
        await toggleSchedule(s.id, !s.enabled);
        await load();
      } catch (err) {
        setError(err?.message || "Failed to toggle schedule");
      } finally {
        setBusyId(null);
      }
    },
    [load]
  );

  const onDelete = useCallback(
    async (s) => {
      setBusyId(s.id);
      setError(null);
      try {
        await deleteSchedule(s.id);
        await load();
      } catch (err) {
        setError(err?.message || "Failed to delete schedule");
      } finally {
        setBusyId(null);
      }
    },
    [load]
  );

  const toolLabel = (id) => tools.find((t) => t.id === id)?.name || id;

  return (
    <section className="panel schedules-panel">
      <header className="panel-head">
        <span className="panel-title">
          <Icon name="history" size={15} /> Schedules
          {schedules.length > 0 && <span className="sched-count">{schedules.length}</span>}
        </span>
      </header>

      <div className="results-body">
        <form className="sched-form" onSubmit={onCreate}>
          <div className="sched-form-row">
            <select
              className="sched-input sched-tool"
              value={tool}
              onChange={(e) => setTool(e.target.value)}
              disabled={!tools.length}
            >
              {!tools.length && <option value="">No tools</option>}
              {tools.map((t) => (
                <option key={t.id} value={t.id}>
                  {t.name}
                </option>
              ))}
            </select>
            <input
              className="sched-input"
              placeholder="target (e.g. example.com)"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
            />
          </div>
          <div className="sched-form-row">
            <input
              className="sched-input sched-cron mono"
              placeholder="cron — e.g. 0 2 * * *"
              value={cron}
              onChange={(e) => setCron(e.target.value)}
            />
            <button
              className="btn btn-run sched-add"
              type="submit"
              disabled={creating || !workspaceId || !tool || !target.trim() || !cron.trim()}
            >
              <Icon name="play" size={13} /> {creating ? "Adding…" : "Add"}
            </button>
          </div>
        </form>

        {error && (
          <div className="result-error triage-note">
            <Icon name="x" size={16} /> {error}
          </div>
        )}

        {loading && schedules.length === 0 ? (
          <div className="muted sched-empty">Loading schedules…</div>
        ) : schedules.length === 0 ? (
          <div className="results-empty">
            <Icon name="history" size={28} />
            <p>No recurring scans yet. Add one above to run a tool on a cron schedule.</p>
          </div>
        ) : (
          <div className="sched-list">
            {schedules.map((s) => (
              <div className={`sched-item ${s.enabled ? "" : "sched-off"}`} key={s.id}>
                <div className="sched-main">
                  <div className="sched-line1">
                    <span className="sched-toolname">{toolLabel(s.tool)}</span>
                    <span className={`pill ${s.enabled ? "pill-ok" : "pill-dim"}`}>
                      {s.enabled ? "active" : "paused"}
                    </span>
                  </div>
                  <div className="sched-target mono">{s.target}</div>
                  <div className="sched-cron mono">
                    <Icon name="history" size={12} /> {s.cron}
                    {s.next_run_at && (
                      <span className="sched-next">
                        next {new Date(s.next_run_at).toLocaleString()}
                      </span>
                    )}
                  </div>
                </div>
                <div className="sched-actions">
                  <button
                    className="btn-ghost sched-btn"
                    onClick={() => onToggle(s)}
                    disabled={busyId === s.id}
                    title={s.enabled ? "Pause" : "Resume"}
                  >
                    <Icon name={s.enabled ? "stop" : "play"} size={13} />
                  </button>
                  <button
                    className="btn-ghost sched-btn sched-del"
                    onClick={() => onDelete(s)}
                    disabled={busyId === s.id}
                    title="Delete"
                  >
                    <Icon name="trash" size={13} />
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </section>
  );
}

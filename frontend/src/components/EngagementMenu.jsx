import { useState, useRef, useEffect } from "react";
import { useAuth } from "../auth/AuthContext";
import { updateScope } from "../api/client";
import Icon from "./Icon";

/**
 * EngagementMenu — the single top-bar control for "which client am I working
 * on, and what am I allowed to touch."
 *
 * It merges what used to be two separate boxes (the engagement/workspace picker
 * and the scope pill) into one self-explanatory control, because they are two
 * halves of the same idea:
 *
 *   • an ENGAGEMENT (workspace) is one client/project — it owns that client's
 *     scans, findings, reports and authorized scope; you make one per client;
 *   • the SCOPE is the list of targets that engagement is allowed to scan (the
 *     authorization gate every scan/emulation/exploit is checked against).
 *
 * The button shows the active engagement + a short scope hint. The popover lets
 * you switch engagement, create a new one, and edit that engagement's scope.
 */
export default function EngagementMenu({ disabled }) {
  const {
    orgs,
    activeOrg,
    selectOrg,
    workspaces,
    activeWorkspace,
    selectWorkspace,
    createEngagement,
    refreshWorkspaces,
  } = useAuth();

  const ws = activeWorkspace;
  const scope = ws?.scope || [];

  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState(null);
  const [scopeVal, setScopeVal] = useState(""); // add-target field
  const [creating, setCreating] = useState(false); // new-engagement form shown
  const [newName, setNewName] = useState("");
  const [newScope, setNewScope] = useState("");
  const ref = useRef(null);

  // Close on outside-click / Escape.
  useEffect(() => {
    if (!open) return;
    const onDoc = (e) => {
      if (ref.current && !ref.current.contains(e.target)) setOpen(false);
    };
    const onEsc = (e) => e.key === "Escape" && setOpen(false);
    document.addEventListener("mousedown", onDoc);
    document.addEventListener("keydown", onEsc);
    return () => {
      document.removeEventListener("mousedown", onDoc);
      document.removeEventListener("keydown", onEsc);
    };
  }, [open]);

  if (!ws) {
    // Signed in but no workspace yet — keep a neutral placeholder.
    return (
      <div className="eng-menu">
        <button className="eng-btn" disabled>
          <Icon name="folder" size={14} /> No engagement
        </button>
      </div>
    );
  }

  // ---- scope helpers ------------------------------------------------------ //
  const saveScope = async (next) => {
    setBusy(true);
    setErr(null);
    try {
      await updateScope(ws.id, next);
      await refreshWorkspaces();
    } catch (e) {
      setErr(e?.message || "Could not update scope.");
    } finally {
      setBusy(false);
    }
  };
  const addTarget = async (e) => {
    e?.preventDefault();
    const t = scopeVal.trim();
    if (!t) return;
    if (!scope.includes(t)) await saveScope([...scope, t]);
    setScopeVal("");
  };
  const removeTarget = (t) => saveScope(scope.filter((s) => s !== t));
  const setAny = () => saveScope(["*"]);

  // ---- new engagement ----------------------------------------------------- //
  const createEng = async (e) => {
    e?.preventDefault();
    const name = newName.trim();
    if (!name) return;
    setBusy(true);
    setErr(null);
    try {
      const initial = newScope
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean);
      await createEngagement({ name, scope: initial });
      setNewName("");
      setNewScope("");
      setCreating(false);
    } catch (e2) {
      setErr(e2?.message || "Could not create engagement.");
    } finally {
      setBusy(false);
    }
  };

  const isAny = scope.includes("*");
  const unrestricted = scope.length === 0;
  const scopeLabel = unrestricted
    ? "scope: unrestricted"
    : isAny
    ? "scope: any (*)"
    : `scope: ${scope.length} target${scope.length > 1 ? "s" : ""}`;
  const scopeTone = unrestricted ? "warn" : "ok";

  return (
    <div className="eng-menu" ref={ref}>
      <button
        className={`eng-btn ${open ? "open" : ""}`}
        onClick={() => setOpen((o) => !o)}
        disabled={disabled}
        title="Engagement — the client/project you're working on, and its authorized scope"
      >
        <Icon name="folder" size={14} />
        <span className="eng-btn-name">{ws.name}</span>
        <span className={`eng-btn-scope tone-${scopeTone}`}>{scopeLabel}</span>
        <span className="eng-btn-caret">▾</span>
      </button>

      {open && (
        <div className="eng-pop" role="dialog">
          {/* Organization (only when the user belongs to more than one) */}
          {orgs.length > 1 && (
            <label className="eng-field">
              <span className="eng-field-label">Organization</span>
              <select
                value={activeOrg?.id ?? ""}
                onChange={(e) => selectOrg(e.target.value)}
                disabled={busy}
              >
                {orgs.map((o) => (
                  <option key={o.id} value={o.id}>
                    {o.name}
                  </option>
                ))}
              </select>
            </label>
          )}

          {/* Engagement switcher */}
          <label className="eng-field">
            <span className="eng-field-label">Engagement (client / project)</span>
            <select
              value={ws.id}
              onChange={(e) => selectWorkspace(e.target.value)}
              disabled={busy || workspaces.length === 0}
            >
              {workspaces.map((w) => (
                <option key={w.id} value={w.id}>
                  {w.name}
                </option>
              ))}
            </select>
          </label>

          {/* + New engagement */}
          {!creating ? (
            <button
              className="eng-new-btn"
              onClick={() => setCreating(true)}
              disabled={busy}
            >
              <Icon name="plus" size={12} /> New engagement
            </button>
          ) : (
            <form className="eng-new-form" onSubmit={createEng}>
              <input
                value={newName}
                onChange={(e) => setNewName(e.target.value)}
                placeholder="client / project name — e.g. Acme Corp"
                autoFocus
                disabled={busy}
                spellCheck={false}
              />
              <input
                value={newScope}
                onChange={(e) => setNewScope(e.target.value)}
                placeholder="scope (optional) — e.g. acme.com, *.acme.com"
                disabled={busy}
                spellCheck={false}
                autoComplete="off"
              />
              <div className="eng-new-actions">
                <button type="submit" disabled={busy || !newName.trim()}>
                  Create
                </button>
                <button
                  type="button"
                  className="eng-link"
                  onClick={() => {
                    setCreating(false);
                    setNewName("");
                    setNewScope("");
                  }}
                  disabled={busy}
                >
                  Cancel
                </button>
              </div>
            </form>
          )}

          <div className="eng-divider" />

          {/* Authorized scope for the active engagement */}
          <div className="eng-scope">
            <div className="eng-scope-head">
              <span className="eng-field-label">Authorized scope</span>
              <span className={`eng-scope-badge tone-${scopeTone}`}>
                {unrestricted ? "unrestricted" : isAny ? "any (*)" : `${scope.length}`}
              </span>
            </div>
            <p className="eng-scope-sub">
              Targets <b>{ws.name}</b> is allowed to scan. Type <code>*</code> to
              allow any. Out-of-scope targets are blocked.
            </p>

            <div className="eng-scope-chips">
              {unrestricted && (
                <span className="scope-chip scope-chip-warn">
                  Warning: unrestricted — every target allowed
                </span>
              )}
              {scope.map((s) => (
                <span
                  key={s}
                  className={`scope-chip${s === "*" ? " scope-chip-any" : ""}`}
                >
                  {s === "*" ? "any target (*)" : s}
                  <button
                    className="scope-chip-x"
                    onClick={() => removeTarget(s)}
                    disabled={busy}
                    title="Remove"
                  >
                    <Icon name="x" size={10} />
                  </button>
                </span>
              ))}
            </div>

            <form className="eng-scope-form" onSubmit={addTarget}>
              <input
                value={scopeVal}
                onChange={(e) => setScopeVal(e.target.value)}
                placeholder="add target — domain, IP, CIDR, or *"
                disabled={busy}
                spellCheck={false}
                autoComplete="off"
              />
              <button type="submit" disabled={busy || !scopeVal.trim()}>
                Add
              </button>
            </form>

            {!isAny && (
              <button className="eng-link" onClick={setAny} disabled={busy}>
                Set to any (*)
              </button>
            )}
          </div>

          {err && <div className="eng-err">{err}</div>}
        </div>
      )}
    </div>
  );
}

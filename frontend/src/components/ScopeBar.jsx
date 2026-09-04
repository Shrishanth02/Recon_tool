import { useState } from "react";
import { useAuth } from "../auth/AuthContext";
import { updateScope } from "../api/client";
import Icon from "./Icon";

/**
 * ScopeBar — the engagement's authorized-target editor.
 *
 * Scope is the operator-defined authorization record every scan/emulation/exploit
 * is checked against. This bar makes it self-serve: see the current scope, add or
 * remove targets (domain, IP, CIDR, or a wildcard), or set it to "any target" (`*`)
 * in one click. An empty scope is treated as unrestricted by the backend.
 */
export default function ScopeBar() {
  const { activeWorkspace, refreshWorkspaces } = useAuth();
  const ws = activeWorkspace;
  const scope = ws?.scope || [];
  const [val, setVal] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState(null);

  const save = async (next) => {
    if (!ws) return;
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

  const add = async (e) => {
    e?.preventDefault();
    const t = val.trim();
    if (!t) return;
    if (!scope.includes(t)) await save([...scope, t]);
    setVal("");
  };
  const remove = (t) => save(scope.filter((s) => s !== t));
  const setGlobal = () => save(["*"]);

  const isAny = scope.includes("*");
  const unrestricted = scope.length === 0 || isAny;

  if (!ws) return null;

  return (
    <div className="scopebar">
      <span className="scopebar-label" title="Authorized targets for this engagement">
        <Icon name="shield" size={13} /> Scope
      </span>

      <div className="scopebar-chips">
        {scope.length === 0 && (
          <span
            className="scope-chip scope-chip-warn"
            title="No scope is set, so EVERY target is allowed. Add a target below (or type * ) to define this engagement's scope."
          >
            Warning: unrestricted — every target allowed
          </span>
        )}
        {scope.map((s) => (
          <span key={s} className={`scope-chip${s === "*" ? " scope-chip-any" : ""}`}>
            {s === "*" ? "any target (*)" : s}
            <button
              className="scope-chip-x"
              onClick={() => remove(s)}
              disabled={busy}
              title="Remove"
            >
              <Icon name="x" size={10} />
            </button>
          </span>
        ))}
      </div>

      <form className="scopebar-form" onSubmit={add}>
        <input
          value={val}
          onChange={(e) => setVal(e.target.value)}
          placeholder="add target — domain, IP, CIDR, or *"
          disabled={busy}
          spellCheck={false}
          autoComplete="off"
        />
        <button type="submit" disabled={busy || !val.trim()}>
          Add
        </button>
      </form>

      {!unrestricted && (
        <button
          className="scopebar-any"
          onClick={setGlobal}
          disabled={busy}
          title="Authorize any target (global wildcard)"
        >
          Set to any (*)
        </button>
      )}
      {err && <span className="scopebar-err">{err}</span>}
    </div>
  );
}

import Icon from "./Icon";
import { useAuth } from "../auth/AuthContext";

// Tenant picker: choose the active organization and, within it, the active
// workspace (engagement). Everything the dashboard shows is scoped to
// `activeWorkspace.id`. Rendered in the top bar.
export default function OrgSwitcher({ disabled }) {
  const {
    orgs,
    activeOrg,
    workspaces,
    activeWorkspace,
    selectOrg,
    selectWorkspace,
  } = useAuth();

  const ws = activeWorkspace;

  return (
    <div className="org-switcher">
      <div className="org-field">
        <label>Organization</label>
        <select
          value={activeOrg?.id ?? ""}
          onChange={(e) => selectOrg(e.target.value)}
          disabled={disabled || orgs.length === 0}
          title="Active organization"
        >
          {orgs.length === 0 && <option value="">No organizations</option>}
          {orgs.map((o) => (
            <option key={o.id} value={o.id}>
              {o.name}
            </option>
          ))}
        </select>
      </div>

      <span className="org-sep">
        <Icon name="swap" size={14} />
      </span>

      <div className="org-field">
        <label>Workspace</label>
        <select
          value={ws?.id ?? ""}
          onChange={(e) => selectWorkspace(e.target.value)}
          disabled={disabled || workspaces.length === 0}
          title="Active engagement"
        >
          {workspaces.length === 0 && <option value="">No workspaces</option>}
          {workspaces.map((w) => (
            <option key={w.id} value={w.id}>
              {w.name}
            </option>
          ))}
        </select>
      </div>

      {ws && (
        <div className="org-stats" title="Scans · findings in this engagement">
          <span>
            <Icon name="radar" size={12} /> {ws.scan_count ?? 0}
          </span>
          <span>
            <Icon name="bug" size={12} /> {ws.finding_count ?? 0}
          </span>
          {ws.scope?.length > 0 && (
            <span className="accent">
              <Icon name="shield" size={12} /> {ws.scope.length}
            </span>
          )}
        </div>
      )}
    </div>
  );
}

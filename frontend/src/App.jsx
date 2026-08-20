import { useCallback, useEffect, useMemo, useState } from "react";
import "./App.css";
import {
  fetchTools,
  fetchWorkspaceScans,
  fetchWorkspaceFindings,
  fetchScan,
  deleteScan,
  clearWorkspaceScans,
} from "./api/client";
import { AuthProvider, useAuth } from "./auth/AuthContext";
import { useScan } from "./hooks/useScan";
import Sidebar from "./components/Sidebar";
import ScanForm from "./components/ScanForm";
import LiveTerminal from "./components/LiveTerminal";
import ResultsPanel from "./components/ResultsPanel";
import FindingsPanel from "./components/FindingsPanel";
import AttackMatrix from "./components/AttackMatrix";
import EmulationPanel from "./components/EmulationPanel";
import CoveragePanel from "./components/CoveragePanel";
import ExploitPanel from "./components/ExploitPanel";
import SchedulesPanel from "./components/SchedulesPanel";
import ScanHistory from "./components/ScanHistory";
import StatusBar from "./components/StatusBar";
import Login from "./components/Login";
import EngagementMenu from "./components/EngagementMenu";
import BillingPanel from "./components/BillingPanel";
import SettingsPanel from "./components/SettingsPanel";
import ThemeToggle from "./components/ThemeToggle";
import Icon from "./components/Icon";
import AutoPentestPanel from "./components/AutoPentestPanel";
import PurpleHistory from "./components/PurpleHistory";

// The automated purple-team suite — its own navigation, separate from the
// manual recon scanners. Order follows the pentest lifecycle:
// run → map → emulate → validate → exploit → schedule.
const PURPLE_ITEMS = [
  { id: "autopent", name: "Auto-Pentest", desc: "End-to-end automation", icon: "play" },
  { id: "phistory", name: "Run History", desc: "Past auto-pentest runs", icon: "history" },
  { id: "attack", name: "ATT&CK Coverage", desc: "Technique mapping", icon: "cpu" },
  { id: "emulate", name: "Emulate", desc: "Safe adversary emulation", icon: "pulse" },
  { id: "coverage", name: "Coverage", desc: "Detection posture", icon: "shield" },
  { id: "exploit", name: "Exploit", desc: "Human-gated validation", icon: "bug" },
  { id: "schedules", name: "Schedules", desc: "Recurring automation", icon: "history" },
];

// Top-level shell: provide auth/tenancy context, then gate on it.
export default function App() {
  return (
    <AuthProvider>
      <Root />
    </AuthProvider>
  );
}

function Root() {
  const { booting, isAuthenticated } = useAuth();

  if (booting) {
    return (
      <div className="auth-screen">
        <div className="auth-boot">
          <span className="rec-dot" />
          Restoring session…
        </div>
      </div>
    );
  }
  if (!isAuthenticated) return <Login />;
  return <Dashboard />;
}

function Dashboard() {
  const { user, activeOrg, activeWorkspace, logout, refreshWorkspaces } = useAuth();
  const workspaceId = activeWorkspace?.id ?? null;
  const orgId = activeOrg?.id ?? null;

  const [showBilling, setShowBilling] = useState(false);
  const [showSettings, setShowSettings] = useState(false);

  // Two top-level areas: manual recon vs the automated purple-team suite.
  const [section, setSection] = useState("recon"); // recon | purple
  const [purpleTab, setPurpleTab] = useState("autopent"); // autopent | attack | emulate | coverage | exploit | schedules

  const [tools, setTools] = useState([]);
  const [connected, setConnected] = useState(false);
  const [selected, setSelected] = useState(null);
  const [target, setTarget] = useState("");
  const [optionsByTool, setOptionsByTool] = useState({});
  const [rightTab, setRightTab] = useState("results"); // results | findings | history

  const [findings, setFindings] = useState([]);
  const [scans, setScans] = useState([]);

  // When viewing a stored scan from history, override the live panels.
  const [historyView, setHistoryView] = useState(null);

  const refreshWorkspace = useCallback(async (wsId) => {
    if (!wsId) return;
    try {
      const [f, s] = await Promise.all([
        fetchWorkspaceFindings(wsId),
        fetchWorkspaceScans(wsId),
      ]);
      setFindings(f);
      setScans(s);
    } catch {
      /* backend may be momentarily unavailable */
    }
  }, []);

  const onComplete = useCallback(() => {
    refreshWorkspace(workspaceId);
    // Keep the switcher's per-engagement scan/finding counts fresh.
    refreshWorkspaces();
  }, [workspaceId, refreshWorkspace, refreshWorkspaces]);

  const { status, logs, result, error, elapsed, isRunning, startScan, stopScan } =
    useScan(onComplete);

  // Bootstrap: tools (workspace-independent).
  useEffect(() => {
    let alive = true;
    (async () => {
      try {
        const list = await fetchTools();
        if (!alive) return;
        setTools(list);
        setConnected(true);
        setSelected((cur) => cur || list[0]?.id || null);
        const defaults = {};
        for (const t of list) {
          defaults[t.id] = {};
          for (const o of t.options || []) defaults[t.id][o.key] = o.default;
        }
        setOptionsByTool((prev) => ({ ...defaults, ...prev }));
      } catch {
        if (alive) setConnected(false);
      }
    })();
    return () => {
      alive = false;
    };
  }, []);

  // Load findings + scans whenever the active workspace changes.
  useEffect(() => {
    setHistoryView(null);
    setFindings([]);
    setScans([]);
    if (workspaceId) refreshWorkspace(workspaceId);
  }, [workspaceId, refreshWorkspace]);

  const tool = useMemo(() => tools.find((t) => t.id === selected) || null, [tools, selected]);
  const toolNames = useMemo(
    () => Object.fromEntries(tools.map((t) => [t.id, t.name])),
    [tools]
  );

  const handleSelect = (id) => {
    setSelected(id);
    setTarget("");
    setHistoryView(null);
  };

  const handleOptionChange = (key, value) => {
    setOptionsByTool((prev) => ({
      ...prev,
      [selected]: { ...(prev[selected] || {}), [key]: value },
    }));
  };

  const run = () => {
    if (!tool || !target.trim() || !workspaceId) return;
    setHistoryView(null);
    setRightTab("results");
    startScan({
      tool: tool.id,
      target: target.trim(),
      options: optionsByTool[tool.id] || {},
      workspaceId,
    });
  };

  const replay = async (scanId) => {
    try {
      const scan = await fetchScan(scanId);
      setHistoryView({
        tool: scan.tool,
        target: scan.target,
        logs: scan.logs || [],
        result: scan.result,
        error: scan.error,
      });
      setRightTab("results");
    } catch {
      /* ignore */
    }
  };

  const deleteHistoryScan = async (scanId) => {
    try {
      await deleteScan(scanId);
      if (historyView) setHistoryView(null);
      refreshWorkspace(workspaceId);
      refreshWorkspaces();
    } catch {
      /* ignore — a failed delete just leaves the row */
    }
  };

  const clearAllHistory = async () => {
    if (!workspaceId) return;
    if (
      !window.confirm(
        "Delete ALL scan history and findings for this engagement? This cannot be undone."
      )
    )
      return;
    try {
      await clearWorkspaceScans(workspaceId);
      setHistoryView(null);
      refreshWorkspace(workspaceId);
      refreshWorkspaces();
    } catch {
      /* ignore */
    }
  };

  const exportJson = () => {
    const data = historyView ? historyView.result : result;
    const t = historyView ? historyView.tool : tool?.id;
    if (!data) return;
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `reconx-${t}-${target || "scan"}.json`.replace(/[^\w.-]+/g, "_");
    a.click();
    URL.revokeObjectURL(url);
  };

  // What the panels display: a stored scan (historyView) or the live scan.
  const viewLogs = historyView ? historyView.logs : logs;
  const viewResult = historyView ? historyView.result : result;
  const viewError = historyView ? historyView.error : error;
  const viewToolId = historyView ? historyView.tool : tool?.id;

  return (
    <div className="layout">
      <Sidebar
        section={section}
        onSection={setSection}
        tools={tools}
        selected={selected}
        onSelect={handleSelect}
        purpleItems={PURPLE_ITEMS}
        purpleSelected={purpleTab}
        onPurpleSelect={setPurpleTab}
        connected={connected}
        disabled={isRunning}
      />

      <main className="main">
        <header className="topbar">
          <EngagementMenu disabled={isRunning} />
          <div className="topbar-spacer" />
          <ThemeToggle />
          <button
            className="btn-ghost"
            onClick={() => setShowBilling(true)}
            disabled={!orgId}
            title="Plan, usage & billing"
          >
            <Icon name="shield" size={14} /> Billing
          </button>
          <button
            className="btn-ghost"
            onClick={() => setShowSettings(true)}
            disabled={!orgId}
            title="Branding, SSO, security & audit"
          >
            <Icon name="cpu" size={14} /> Settings
          </button>
          <div className="user-chip" title={user?.email}>
            <span className="user-name">{user?.full_name || user?.email}</span>
            <button className="btn-ghost" onClick={logout} title="Sign out">
              <Icon name="swap" size={14} /> Sign out
            </button>
          </div>
        </header>

        {section === "recon" ? (
          <>
            <ScanForm
              tool={tool}
              target={target}
              onTargetChange={setTarget}
              options={optionsByTool[selected] || {}}
              onOptionChange={handleOptionChange}
              onRun={run}
              onStop={stopScan}
              isRunning={isRunning}
            />

            <div className="workspace">
              <LiveTerminal logs={viewLogs} isRunning={isRunning && !historyView} status={status} />

              <div className="right-col">
                <div className="tabbar">
                  <button className={rightTab === "results" ? "tab active" : "tab"} onClick={() => setRightTab("results")}>
                    Results
                  </button>
                  <button className={rightTab === "findings" ? "tab active" : "tab"} onClick={() => setRightTab("findings")}>
                    Findings{findings.length ? ` · ${findings.length}` : ""}
                  </button>
                  <button className={rightTab === "history" ? "tab active" : "tab"} onClick={() => setRightTab("history")}>
                    History{scans.length ? ` · ${scans.length}` : ""}
                  </button>
                </div>

                {rightTab === "results" && (
                  <ResultsPanel
                    tool={viewToolId}
                    result={viewResult}
                    error={viewError}
                    status={status}
                    onExport={exportJson}
                  />
                )}
                {rightTab === "findings" && (
                  <FindingsPanel projectId={workspaceId} findings={findings} />
                )}
                {rightTab === "history" && (
                  <ScanHistory
                    scans={scans}
                    toolNames={toolNames}
                    onReplay={replay}
                    onDelete={deleteHistoryScan}
                    onClearAll={clearAllHistory}
                  />
                )}
              </div>
            </div>

            <StatusBar
              status={status}
              elapsed={elapsed}
              logCount={logs.length}
              target={historyView ? historyView.target : target}
              tool={tool?.name}
            />
          </>
        ) : (
          <div className="purple-area">
            <div className="purple-head">
              <div className="purple-head-main">
                <Icon name="bolt" size={16} />
                <span>Purple Team</span>
                <span className="purple-head-sep">/</span>
                <span className="purple-head-sub">
                  {(PURPLE_ITEMS.find((p) => p.id === purpleTab) || PURPLE_ITEMS[0]).name}
                </span>
              </div>
              <p className="purple-head-desc">
                Automated adversary emulation → detection validation → coverage → human-gated exploitation, run end-to-end against your authorized scope.
              </p>
            </div>

            <div className="right-col">
              {purpleTab === "autopent" && <AutoPentestPanel workspaceId={workspaceId} />}
              {purpleTab === "phistory" && <PurpleHistory workspaceId={workspaceId} />}
              {purpleTab === "attack" && <AttackMatrix workspaceId={workspaceId} />}
              {purpleTab === "emulate" && <EmulationPanel workspaceId={workspaceId} />}
              {purpleTab === "coverage" && <CoveragePanel workspaceId={workspaceId} />}
              {purpleTab === "exploit" && <ExploitPanel workspaceId={workspaceId} />}
              {purpleTab === "schedules" && (
                <SchedulesPanel workspaceId={workspaceId} tools={tools} />
              )}
            </div>
          </div>
        )}
      </main>

      {showBilling && (
        <div
          className="billing-overlay"
          onClick={() => setShowBilling(false)}
          role="presentation"
        >
          <div className="billing-modal" onClick={(e) => e.stopPropagation()}>
            <button
              className="billing-close btn-ghost"
              onClick={() => setShowBilling(false)}
              title="Close"
            >
              <Icon name="x" size={16} />
            </button>
            <BillingPanel orgId={orgId} />
          </div>
        </div>
      )}

      {showSettings && (
        <div
          className="billing-overlay"
          onClick={() => setShowSettings(false)}
          role="presentation"
        >
          <div className="billing-modal settings-modal" onClick={(e) => e.stopPropagation()}>
            <button
              className="billing-close btn-ghost"
              onClick={() => setShowSettings(false)}
              title="Close"
            >
              <Icon name="x" size={16} />
            </button>
            <SettingsPanel orgId={orgId} />
          </div>
        </div>
      )}
    </div>
  );
}

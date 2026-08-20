import { useCallback, useEffect, useRef, useState } from "react";
import { getPipelineWsUrl } from "../api/client";

// Stage metadata — mirrors backend STAGE_NAMES
export const STAGE_META = {
  1:  { name: "WHOIS Lookup",            icon: "id",         color: "#6c8ebf" },
  2:  { name: "Subdomain Enumeration",   icon: "globe",      color: "#82b366" },
  3:  { name: "HTTP Probe",              icon: "pulse",      color: "#d79b00" },
  4:  { name: "Port Scan",               icon: "radar",      color: "#ae4132" },
  5:  { name: "Tech Fingerprinting",     icon: "cpu",        color: "#9673a6" },
  6:  { name: "Vulnerability Scan",      icon: "bug",        color: "#c00000" },
  7:  { name: "Content Discovery",       icon: "folder",     color: "#007867" },
  8:  { name: "DNS Zone Transfer",       icon: "swap",       color: "#0050ef" },
  9:  { name: "Origin Discovery",        icon: "radar",      color: "#5b21b6" },
  10: { name: "Deep Crawl",              icon: "folderTree", color: "#7c3aed" },
  11: { name: "Web Audit",               icon: "shield",     color: "#0e7490" },
  12: { name: "Injection Scan",          icon: "bug",        color: "#b91c1c" },
  13: { name: "WAF Test",                icon: "shield",     color: "#b45309" },
  14: { name: "Subdomain Takeover",      icon: "globe",      color: "#7c3aed" },
  15: { name: "SSRF Probe",              icon: "radar",      color: "#0891b2" },
  16: { name: "IDOR / Authorization",    icon: "id",         color: "#be123c" },
  17: { name: "JWT / API Security",      icon: "shield",     color: "#4338ca" },
  18: { name: "CSRF Check",              icon: "shield",     color: "#9d174d" },
  19: { name: "Business Logic",          icon: "cpu",        color: "#7c2d12" },
  20: { name: "Summary",                 icon: "shield",     color: "#1b6b3a" },
};

//: The final Summary stage number (mirrors backend SUMMARY_STAGE).
export const SUMMARY_STAGE = 20;

const STAGE_COUNT = Object.keys(STAGE_META).length;

/**
 * usePipeline — drives the automated end-to-end pentest pipeline over WebSocket.
 *
 * Returns:
 *   status       "idle" | "connecting" | "running" | "done" | "stopped" | "error"
 *   stages       { [stageNum]: { status, logs, result } }
 *   summary      final pipeline_done payload (or null)
 *   activeStage  currently running stage number (or null)
 *   elapsed      seconds since start
 *   isRunning
 *   startPipeline({ target, workspaceId, config? })
 *   stopPipeline()
 */
export function usePipeline(onComplete) {
  const [status, setStatus] = useState("idle");
  const [stages, setStages] = useState({});
  const [summary, setSummary] = useState(null);
  const [activeStage, setActiveStage] = useState(null);
  const [elapsed, setElapsed] = useState(0);

  const wsRef = useRef(null);
  const timerRef = useRef(null);
  const startedRef = useRef(0);
  const completeRef = useRef(onComplete);
  completeRef.current = onComplete;

  const stopTimer = () => {
    if (timerRef.current) {
      clearInterval(timerRef.current);
      timerRef.current = null;
    }
  };

  const initStages = () => {
    const s = {};
    for (let i = 1; i <= STAGE_COUNT; i++) {
      s[i] = { status: "pending", logs: [], result: null };
    }
    return s;
  };

  const startPipeline = useCallback(({ target, workspaceId, config }) => {
    if (wsRef.current) {
      try { wsRef.current.close(); } catch (_) {}
    }
    setStatus("connecting");
    setStages(initStages());
    setSummary(null);
    setActiveStage(null);
    setElapsed(0);

    const ws = new WebSocket(getPipelineWsUrl());
    wsRef.current = ws;

    ws.onopen = () => {
      setStatus("running");
      startedRef.current = Date.now();
      stopTimer();
      timerRef.current = setInterval(() => {
        setElapsed((Date.now() - startedRef.current) / 1000);
      }, 200);
      ws.send(JSON.stringify({
        target,
        workspace_id: workspaceId,
        config: config || {},
      }));
    };

    ws.onmessage = (event) => {
      let msg;
      try { msg = JSON.parse(event.data); } catch { return; }

      switch (msg.type) {
        case "pipeline_stage": {
          const { stage, status: st } = msg;
          if (st === "started") setActiveStage(stage);
          else if (activeStage === stage) setActiveStage(null);
          setStages((prev) => ({
            ...prev,
            [stage]: { ...(prev[stage] || { logs: [], result: null }), status: st },
          }));
          break;
        }
        case "pipeline_log": {
          const { stage, data } = msg;
          setStages((prev) => {
            const cur = prev[stage] || { status: "running", result: null, logs: [] };
            return { ...prev, [stage]: { ...cur, logs: [...cur.logs, data] } };
          });
          break;
        }
        case "pipeline_result": {
          const { stage, data } = msg;
          setStages((prev) => {
            const cur = prev[stage] || { status: "running", logs: [] };
            return { ...prev, [stage]: { ...cur, result: data } };
          });
          break;
        }
        case "pipeline_done": {
          stopTimer();
          setSummary(msg.summary || {});
          setActiveStage(null);
          const finalStatus = "done";
          setStatus(finalStatus);
          completeRef.current?.({ target, summary: msg.summary });
          break;
        }
        default:
          break;
      }
    };

    ws.onerror = () => setStatus("error");
    ws.onclose = () => {
      stopTimer();
      setStatus((cur) =>
        cur === "running" || cur === "connecting" ? "done" : cur
      );
      setActiveStage(null);
    };
  }, []);

  const stopPipeline = useCallback(() => {
    const ws = wsRef.current;
    if (ws && ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({ action: "stop" }));
      setStatus("stopped");
    }
  }, []);

  useEffect(() => {
    return () => {
      stopTimer();
      if (wsRef.current) try { wsRef.current.close(); } catch (_) {}
    };
  }, []);

  const isRunning = status === "connecting" || status === "running";
  return {
    status, stages, summary, activeStage, elapsed, isRunning,
    startPipeline, stopPipeline,
  };
}

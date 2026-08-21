import { useCallback, useEffect, useRef, useState } from "react";
import { WS_URL, wsAuthProtocols } from "../api/client";

// Drives a single live scan over a WebSocket. Exposes streaming logs, the
// final structured result, status, and an elapsed-time counter. Calls
// onComplete(record) when a scan finishes so the caller can store history.
export function useScan(onComplete) {
  const [status, setStatus] = useState("idle"); // idle|connecting|scanning|done|error|stopped
  const [logs, setLogs] = useState([]);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [elapsed, setElapsed] = useState(0);
  const [active, setActive] = useState(null); // {tool, target}

  const wsRef = useRef(null);
  const timerRef = useRef(null);
  const startedRef = useRef(0);
  const stateRef = useRef({ logs: [], result: null, error: null, tool: null, target: null });
  const completeRef = useRef(onComplete);
  completeRef.current = onComplete;

  const stopTimer = () => {
    if (timerRef.current) {
      clearInterval(timerRef.current);
      timerRef.current = null;
    }
  };

  const finish = useCallback((finalStatus) => {
    stopTimer();
    const s = stateRef.current;
    const duration = startedRef.current
      ? (Date.now() - startedRef.current) / 1000
      : 0;
    if (s.tool) {
      completeRef.current?.({
        id: `${s.tool}-${startedRef.current}`,
        scanId: s.scanId,
        tool: s.tool,
        target: s.target,
        status: finalStatus,
        result: s.result,
        error: s.error,
        logCount: s.logs.length,
        duration,
        finishedAt: Date.now(),
      });
    }
  }, []);

  const startScan = useCallback(
    ({ tool, target, options, workspaceId, projectId }) => {
      if (wsRef.current) {
        try { wsRef.current.close(); } catch (_) {}
      }
      stateRef.current = { logs: [], result: null, error: null, tool, target, scanId: null };
      setLogs([]);
      setResult(null);
      setError(null);
      setElapsed(0);
      setActive({ tool, target });
      setStatus("connecting");

      const ws = new WebSocket(WS_URL, wsAuthProtocols());
      wsRef.current = ws;

      ws.onopen = () => {
        ws.send(
          JSON.stringify({
            tool,
            target,
            options: options || {},
            // Backend expects `workspace_id`; `projectId` kept as a fallback.
            workspace_id: workspaceId ?? projectId,
          })
        );
      };

      ws.onmessage = (event) => {
        let msg;
        try { msg = JSON.parse(event.data); } catch (_) { return; }

        switch (msg.type) {
          case "start": {
            setStatus("scanning");
            startedRef.current = Date.now();
            stopTimer();
            timerRef.current = setInterval(() => {
              setElapsed((Date.now() - startedRef.current) / 1000);
            }, 100);
            break;
          }
          case "log": {
            stateRef.current.logs.push(msg.data);
            setLogs((prev) => [...prev, msg.data]);
            break;
          }
          case "result": {
            stateRef.current.result = msg.data;
            setResult(msg.data);
            break;
          }
          case "error": {
            stateRef.current.error = msg.data;
            setError(msg.data);
            break;
          }
          case "saved": {
            stateRef.current.scanId = msg.scan_id;
            break;
          }
          case "done": {
            setStatus((cur) => {
              const next = stateRef.current.error
                ? "error"
                : cur === "stopped"
                ? "stopped"
                : "done";
              finish(next);
              return next;
            });
            break;
          }
          default:
            break;
        }
      };

      ws.onerror = () => {
        stateRef.current.error =
          stateRef.current.error || "Connection to scan engine failed.";
        setError((e) => e || "Connection to scan engine failed.");
      };

      ws.onclose = () => {
        stopTimer();
        setStatus((cur) =>
          cur === "scanning" || cur === "connecting"
            ? (stateRef.current.error ? "error" : "done")
            : cur
        );
      };
    },
    [finish]
  );

  const stopScan = useCallback(() => {
    const ws = wsRef.current;
    if (ws && ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({ action: "stop" }));
      setStatus("stopped");
    }
  }, []);

  useEffect(() => {
    return () => {
      stopTimer();
      if (wsRef.current) {
        try { wsRef.current.close(); } catch (_) {}
      }
    };
  }, []);

  const isRunning = status === "connecting" || status === "scanning";
  return { status, logs, result, error, elapsed, active, isRunning, startScan, stopScan };
}

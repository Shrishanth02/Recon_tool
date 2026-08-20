"""Real exploitation backend — Metasploit RPC integration.

This is the engine behind an *approved* exploit proposal when
``settings.REAL_EXPLOIT`` is on and a Metasploit RPC daemon (``msfrpcd``) is
reachable. It maps a finding to a real Metasploit module and runs it against the
target — either in **check** mode (safely verify exploitability, the default) or
**exploit** mode (fire the module and try to land a session).

Design boundaries (unchanged from the safe engine):
* It is only ever reached *after* the router has enforced the human-approval
  gate + engagement scope + SSRF/netguard. This module does not re-open those.
* It is fully lazy + exception-guarded: if ``pymetasploit3`` is missing or no
  ``msfrpcd`` answers, :func:`available` returns ``False`` and callers fall back
  to the safe reachability probe. Nothing here raises into the request path.
* It never invents exploit code — it drives vetted modules shipped with
  Metasploit, selected by CVE/service, exactly as ``msfconsole`` would.

Operators enable it per deployment (self-hosted, authorized engagement):
    RECONX_REAL_EXPLOIT=true
    RECONX_MSF_PASSWORD=...        # msfrpcd -P <pass>
    RECONX_MSF_HOST/PORT/SSL       # default 127.0.0.1:55553, ssl on
    RECONX_MSF_MODE=check|exploit  # default check
"""

from __future__ import annotations

import os
import re
import time
from typing import Any

from .config import settings

_SCHEME = re.compile(r"^[a-z]+://", re.I)


def _host_port(target: str) -> tuple[str, int | None]:
    t = _SCHEME.sub("", (target or "").strip()).split("/")[0]
    if ":" in t:
        host, _, port = t.partition(":")
        try:
            return host, int(port)
        except ValueError:
            return host, None
    # bare URL with no port: infer from scheme
    scheme = (target or "").split("://")[0].lower() if "://" in (target or "") else ""
    return t, {"http": 80, "https": 443}.get(scheme)


def _client() -> Any:
    """Build a Metasploit RPC client, or raise. Import is lazy on purpose."""
    from pymetasploit3.msfrpc import MsfRpcClient

    return MsfRpcClient(
        settings.MSF_PASSWORD,
        username=settings.MSF_USER,
        server=settings.MSF_HOST,
        port=int(settings.MSF_PORT),
        ssl=bool(settings.MSF_SSL),
    )


def available() -> bool:
    """True when real exploitation is enabled *and* an msfrpcd is reachable.

    Never raises: any import / connection failure is reported as unavailable so
    the exploit engine transparently falls back to the safe probe.
    """
    if not settings.real_exploit_enabled:
        return False
    try:
        c = _client()
        # a trivially cheap authenticated call proves the daemon answers
        _ = c.core.version
        return True
    except Exception:
        return False


def _mode() -> str:
    m = (os.getenv("RECONX_MSF_MODE") or "check").strip().lower()
    return "exploit" if m == "exploit" else "check"


def _search_module(client: Any, *, cve: str | None, name: str | None,
                   service: str | None) -> str | None:
    """Find the fullname of a Metasploit exploit module matching the finding.

    Prefers an exact CVE match, then a service/name keyword search. Returns the
    module fullname (e.g. ``exploit/unix/ftp/vsftpd_234_backdoor``) or ``None``.
    """
    queries = []
    if cve:
        queries.append(cve)
    for kw in (name, service):
        if kw:
            queries.append(str(kw))
    for q in queries:
        try:
            hits = client.modules.search(q) or []
        except Exception:
            continue
        # prefer exploit modules; fall back to auxiliary
        for want in ("exploit", "auxiliary"):
            for h in hits:
                if (h.get("type") == want) and h.get("fullname"):
                    return h["fullname"]
    return None


def run_exploit(target: str, *, cve: str | None = None, name: str | None = None,
                service: str | None = None) -> dict[str, Any]:
    """Run a real Metasploit module against ``target`` for the given finding.

    Returns a structured result dict (never raises):
      {engine:"metasploit", available:bool, mode:"check"|"exploit",
       module:str|None, exploitable:bool|None, session:bool, output:str,
       non_destructive:bool, target:str}

    ``exploitable`` is the module's check verdict where supported; ``session``
    is True only if exploit mode landed a Metasploit session. When no matching
    module is found or the daemon is unreachable, ``available``/``module`` reflect
    that and the caller falls back to the safe probe.
    """
    host, port = _host_port(target)
    mode = _mode()
    result: dict[str, Any] = {
        "engine": "metasploit",
        "available": False,
        "mode": mode,
        "module": None,
        "exploitable": None,
        "session": False,
        "output": "",
        "target": target,
        "non_destructive": mode == "check",
    }
    try:
        client = _client()
        _ = client.core.version
        result["available"] = True
    except Exception as exc:  # daemon unreachable → caller falls back to safe probe
        result["output"] = f"metasploit rpc unavailable: {exc}"
        return result

    module_name = _search_module(client, cve=cve, name=name, service=service)
    if not module_name:
        result["output"] = "no matching Metasploit module for this finding"
        return result
    result["module"] = module_name

    try:
        mtype, _, mpath = module_name.partition("/")
        mod = client.modules.use(mtype, mpath)
        mod["RHOSTS"] = host
        if port:
            try:
                mod["RPORT"] = port
            except Exception:
                pass

        # --- check mode: verify exploitability without firing a payload ----- #
        if mode == "check" or mtype == "auxiliary":
            try:
                chk = mod.check()  # returns a dict/string depending on module
                text = str(chk)
                result["output"] = text[:2000]
                result["exploitable"] = any(
                    k in text.lower()
                    for k in ("vulnerable", "appears", "exploitable")
                ) and "not" not in text.lower()[:40]
            except Exception as exc:
                result["output"] = f"check not supported / failed: {exc}"
            return result

        # --- exploit mode: run the module and look for a new session -------- #
        payload = None
        try:
            payloads = mod.targetpayloads() or []
            payload = payloads[0] if payloads else None
        except Exception:
            payload = None
        before = set(client.sessions.list.keys())
        mod.execute(payload=payload) if payload else mod.execute()
        deadline = time.time() + int(settings.MSF_EXPLOIT_TIMEOUT)
        new_sid = None
        while time.time() < deadline:
            now = set(client.sessions.list.keys())
            fresh = now - before
            if fresh:
                new_sid = next(iter(fresh))
                break
            time.sleep(2)
        if new_sid is not None:
            result["session"] = True
            result["exploitable"] = True
            result["output"] = f"session {new_sid} opened via {module_name}"
        else:
            result["output"] = f"{module_name} executed; no session opened"
    except Exception as exc:
        result["output"] = f"module run failed: {exc}"
    return result

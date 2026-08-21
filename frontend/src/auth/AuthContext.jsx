import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from "react";
import {
  authHeader,
  createWorkspace,
  fetchMe,
  fetchWorkspaces,
  loginUser,
  logoutSession,
  refreshTokens,
  registerUser,
  setAuthToken,
  setUnauthorizedHandler,
} from "../api/client";

// Tenancy + session state for RECON-X. The ACCESS token lives in localStorage so
// a reload keeps you signed in; the REFRESH token is NOT stored in JS — it lives
// only in the httpOnly `reconx_refresh` cookie the backend sets, out of reach of
// XSS. `activeWorkspace.id` is what the dashboard drives every scoped call
// (scans, findings, history, report) off of.

const LS = {
  access: "reconx.access",
  org: "reconx.orgId",
  ws: "reconx.wsId",
};

const AuthContext = createContext(null);

function readLS(key) {
  try {
    return localStorage.getItem(key);
  } catch {
    return null;
  }
}
function writeLS(key, val) {
  try {
    if (val == null) localStorage.removeItem(key);
    else localStorage.setItem(key, String(val));
  } catch {
    /* storage disabled — session stays in-memory only */
  }
}

export function AuthProvider({ children }) {
  const [booting, setBooting] = useState(true); // restoring a persisted session
  const [user, setUser] = useState(null);
  const [orgs, setOrgs] = useState([]);
  const [activeOrg, setActiveOrg] = useState(null);
  const [workspaces, setWorkspaces] = useState([]);
  const [activeWorkspace, setActiveWorkspace] = useState(null);

  const persistTokens = useCallback((access) => {
    setAuthToken(access); // updates REST Bearer header + WS subprotocol credential
    writeLS(LS.access, access || null);
    // The refresh token is never written to JS storage — it lives only in the
    // httpOnly `reconx_refresh` cookie (set by the backend on login/refresh).
  }, []);

  const clearSession = useCallback(() => {
    persistTokens(null);
    writeLS(LS.org, null);
    writeLS(LS.ws, null);
    setUser(null);
    setOrgs([]);
    setActiveOrg(null);
    setWorkspaces([]);
  }, [persistTokens]);

  // Load the workspaces of an org and choose an active one (preferring a
  // remembered / explicitly-requested id, else the default engagement).
  const loadWorkspaces = useCallback(async (org, preferWsId) => {
    if (!org) {
      setWorkspaces([]);
      setActiveWorkspace(null);
      return;
    }
    const list = await fetchWorkspaces(org.id);
    setWorkspaces(list);
    const wanted = preferWsId != null ? Number(preferWsId) : null;
    const chosen =
      list.find((w) => w.id === wanted) ||
      // default engagement is the oldest (lowest id)
      list.reduce((a, b) => (!a || b.id < a.id ? b : a), null);
    setActiveWorkspace(chosen || null);
    writeLS(LS.ws, chosen?.id ?? null);
  }, []);

  // Populate user + org/workspace context after tokens are in place.
  const hydrate = useCallback(
    async ({ preferOrgId, preferWsId, seedOrg, seedWorkspace } = {}) => {
      const me = await fetchMe();
      setUser(me.user);
      setOrgs(me.orgs);
      const wanted = preferOrgId != null ? Number(preferOrgId) : seedOrg?.id;
      const org =
        me.orgs.find((o) => o.id === wanted) || me.orgs[0] || seedOrg || null;
      setActiveOrg(org);
      writeLS(LS.org, org?.id ?? null);
      // If login handed us the exact workspace, seed it instantly, then refresh
      // the full list in the background.
      if (seedWorkspace && seedWorkspace.org_id === org?.id) {
        setActiveWorkspace(seedWorkspace);
        writeLS(LS.ws, seedWorkspace.id);
      }
      await loadWorkspaces(org, preferWsId ?? seedWorkspace?.id);
    },
    [loadWorkspaces]
  );

  // ---- Public actions ---------------------------------------------------- //
  const login = useCallback(
    async ({ email, password, mfa_code }) => {
      const data = await loginUser({ email, password, mfa_code });
      persistTokens(data.access_token); // refresh arrives as an httpOnly cookie
      await hydrate({ seedOrg: data.org, seedWorkspace: data.workspace });
      return data;
    },
    [hydrate, persistTokens]
  );

  const register = useCallback(
    async ({ email, password, full_name, org_name }) => {
      const data = await registerUser({ email, password, full_name, org_name });
      persistTokens(data.access_token); // refresh arrives as an httpOnly cookie
      await hydrate({ seedOrg: data.org, seedWorkspace: data.workspace });
      return data;
    },
    [hydrate, persistTokens]
  );

  const logout = useCallback(() => {
    logoutSession().catch(() => {}); // best-effort: clear the httpOnly cookie server-side
    clearSession();
  }, [clearSession]);

  const selectOrg = useCallback(
    async (orgId) => {
      const org = orgs.find((o) => o.id === Number(orgId));
      if (!org) return;
      setActiveOrg(org);
      writeLS(LS.org, org.id);
      await loadWorkspaces(org);
    },
    [orgs, loadWorkspaces]
  );

  const selectWorkspace = useCallback(
    (wsId) => {
      const ws = workspaces.find((w) => w.id === Number(wsId));
      if (!ws) return;
      setActiveWorkspace(ws);
      writeLS(LS.ws, ws.id);
    },
    [workspaces]
  );

  // Re-pull the active org's workspace list (e.g. after creating one / to
  // refresh summary counts) and keep the active selection.
  const refreshWorkspaces = useCallback(async () => {
    if (!activeOrg) return;
    const list = await fetchWorkspaces(activeOrg.id);
    setWorkspaces(list);
    setActiveWorkspace((cur) => list.find((w) => w.id === cur?.id) || cur);
  }, [activeOrg]);

  // Create a new engagement (workspace) in the active org, then re-pull the
  // list and make the new one active — all atomically, so callers never race a
  // stale `workspaces` closure. Returns the newly-active workspace.
  const createEngagement = useCallback(
    async ({ name, description = "", scope = [] }) => {
      if (!activeOrg) return null;
      const created = await createWorkspace(activeOrg.id, { name, description, scope });
      const list = await fetchWorkspaces(activeOrg.id);
      setWorkspaces(list);
      const chosen = list.find((w) => w.id === created.id) || created;
      setActiveWorkspace(chosen);
      writeLS(LS.ws, chosen.id);
      return chosen;
    },
    [activeOrg]
  );

  // ---- 401 -> silent refresh (registered once) --------------------------- //
  useEffect(() => {
    setUnauthorizedHandler(async () => {
      try {
        const tok = await refreshTokens(); // rotates via the httpOnly refresh cookie
        persistTokens(tok.access_token);
        return true;
      } catch {
        clearSession();
        return false;
      }
    });
    return () => setUnauthorizedHandler(null);
  }, [persistTokens, clearSession]);

  // ---- Restore a persisted session on first mount ------------------------ //
  useEffect(() => {
    let alive = true;
    (async () => {
      const access = readLS(LS.access);
      if (!access) {
        setBooting(false);
        return;
      }
      setAuthToken(access);
      try {
        await hydrate({ preferOrgId: readLS(LS.org), preferWsId: readLS(LS.ws) });
      } catch {
        // access likely expired — try one refresh (httpOnly cookie) before giving up.
        try {
          const tok = await refreshTokens();
          persistTokens(tok.access_token);
          await hydrate({ preferOrgId: readLS(LS.org), preferWsId: readLS(LS.ws) });
        } catch {
          if (alive) clearSession();
        }
      } finally {
        if (alive) setBooting(false);
      }
    })();
    return () => {
      alive = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const value = useMemo(
    () => ({
      booting,
      isAuthenticated: !!user,
      user,
      orgs,
      activeOrg,
      workspaces,
      activeWorkspace,
      login,
      register,
      logout,
      selectOrg,
      selectWorkspace,
      refreshWorkspaces,
      createEngagement,
      authHeader,
    }),
    [
      booting,
      user,
      orgs,
      activeOrg,
      workspaces,
      activeWorkspace,
      login,
      register,
      logout,
      selectOrg,
      selectWorkspace,
      refreshWorkspaces,
      createEngagement,
    ]
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within <AuthProvider>");
  return ctx;
}

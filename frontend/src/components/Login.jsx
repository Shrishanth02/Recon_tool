import { useState } from "react";
import Icon from "./Icon";
import { useAuth } from "../auth/AuthContext";
import { HTTP_BASE } from "../api/client";

// Combined sign-in / create-account card. Matches the dark RECON-X security
// console styling and talks only to AuthContext.
export default function Login() {
  const { login, register } = useAuth();
  const [mode, setMode] = useState("login"); // login | register
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [fullName, setFullName] = useState("");
  const [orgName, setOrgName] = useState("");
  const [mfaCode, setMfaCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);

  // Optional SSO affordance: type an org slug and get redirected to the
  // backend's IdP-initiated login. Kept secondary to password sign-in.
  const [showSso, setShowSso] = useState(false);
  const [ssoSlug, setSsoSlug] = useState("");

  const isRegister = mode === "register";

  const startSso = (e) => {
    e.preventDefault();
    const slug = ssoSlug.trim().toLowerCase();
    if (!slug) return;
    // Full-page navigation: the backend responds with an IdP redirect.
    window.location.assign(`${HTTP_BASE}/auth/sso/${encodeURIComponent(slug)}/login`);
  };

  const submit = async (e) => {
    e.preventDefault();
    if (busy) return;
    setBusy(true);
    setError(null);
    try {
      if (isRegister) {
        await register({
          email: email.trim(),
          password,
          full_name: fullName.trim(),
          org_name: orgName.trim() || undefined,
        });
      } else {
        await login({
          email: email.trim(),
          password,
          mfa_code: mfaCode.trim() || undefined,
        });
      }
    } catch (err) {
      setError(err?.message || "Something went wrong. Please try again.");
    } finally {
      setBusy(false);
    }
  };

  const toggle = () => {
    setMode(isRegister ? "login" : "register");
    setError(null);
  };

  return (
    <div className="auth-screen">
      <div className="auth-card">
        <div className="auth-brand">
          <div className="brand-mark">
            <Icon name="shield" size={22} />
          </div>
          <div className="brand-text">
            <span className="brand-name">RECON-X</span>
            <span className="brand-sub">security console</span>
          </div>
        </div>

        <h2 className="auth-title">
          {isRegister ? "Create your workspace" : "Sign in to continue"}
        </h2>
        <p className="auth-sub">
          {isRegister
            ? "Spin up an organization and its first engagement."
            : "Authenticate to reach your engagements and scans."}
        </p>

        <form className="auth-form" onSubmit={submit}>
          {isRegister && (
            <label className="auth-field">
              <span>Full name</span>
              <input
                type="text"
                autoComplete="name"
                value={fullName}
                onChange={(e) => setFullName(e.target.value)}
                placeholder="Ada Lovelace"
              />
            </label>
          )}

          <label className="auth-field">
            <span>Email</span>
            <input
              type="email"
              required
              autoComplete="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="you@company.com"
            />
          </label>

          <label className="auth-field">
            <span>Password</span>
            <input
              type="password"
              required
              minLength={isRegister ? 8 : undefined}
              autoComplete={isRegister ? "new-password" : "current-password"}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder={isRegister ? "At least 8 characters" : "••••••••"}
            />
          </label>

          {isRegister && (
            <label className="auth-field">
              <span>
                Organization <em className="auth-optional">optional</em>
              </span>
              <input
                type="text"
                value={orgName}
                onChange={(e) => setOrgName(e.target.value)}
                placeholder="Acme Security"
              />
            </label>
          )}

          {!isRegister && (
            <label className="auth-field">
              <span>
                MFA code <em className="auth-optional">if enabled</em>
              </span>
              <input
                type="text"
                inputMode="numeric"
                autoComplete="one-time-code"
                value={mfaCode}
                onChange={(e) => setMfaCode(e.target.value)}
                placeholder="123456"
              />
            </label>
          )}

          {error && (
            <div className="auth-error">
              <Icon name="x" size={14} /> {error}
            </div>
          )}

          <button className="btn btn-run auth-submit" type="submit" disabled={busy}>
            <Icon name={isRegister ? "shield" : "bolt"} size={16} />
            {busy
              ? isRegister
                ? "Creating…"
                : "Signing in…"
              : isRegister
              ? "Create account"
              : "Sign in"}
          </button>
        </form>

        {!isRegister && (
          <div className="auth-sso">
            {!showSso ? (
              <button
                type="button"
                className="auth-link auth-sso-toggle"
                onClick={() => setShowSso(true)}
              >
                <Icon name="id" size={13} /> Sign in with SSO
              </button>
            ) : (
              <form className="auth-sso-form" onSubmit={startSso}>
                <label className="auth-field">
                  <span>Organization slug</span>
                  <input
                    type="text"
                    value={ssoSlug}
                    onChange={(e) => setSsoSlug(e.target.value)}
                    placeholder="acme-security"
                    autoFocus
                  />
                </label>
                <button
                  type="submit"
                  className="btn-ghost auth-sso-go"
                  disabled={!ssoSlug.trim()}
                >
                  <Icon name="swap" size={13} /> Continue to SSO
                </button>
              </form>
            )}
          </div>
        )}

        <div className="auth-switch">
          {isRegister ? "Already have an account?" : "Need an account?"}
          <button type="button" className="auth-link" onClick={toggle}>
            {isRegister ? "Sign in" : "Create one"}
          </button>
        </div>
      </div>
    </div>
  );
}

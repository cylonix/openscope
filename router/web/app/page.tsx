"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { consoleApi, ApiError, Role } from "@/lib/api";
import { ThemeToggle } from "@/components/theme-toggle";

export default function Home() {
  const router = useRouter();
  const [token, setToken] = useState("");
  const [showToken, setShowToken] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [expired, setExpired] = useState(false);
  // True while we auto-sign-in from a ?code= link — shows a clean "signing
  // you in…" state instead of a flash of the manual form.
  const [autoLoggingIn, setAutoLoggingIn] = useState(false);

  // doLogin exchanges a demo code (or osk_ token) for a session and routes to
  // the role's dashboard. Shared by the manual form and the auto-login link.
  async function doLogin(value: string) {
    setError(null);
    setLoading(true);
    try {
      const { role, resolved_token } = await consoleApi.login(value);
      // If the input was an 8-char demo code, the server returns the full
      // osk_… token so /v1/scan and /v1/chat keep working — those calls
      // bypass the console's HttpOnly cookie and authenticate to the
      // router directly via Authorization: Bearer.
      sessionStorage.setItem("openscope_token", resolved_token ?? value);
      sessionStorage.setItem("openscope_role", role);
      router.push(roleDashboard(role));
    } catch (err) {
      setError(err instanceof ApiError ? `${err.code}: ${err.message}` : String(err));
      setAutoLoggingIn(false); // fall back to the manual form on failure
    } finally {
      setLoading(false);
    }
  }

  // On load, read the URL once: a ?code= (or ?token=/?key=) param means this is
  // a forwardable one-click demo link — prefill it and sign in automatically.
  // ?expired=1 means the dashboard bounced us here on session timeout.
  useEffect(() => {
    if (typeof window === "undefined") return;
    const p = new URLSearchParams(window.location.search);
    const code = (p.get("code") || p.get("token") || p.get("key") || "").trim();
    if (code) {
      setToken(code);
      setAutoLoggingIn(true);
      void doLogin(code);
    } else if (p.get("expired") === "1") {
      setExpired(true);
    }
    // doLogin is stable for this one-shot mount; intentionally not a dep.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!token) return;
    await doLogin(token);
  }

  return (
    <main className="min-h-screen flex items-center justify-center bg-slate-50 p-4 relative">
      <div className="absolute top-4 right-4">
        <ThemeToggle />
      </div>
      <div className="w-full max-w-md bg-white border border-slate-200 rounded-lg shadow-sm p-8">
        <div className="mb-6">
          <h1 className="text-2xl font-semibold text-slate-900">OpenScope</h1>
          <p className="text-xs uppercase tracking-wider text-slate-500 mt-1">
            AI Agent Trust Perimeter — Demo
          </p>
        </div>
        {autoLoggingIn && !error ? (
          <div className="py-8 text-center">
            <div
              className="inline-block w-5 h-5 rounded-full animate-spin mb-3"
              style={{ border: "2px solid var(--line-strong)", borderTopColor: "var(--teal)" }}
            />
            <div className="text-sm text-slate-700">Signing you in to the OpenScope demo…</div>
            <div className="mt-1 text-xs text-slate-500">Opening your dashboard.</div>
          </div>
        ) : (
          <>
        {expired && (
          <div className="text-sm text-amber-800 bg-amber-50 border border-amber-200 rounded p-2 mb-4">
            Your demo session timed out. Sign in again to pick up where you left off.
          </div>
        )}
        <p className="text-sm text-slate-600 mb-6">
          Paste your 8-character demo code (or your full <code className="font-mono text-xs">osk_…</code> key) to sign in.
        </p>
        <form onSubmit={submit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-slate-700 mb-1">
              Demo code or key
            </label>
            <div className="relative">
              <input
                type={showToken ? "text" : "password"}
                value={token}
                onChange={(e) => setToken(e.target.value.trim())}
                placeholder="A1B2C3D4 or osk_developer_…"
                autoComplete="off"
                autoCorrect="off"
                autoCapitalize="off"
                spellCheck={false}
                autoFocus
                className="w-full px-3 py-2 pr-10 border border-slate-300 rounded-md font-mono text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                required
              />
              <button
                type="button"
                onClick={() => setShowToken((s) => !s)}
                aria-label={showToken ? "Hide demo key" : "Show demo key"}
                title={showToken ? "Hide" : "Show"}
                className="absolute right-2 top-1/2 -translate-y-1/2 p-1 text-slate-500 hover:text-slate-800 focus:outline-none focus:ring-2 focus:ring-blue-500 rounded"
              >
                {showToken ? <EyeOff /> : <Eye />}
              </button>
            </div>
            <p className="text-xs text-slate-500 mt-1">
              Codes are issued by OpenScope and emailed individually.
            </p>
          </div>
          {error && (
            <div className="text-sm text-red-700 bg-red-50 border border-red-200 rounded p-2 break-words">
              {error}
            </div>
          )}
          <button
            type="submit"
            disabled={loading || !token}
            className="w-full bg-blue-600 hover:bg-blue-700 disabled:bg-slate-300 text-white py-2 px-4 rounded-md text-sm font-medium transition"
          >
            {loading ? "Signing in…" : "Sign in"}
          </button>
        </form>
        <div className="mt-6 pt-6 border-t border-slate-100 text-xs text-slate-500">
          Don&apos;t have a key? Email{" "}
          <a
            href="mailto:contact@openscopeai.com?subject=OpenScope%20demo%20key%20request"
            className="text-blue-600 hover:underline"
          >
            contact@openscopeai.com
          </a>{" "}
          or contact your OpenScope rep.
        </div>
          </>
        )}
      </div>
    </main>
  );
}

function Eye() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
      <circle cx="12" cy="12" r="3" />
    </svg>
  );
}

function EyeOff() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24" />
      <line x1="1" y1="1" x2="23" y2="23" />
    </svg>
  );
}

function roleDashboard(role: Role): string {
  switch (role) {
    case "developer": return "/dashboard/developer";
    case "it":        return "/dashboard/it";
    case "engineer":  return "/dashboard/ops";
    case "admin":     return "/admin";
    default:          return "/";
  }
}

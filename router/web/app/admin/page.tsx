"use client";

import { useState, useEffect } from "react";
import { ThemeToggle } from "@/components/theme-toggle";

// Admin page (founder-only). Asks for the admin bearer token, lists tenants,
// and mints new demo keys.
//
// Auth model is different from the role dashboards: no session cookie. The
// founder pastes the admin token once per browser tab; it's kept in
// sessionStorage and attached as Authorization: Bearer on every call.

type Tenant = {
  id: string;
  slug: string;
  name: string;
  active_keys: number;
};

type MintedKey = {
  tenant_id: string;
  tenant_slug: string;
  role: string;
  key_id: string;
  token: string;
  key_prefix: string;
  recipient_email?: string;
};

type AdminKey = {
  id: string;
  tenant_id: string;
  tenant_slug: string;
  role: string;
  key_prefix: string;
  recipient_email?: string;
  created_at: string;
  last_used_at?: string;
  revoked_at?: string;
};

type MintedCode = {
  code: string;
  tenant_id: string;
  tenant_slug: string;
  role: string;
  key_id: string;
  token: string;
  key_prefix: string;
  label?: string;
  recipient_email?: string;
};

type DemoCode = {
  code: string;
  tenant_id: string;
  tenant_slug: string;
  role: string;
  api_key_id: string;
  label?: string;
  created_at: string;
  last_used_at?: string;
  revoked_at?: string;
};

type UsageDay = {
  tenant_slug: string;
  day: string;
  requests: number;
  input_tokens: number;
  output_tokens: number;
  total_cost_usd: number;
};

type UsageTotals = {
  tenants_active_7d: number;
  requests: number;
  input_tokens: number;
  output_tokens: number;
  total_cost_usd: number;
};

export default function AdminPage() {
  const [token, setToken] = useState<string>("");
  const [authed, setAuthed] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const t = sessionStorage.getItem("openscope_admin_token");
    if (t) {
      setToken(t);
      setAuthed(true);
    }
  }, []);

  async function tryAuth(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      const res = await fetch("/api/console/api/v1/admin/tenants", {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.message ?? `HTTP ${res.status}`);
      }
      sessionStorage.setItem("openscope_admin_token", token);
      setAuthed(true);
    } catch (e) {
      setError(String(e));
    }
  }

  function logout() {
    sessionStorage.removeItem("openscope_admin_token");
    setToken("");
    setAuthed(false);
  }

  if (!authed) {
    return (
      <main className="min-h-screen flex items-center justify-center bg-slate-50 p-4">
        <div className="w-full max-w-md bg-white border border-slate-200 rounded-lg shadow-sm p-8">
          <h1 className="text-2xl font-semibold text-slate-900 mb-2">OpenScope Admin</h1>
          <p className="text-sm text-slate-600 mb-6">
            Founder-only. Paste the admin bearer token.
          </p>
          <form onSubmit={tryAuth} className="space-y-4">
            <input
              type="password"
              value={token}
              onChange={(e) => setToken(e.target.value)}
              placeholder="OPENSCOPE_ADMIN_TOKEN"
              autoComplete="off"
              className="w-full px-3 py-2 border border-slate-300 rounded-md font-mono text-sm"
              required
            />
            {error && (
              <div className="text-sm text-red-700 bg-red-50 border border-red-200 rounded p-2">{error}</div>
            )}
            <button
              type="submit"
              className="w-full bg-slate-900 hover:bg-slate-800 text-white py-2 rounded text-sm"
            >
              Sign in
            </button>
          </form>
        </div>
      </main>
    );
  }

  return <AdminConsole token={token} onLogout={logout} />;
}

function AdminConsole({ token, onLogout }: { token: string; onLogout: () => void }) {
  const [tenants, setTenants] = useState<Tenant[]>([]);
  const [keys, setKeys] = useState<AdminKey[]>([]);
  const [codes, setCodes] = useState<DemoCode[]>([]);
  const [usage, setUsage] = useState<{ daily: UsageDay[]; totals: UsageTotals } | null>(null);
  const [refreshKey, setRefreshKey] = useState(0);
  const [lastMint, setLastMint] = useState<MintedKey | null>(null);
  const [lastCode, setLastCode] = useState<MintedCode | null>(null);

  useEffect(() => {
    const headers = { Authorization: `Bearer ${token}` };
    fetch("/api/console/api/v1/admin/tenants", { headers })
      .then((r) => r.json()).then((d) => setTenants(d.tenants ?? [])).catch(() => setTenants([]));
    fetch("/api/console/api/v1/admin/keys", { headers })
      .then((r) => r.json()).then((d) => setKeys(d.keys ?? [])).catch(() => setKeys([]));
    fetch("/api/console/api/v1/admin/demo_codes", { headers })
      .then((r) => r.json()).then((d) => setCodes(d.codes ?? [])).catch(() => setCodes([]));
    fetch("/api/console/api/v1/admin/usage", { headers })
      .then((r) => r.json()).then(setUsage).catch(() => setUsage(null));
  }, [token, refreshKey]);

  async function revokeKey(id: string) {
    if (!confirm("Revoke this key? The owner will be locked out immediately.")) return;
    const res = await fetch("/api/console/api/v1/admin/keys/revoke", {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({ id }),
    });
    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      alert(`Revoke failed: ${body.message ?? res.statusText}`);
      return;
    }
    setRefreshKey((n) => n + 1);
  }

  async function revokeCode(code: string) {
    if (!confirm(`Revoke demo code ${code}? Anyone holding it will be locked out.`)) return;
    const res = await fetch("/api/console/api/v1/admin/demo_codes/revoke", {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({ code }),
    });
    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      alert(`Revoke failed: ${body.message ?? res.statusText}`);
      return;
    }
    setRefreshKey((n) => n + 1);
  }

  return (
    <div className="min-h-screen bg-slate-50">
      <header className="bg-white border-b border-slate-200">
        <div className="max-w-5xl mx-auto px-6 py-3 flex items-center justify-between">
          <div className="font-semibold text-slate-900">OpenScope Admin</div>
          <div className="flex items-center gap-4">
            <ThemeToggle />
            <button onClick={onLogout} className="text-sm text-slate-600 hover:text-slate-900">Sign out</button>
          </div>
        </div>
      </header>
      <main className="max-w-5xl mx-auto px-6 py-8 space-y-6">
        {usage && <UsageOverview u={usage} />}

        <MintCodeForm token={token} onSuccess={(c) => { setLastCode(c); setRefreshKey((n) => n + 1); }} />

        {lastCode && <MintedCodeDisplay c={lastCode} onClose={() => setLastCode(null)} />}

        <CodesSection codes={codes} onRevoke={revokeCode} />

        <details className="bg-white border border-slate-200 rounded-lg p-5">
          <summary className="text-sm font-medium text-slate-700 cursor-pointer">
            Advanced: mint a full <code className="font-mono text-xs">osk_…</code> key (no demo code)
          </summary>
          <div className="mt-4">
            <MintForm token={token} onSuccess={(k) => { setLastMint(k); setRefreshKey((n) => n + 1); }} />
            {lastMint && <div className="mt-4"><MintedKeyDisplay k={lastMint} onClose={() => setLastMint(null)} /></div>}
          </div>
        </details>

        <section className="bg-white border border-slate-200 rounded-lg p-5">
          <h2 className="text-lg font-semibold text-slate-900 mb-3">Tenants</h2>
          <table className="w-full text-sm">
            <thead className="text-xs uppercase tracking-wide text-slate-500 border-b border-slate-200">
              <tr><th className="text-left py-2">Slug</th><th className="text-left">Name</th><th className="text-right">Active keys</th><th className="text-left pl-4 font-mono">ID</th></tr>
            </thead>
            <tbody>
              {tenants.length === 0 && <tr><td colSpan={4} className="text-center py-4 text-slate-500">No tenants yet — mint a key above.</td></tr>}
              {tenants.map((t) => (
                <tr key={t.id} className="border-b border-slate-100">
                  <td className="py-2"><code className="text-xs">{t.slug}</code></td>
                  <td>{t.name}</td>
                  <td className="text-right">{t.active_keys}</td>
                  <td className="pl-4 text-xs text-slate-500 font-mono">{t.id}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>

        <KeysSection keys={keys} onRevoke={revokeKey} />
      </main>
    </div>
  );
}

function UsageOverview({ u }: { u: { daily: UsageDay[]; totals: UsageTotals } }) {
  return (
    <section className="bg-white border border-slate-200 rounded-lg p-5">
      <h2 className="text-lg font-semibold text-slate-900 mb-3">Cross-tenant usage (last 7 days)</h2>
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-4 mb-4">
        <Stat label="Tenants active" value={u.totals.tenants_active_7d} />
        <Stat label="Requests" value={u.totals.requests} />
        <Stat label="Input tokens" value={u.totals.input_tokens.toLocaleString()} />
        <Stat label="Output tokens" value={u.totals.output_tokens.toLocaleString()} />
        <Stat label="Total spend" value={`$${u.totals.total_cost_usd.toFixed(6)}`} />
      </div>
      {u.daily.length === 0 ? (
        <div className="text-sm text-slate-500 text-center py-4">No activity yet across any tenant in the last 7 days.</div>
      ) : (
        <table className="w-full text-sm">
          <thead className="text-xs uppercase tracking-wide text-slate-500 border-b border-slate-200">
            <tr>
              <th className="text-left py-2">Day</th>
              <th className="text-left">Tenant</th>
              <th className="text-right">Requests</th>
              <th className="text-right">Input</th>
              <th className="text-right">Output</th>
              <th className="text-right">Spend</th>
            </tr>
          </thead>
          <tbody>
            {u.daily.map((d) => (
              <tr key={`${d.day}-${d.tenant_slug}`} className="border-b border-slate-100">
                <td className="py-1.5 font-mono text-xs">{d.day}</td>
                <td><code className="text-xs">{d.tenant_slug}</code></td>
                <td className="text-right">{d.requests}</td>
                <td className="text-right">{d.input_tokens.toLocaleString()}</td>
                <td className="text-right">{d.output_tokens.toLocaleString()}</td>
                <td className="text-right">${d.total_cost_usd.toFixed(6)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}

function Stat({ label, value }: { label: string; value: string | number }) {
  return (
    <div>
      <div className="text-xs uppercase tracking-wide text-slate-500">{label}</div>
      <div className="text-lg font-semibold text-slate-900 tabular-nums">{value}</div>
    </div>
  );
}

function KeysSection({ keys, onRevoke }: { keys: AdminKey[]; onRevoke: (id: string) => void }) {
  const [showRevoked, setShowRevoked] = useState(false);
  const filtered = showRevoked ? keys : keys.filter((k) => !k.revoked_at);
  return (
    <section className="bg-white border border-slate-200 rounded-lg p-5">
      <div className="flex items-center justify-between mb-3">
        <h2 className="text-lg font-semibold text-slate-900">Keys</h2>
        <label className="text-xs text-slate-600 flex items-center gap-2 cursor-pointer">
          <input type="checkbox" checked={showRevoked} onChange={(e) => setShowRevoked(e.target.checked)} />
          Show revoked
        </label>
      </div>
      {filtered.length === 0 ? (
        <div className="text-sm text-slate-500 text-center py-4">
          {showRevoked ? "No keys at all." : "No active keys — mint one above."}
        </div>
      ) : (
        <table className="w-full text-sm">
          <thead className="text-xs uppercase tracking-wide text-slate-500 border-b border-slate-200">
            <tr>
              <th className="text-left py-2">Tenant</th>
              <th className="text-left">Role</th>
              <th className="text-left">Prefix</th>
              <th className="text-left">Recipient</th>
              <th className="text-left">Last used</th>
              <th className="text-left">Created</th>
              <th className="text-right pr-2">Status</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((k) => (
              <tr key={k.id} className="border-b border-slate-100">
                <td className="py-1.5"><code className="text-xs">{k.tenant_slug}</code></td>
                <td><code className="text-xs">{k.role}</code></td>
                <td className="font-mono text-xs text-slate-500">{k.key_prefix}…</td>
                <td className="text-xs">{k.recipient_email ?? <span className="text-slate-400">—</span>}</td>
                <td className="text-xs font-mono text-slate-500">{k.last_used_at ? shortDate(k.last_used_at) : <span className="text-slate-400">never</span>}</td>
                <td className="text-xs font-mono text-slate-500">{shortDate(k.created_at)}</td>
                <td className="text-right pr-2">
                  {k.revoked_at ? (
                    <span className="text-xs text-slate-500 bg-slate-100 px-2 py-0.5 rounded">revoked</span>
                  ) : (
                    <button
                      onClick={() => onRevoke(k.id)}
                      className="text-xs text-red-700 hover:text-red-900 hover:underline"
                    >
                      Revoke
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}

function shortDate(ts: string): string {
  // Server returns "2026-05-22 08:12:48.318583+00" or similar; show YYYY-MM-DD HH:MM.
  return ts.slice(0, 16).replace("T", " ");
}

function MintForm({ token, onSuccess }: { token: string; onSuccess: (k: MintedKey) => void }) {
  const [slug, setSlug] = useState("");
  const [name, setName] = useState("");
  const [role, setRole] = useState("developer");
  const [email, setEmail] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const res = await fetch("/api/console/api/v1/admin/keys", {
        method: "POST",
        headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
        body: JSON.stringify({
          tenant_slug: slug,
          tenant_name: name || slug,
          role,
          recipient_email: email,
        }),
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.message ?? `HTTP ${res.status}`);
      }
      const k = (await res.json()) as MintedKey;
      onSuccess(k);
      setSlug(""); setName(""); setEmail("");
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }

  return (
    <section className="bg-white border border-slate-200 rounded-lg p-5">
      <h2 className="text-lg font-semibold text-slate-900 mb-3">Mint a demo key</h2>
      <form onSubmit={submit} className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        <Field label="Tenant slug" required>
          <input
            value={slug}
            onChange={(e) => setSlug(e.target.value.toLowerCase().replace(/[^a-z0-9-]/g, ""))}
            placeholder="cylonix"
            className="w-full px-3 py-1.5 border border-slate-300 rounded text-sm font-mono"
            required
          />
        </Field>
        <Field label="Tenant name (optional)">
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="Cylonix Inc"
            className="w-full px-3 py-1.5 border border-slate-300 rounded text-sm"
          />
        </Field>
        <Field label="Role" required>
          <select
            value={role}
            onChange={(e) => setRole(e.target.value)}
            className="w-full px-3 py-1.5 border border-slate-300 rounded text-sm"
          >
            <option value="developer">developer</option>
            <option value="it">it</option>
            <option value="engineer">engineer</option>
            <option value="admin">admin</option>
          </select>
        </Field>
        <Field label="Recipient email">
          <input
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="cto@cylonix.io"
            className="w-full px-3 py-1.5 border border-slate-300 rounded text-sm"
          />
        </Field>
        <div className="sm:col-span-2 flex items-center gap-3">
          <button
            type="submit"
            disabled={loading || !slug}
            className="bg-blue-600 hover:bg-blue-700 disabled:bg-slate-300 text-white text-sm px-4 py-2 rounded"
          >
            {loading ? "Minting…" : "Mint key"}
          </button>
          {error && <span className="text-sm text-red-700">{error}</span>}
        </div>
      </form>
    </section>
  );
}

function MintedKeyDisplay({ k, onClose }: { k: MintedKey; onClose: () => void }) {
  const [copied, setCopied] = useState(false);
  return (
    <section className="bg-green-50 border border-green-300 rounded-lg p-5">
      <div className="flex items-start justify-between mb-2">
        <div>
          <h2 className="text-lg font-semibold text-green-900">Key minted</h2>
          <p className="text-sm text-green-800">
            For <code className="bg-white px-1 rounded">{k.tenant_slug}</code> · role <code className="bg-white px-1 rounded">{k.role}</code>
            {k.recipient_email && <> · recipient <code className="bg-white px-1 rounded">{k.recipient_email}</code></>}
          </p>
        </div>
        <button onClick={onClose} className="text-sm text-green-800 hover:text-green-900">Dismiss</button>
      </div>
      <div className="bg-white border border-green-300 rounded p-3 mt-2">
        <div className="text-xs text-green-800 mb-1">Shown ONCE — copy now and email to the recipient.</div>
        <div className="flex items-center gap-2">
          <code className="flex-1 text-sm font-mono break-all">{k.token}</code>
          <button
            onClick={() => { navigator.clipboard.writeText(k.token); setCopied(true); setTimeout(() => setCopied(false), 2000); }}
            className="text-xs bg-slate-900 text-white px-2 py-1 rounded hover:bg-slate-800"
          >
            {copied ? "Copied!" : "Copy"}
          </button>
        </div>
        <div className="text-xs text-green-800 mt-2 font-mono">
          prefix: {k.key_prefix} · key_id: {k.key_id} · tenant_id: {k.tenant_id}
        </div>
      </div>
    </section>
  );
}

function Field({ label, required, children }: { label: string; required?: boolean; children: React.ReactNode }) {
  return (
    <label className="block">
      <div className="text-xs uppercase tracking-wide text-slate-500 mb-1">
        {label}{required && <span className="text-red-500"> *</span>}
      </div>
      {children}
    </label>
  );
}

function MintCodeForm({ token, onSuccess }: { token: string; onSuccess: (c: MintedCode) => void }) {
  const [slug, setSlug] = useState("demo-user001");
  const [role, setRole] = useState("developer");
  const [label, setLabel] = useState("");
  const [email, setEmail] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const res = await fetch("/api/console/api/v1/admin/demo_codes", {
        method: "POST",
        headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
        body: JSON.stringify({
          tenant_slug: slug,
          role,
          recipient_email: email,
          label,
        }),
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.message ?? `HTTP ${res.status}`);
      }
      const c = (await res.json()) as MintedCode;
      onSuccess(c);
      setLabel(""); setEmail("");
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }

  return (
    <section className="bg-white border border-slate-200 rounded-lg p-5">
      <h2 className="text-lg font-semibold text-slate-900 mb-1">Mint a demo code</h2>
      <p className="text-xs text-slate-500 mb-3">
        Issues an 8-character code that the prospect types at the login screen.
        Any prior active code for the same (tenant, role) is auto-revoked.
      </p>
      <form onSubmit={submit} className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        <Field label="Tenant slug" required>
          <input
            value={slug}
            onChange={(e) => setSlug(e.target.value.toLowerCase().replace(/[^a-z0-9-]/g, ""))}
            placeholder="demo-user001"
            className="w-full px-3 py-1.5 border border-slate-300 rounded text-sm font-mono"
            required
          />
        </Field>
        <Field label="Role" required>
          <select
            value={role}
            onChange={(e) => setRole(e.target.value)}
            className="w-full px-3 py-1.5 border border-slate-300 rounded text-sm"
          >
            <option value="developer">developer</option>
            <option value="it">it</option>
            <option value="engineer">engineer</option>
            <option value="admin">admin</option>
          </select>
        </Field>
        <Field label="Label (optional)">
          <input
            value={label}
            onChange={(e) => setLabel(e.target.value)}
            placeholder='e.g. "Acme demo 2026-05-25"'
            className="w-full px-3 py-1.5 border border-slate-300 rounded text-sm"
          />
        </Field>
        <Field label="Recipient email (optional)">
          <input
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="prospect@acme.com"
            className="w-full px-3 py-1.5 border border-slate-300 rounded text-sm"
          />
        </Field>
        <div className="sm:col-span-2 flex items-center gap-3">
          <button
            type="submit"
            disabled={loading || !slug}
            className="bg-blue-600 hover:bg-blue-700 disabled:bg-slate-300 text-white text-sm px-4 py-2 rounded"
          >
            {loading ? "Minting…" : "Mint code"}
          </button>
          {error && <span className="text-sm text-red-700">{error}</span>}
        </div>
      </form>
    </section>
  );
}

function MintedCodeDisplay({ c, onClose }: { c: MintedCode; onClose: () => void }) {
  const [copied, setCopied] = useState(false);
  return (
    <section className="bg-green-50 border border-green-300 rounded-lg p-5">
      <div className="flex items-start justify-between mb-3">
        <div>
          <h2 className="text-lg font-semibold text-green-900">Demo code minted</h2>
          <p className="text-sm text-green-800">
            For <code className="bg-white px-1 rounded">{c.tenant_slug}</code> · role <code className="bg-white px-1 rounded">{c.role}</code>
            {c.label && <> · <span className="italic">{c.label}</span></>}
            {c.recipient_email && <> · recipient <code className="bg-white px-1 rounded">{c.recipient_email}</code></>}
          </p>
        </div>
        <button onClick={onClose} className="text-sm text-green-800 hover:text-green-900">Dismiss</button>
      </div>
      <div className="bg-white border-2 border-green-500 rounded p-4 flex items-center justify-between">
        <code className="text-3xl font-mono font-bold tracking-widest text-green-900">{c.code}</code>
        <button
          onClick={() => { navigator.clipboard.writeText(c.code); setCopied(true); setTimeout(() => setCopied(false), 2000); }}
          className="text-sm bg-slate-900 text-white px-3 py-2 rounded hover:bg-slate-800"
        >
          {copied ? "Copied!" : "Copy code"}
        </button>
      </div>
      <details className="mt-3">
        <summary className="text-xs text-green-800 cursor-pointer hover:text-green-900">Show underlying <code className="font-mono">osk_…</code> token (operator records)</summary>
        <div className="mt-2 bg-white border border-green-200 rounded p-2 text-xs font-mono break-all text-slate-700">{c.token}</div>
        <div className="text-xs text-green-700 mt-1 font-mono">
          prefix: {c.key_prefix} · key_id: {c.key_id} · tenant_id: {c.tenant_id}
        </div>
      </details>
    </section>
  );
}

function CodesSection({ codes, onRevoke }: { codes: DemoCode[]; onRevoke: (code: string) => void }) {
  const [showRevoked, setShowRevoked] = useState(false);
  const filtered = showRevoked ? codes : codes.filter((c) => !c.revoked_at);
  return (
    <section className="bg-white border border-slate-200 rounded-lg p-5">
      <div className="flex items-center justify-between mb-3">
        <h2 className="text-lg font-semibold text-slate-900">Demo codes</h2>
        <label className="text-xs text-slate-600 flex items-center gap-2 cursor-pointer">
          <input type="checkbox" checked={showRevoked} onChange={(e) => setShowRevoked(e.target.checked)} />
          Show revoked
        </label>
      </div>
      {filtered.length === 0 ? (
        <div className="text-sm text-slate-500 text-center py-4">
          {showRevoked ? "No codes at all." : "No active demo codes — mint one above."}
        </div>
      ) : (
        <table className="w-full text-sm">
          <thead className="text-xs uppercase tracking-wide text-slate-500 border-b border-slate-200">
            <tr>
              <th className="text-left py-2">Code</th>
              <th className="text-left">Tenant</th>
              <th className="text-left">Role</th>
              <th className="text-left">Label</th>
              <th className="text-left">Last used</th>
              <th className="text-left">Created</th>
              <th className="text-right pr-2">Status</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((c) => (
              <tr key={c.code} className="border-b border-slate-100">
                <td className="py-1.5"><code className="text-sm font-bold tracking-wider">{c.code}</code></td>
                <td><code className="text-xs">{c.tenant_slug}</code></td>
                <td><code className="text-xs">{c.role}</code></td>
                <td className="text-xs text-slate-700">{c.label ?? <span className="text-slate-400">—</span>}</td>
                <td className="text-xs font-mono text-slate-500">{c.last_used_at ? shortDate(c.last_used_at) : <span className="text-slate-400">never</span>}</td>
                <td className="text-xs font-mono text-slate-500">{shortDate(c.created_at)}</td>
                <td className="text-right pr-2">
                  {c.revoked_at ? (
                    <span className="text-xs text-slate-500 bg-slate-100 px-2 py-0.5 rounded">revoked</span>
                  ) : (
                    <button
                      onClick={() => onRevoke(c.code)}
                      className="text-xs text-red-700 hover:text-red-900 hover:underline"
                    >
                      Revoke
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}

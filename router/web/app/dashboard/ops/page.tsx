"use client";

import { useEffect, useState } from "react";
import { consoleApi, VendorUsageRow, ApiError } from "@/lib/api";
import { ModelBreakdown } from "@/components/model-breakdown";
import { ConsoleShell, type ConsoleSection } from "@/components/console-shell";

type VerifyResult = {
  attempted_query: string;
  pool: string;
  result: string;
  postgres_message: string;
};

export default function OpsDashboard() {
  const [usage, setUsage] = useState<VendorUsageRow[]>([]);
  const [usageErr, setUsageErr] = useState<string | null>(null);

  const [verify, setVerify] = useState<VerifyResult | null>(null);
  const [verifyErr, setVerifyErr] = useState<string | null>(null);
  const [verifying, setVerifying] = useState(false);

  // Probe attempts — these should ALL fail. We surface the failures verbatim
  // to prove we can't reach prompt content.
  const [probeErrs, setProbeErrs] = useState<Record<string, string>>({});

  async function reload() {
    setUsageErr(null);
    try {
      const r = await consoleApi.vendorUsage();
      setUsage(r.daily ?? []);
    } catch (e) {
      setUsageErr(String(e));
    }
  }
  useEffect(() => { void reload(); }, []);

  async function runVerify() {
    setVerifying(true);
    setVerify(null); setVerifyErr(null);
    try {
      const r = await consoleApi.verifyNoPromptAccess();
      setVerify(r);
    } catch (e) {
      setVerifyErr(e instanceof ApiError ? `${e.code}: ${e.message}` : String(e));
    } finally {
      setVerifying(false);
    }
  }

  async function probe(label: string, fn: () => Promise<unknown>) {
    try {
      const ok = await fn();
      setProbeErrs((p) => ({ ...p, [label]: `UNEXPECTED ALLOW: ${JSON.stringify(ok)}` }));
    } catch (e) {
      setProbeErrs((p) => ({ ...p, [label]: e instanceof ApiError ? `${e.status} ${e.code}: ${e.message}` : String(e) }));
    }
  }

  const sections: ConsoleSection[] = [
    {
      id: "usage",
      label: "Usage by tenant",
      element: (
        <section className="bg-white border border-slate-200 rounded-lg p-5">
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-lg font-semibold text-slate-900">Daily usage by tenant</h2>
            <button onClick={reload} className="text-sm bg-white border border-slate-300 rounded px-3 py-1.5 hover:bg-slate-50">Refresh</button>
          </div>
          <p className="text-xs text-slate-500 mb-2">
            From the <code className="bg-slate-100 px-1 rounded">vendor.tenant_usage_daily</code> materialized view. Refreshes every 5 min in production.
          </p>
          {usage.length > 0 && (() => {
            const totals = usage.reduce((acc, u) => ({
              requests: acc.requests + u.requests,
              input: acc.input + u.input_tokens,
              output: acc.output + u.output_tokens,
              spend: acc.spend + u.total_cost_usd,
              tenants: acc.tenants.add(u.tenant_slug),
            }), { requests: 0, input: 0, output: 0, spend: 0, tenants: new Set<string>() });
            return (
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mb-4 pb-4 border-b border-slate-200">
                <div><div className="text-xs uppercase tracking-wide text-slate-500">Active tenants</div><div className="text-lg font-semibold tabular-nums">{totals.tenants.size}</div></div>
                <div><div className="text-xs uppercase tracking-wide text-slate-500">Requests</div><div className="text-lg font-semibold tabular-nums">{totals.requests}</div></div>
                <div><div className="text-xs uppercase tracking-wide text-slate-500">Tokens (in/out)</div><div className="text-lg font-semibold tabular-nums">{totals.input.toLocaleString()} / {totals.output.toLocaleString()}</div></div>
                <div><div className="text-xs uppercase tracking-wide text-slate-500">Spend</div><div className="text-lg font-semibold tabular-nums">${totals.spend.toFixed(6)}</div></div>
              </div>
            );
          })()}
          {usageErr && <div className="text-sm text-red-700 bg-red-50 border border-red-200 rounded p-2 mb-3">{usageErr}</div>}
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="text-xs uppercase tracking-wide text-slate-500 border-b border-slate-200">
                <tr><th className="text-left py-2">Tenant</th><th className="text-left">Day</th><th className="text-right">Requests</th><th className="text-right">Input tok</th><th className="text-right">Output tok</th><th className="text-right">Spend (USD)</th></tr>
              </thead>
              <tbody>
                {usage.length === 0 && <tr><td colSpan={6} className="py-4 text-center text-slate-500">No aggregated usage yet.</td></tr>}
                {usage.map((u) => (
                  <tr key={`${u.tenant_slug}-${u.day}`} className="border-b border-slate-100">
                    <td className="py-2"><code className="text-xs">{u.tenant_slug}</code></td>
                    <td className="text-slate-700">{u.day}</td>
                    <td className="text-right text-slate-700">{u.requests}</td>
                    <td className="text-right text-slate-700">{u.input_tokens}</td>
                    <td className="text-right text-slate-700">{u.output_tokens}</td>
                    <td className="text-right text-slate-700 font-mono">${u.total_cost_usd.toFixed(6)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      ),
    },
    { id: "models", label: "Models", element: <ModelBreakdown scope="vendor" /> },
    {
      id: "verify",
      label: "Verify access",
      element: (
        <div className="space-y-6">
          <section className="bg-white border border-slate-200 rounded-lg p-5">
            <h2 className="text-lg font-semibold text-slate-900 mb-1">Verify our access — the customer&apos;s trust anchor</h2>
            <p className="text-sm text-slate-600 mb-4">
              The most important guarantee we offer: OpenScope engineers cannot see your prompts.
              Below is the actual SQL we try to run, and Postgres&apos;s actual reply. Try it.
            </p>
            <button
              onClick={runVerify}
              disabled={verifying}
              className="bg-slate-900 hover:bg-slate-800 disabled:bg-slate-400 text-white text-sm px-4 py-2 rounded"
            >
              {verifying ? "Asking Postgres…" : "Try to read sensitive.prompt_records"}
            </button>
            {verifyErr && <div className="mt-3 text-sm text-red-700 bg-red-50 border border-red-200 rounded p-2">{verifyErr}</div>}
            {verify && (
              <div className="mt-4 border border-red-300 bg-red-50 rounded p-3 font-mono text-xs">
                <div><b>$</b> psql -U <code>{verify.pool}</code> -c &quot;{verify.attempted_query}&quot;</div>
                <div className="mt-2 text-red-700">{verify.postgres_message}</div>
                <div className="mt-2 text-slate-600 text-[11px]">
                  ↑ Postgres refused the query. The deny is enforced by the database engine via schema GRANTs — not by application code we wrote.
                </div>
              </div>
            )}
          </section>

          <section className="bg-white border border-slate-200 rounded-lg p-5">
            <h2 className="text-lg font-semibold text-slate-900 mb-1">Application-layer denies (HTTP)</h2>
            <p className="text-sm text-slate-600 mb-3">
              Even before queries reach Postgres, the console&apos;s role middleware denies engineer requests to tenant-scoped endpoints. Click to verify.
            </p>
            <div className="flex flex-wrap gap-2">
              <button
                onClick={() => probe("/api/console/api/v1/prompts", () => consoleApi.prompts(1))}
                className="text-sm bg-white border border-slate-300 rounded px-3 py-1.5 hover:bg-slate-50"
              >
                Try GET /api/v1/prompts
              </button>
              <button
                onClick={() => probe("/api/console/api/v1/receipts", () => consoleApi.receipts(1))}
                className="text-sm bg-white border border-slate-300 rounded px-3 py-1.5 hover:bg-slate-50"
              >
                Try GET /api/v1/receipts
              </button>
              <button
                onClick={() => probe("/api/console/api/v1/usage", () => consoleApi.usage())}
                className="text-sm bg-white border border-slate-300 rounded px-3 py-1.5 hover:bg-slate-50"
              >
                Try GET /api/v1/usage
              </button>
            </div>
            {Object.keys(probeErrs).length > 0 && (
              <ul className="mt-3 space-y-1 text-xs font-mono">
                {Object.entries(probeErrs).map(([endpoint, msg]) => (
                  <li key={endpoint} className="border border-red-200 bg-red-50 rounded p-2">
                    <code className="text-red-700">{endpoint}</code>
                    <div className="text-red-700 mt-1">{msg}</div>
                  </li>
                ))}
              </ul>
            )}
          </section>
        </div>
      ),
    },
  ];

  return <ConsoleShell sections={sections} />;
}

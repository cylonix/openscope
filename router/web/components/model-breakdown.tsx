"use client";

// ModelBreakdown — per-model usage & pricing, the "real customer has a whole
// lineup" view. Instead of one flat token count, every entitled model gets a
// row: provider, tier, admin enablement, unit price (in/out per MTok), and this
// month's calls / tokens / cost. Unused-but-entitled models show too (zero-
// filled) with a toggle to hide them — so "you have access to N models, your
// admin enabled M, here's what actually got used" reads at a glance.
//
//   scope="tenant" — the customer IT view (their own usage)
//   scope="vendor" — the OpenScope Ops view (cross-tenant metering, adds a
//                    Tenants column; never any prompt content)

import { useEffect, useState } from "react";
import { consoleApi, ModelInfo, isAuthError, redirectToLogin } from "@/lib/api";

export function ModelBreakdown({ scope }: { scope: "tenant" | "vendor" }) {
  const [models, setModels] = useState<ModelInfo[]>([]);
  const [region, setRegion] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [hideUnused, setHideUnused] = useState(false);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let on = true;
    (async () => {
      try {
        const r = scope === "vendor" ? await consoleApi.vendorModels() : await consoleApi.models();
        if (!on) return;
        setModels(r.models ?? []);
        setRegion(r.region);
      } catch (e) {
        if (isAuthError(e)) { redirectToLogin(); return; }
        if (on) setErr(String(e));
      } finally {
        if (on) setLoading(false);
      }
    })();
    return () => { on = false; };
  }, [scope]);

  const enabledCount = models.filter((m) => m.enabled).length;
  const usedCount = models.filter((m) => m.calls > 0).length;

  // Used first (by cost desc), then enabled-unused, then disabled.
  const sorted = [...models].sort((a, b) => {
    const au = a.calls > 0 ? 1 : 0, bu = b.calls > 0 ? 1 : 0;
    if (bu !== au) return bu - au;
    if (b.total_cost_usd !== a.total_cost_usd) return b.total_cost_usd - a.total_cost_usd;
    const ae = a.enabled ? 1 : 0, be = b.enabled ? 1 : 0;
    if (be !== ae) return be - ae;
    return a.display_name.localeCompare(b.display_name);
  });
  const rows = hideUnused ? sorted.filter((m) => m.calls > 0) : sorted;

  const totals = models.reduce(
    (acc, m) => ({
      calls: acc.calls + m.calls,
      input: acc.input + m.input_tokens,
      output: acc.output + m.output_tokens,
      cost: acc.cost + m.total_cost_usd,
    }),
    { calls: 0, input: 0, output: 0, cost: 0 }
  );

  const cols = scope === "vendor" ? 9 : 8;

  return (
    <section className="bg-white border border-slate-200 rounded-lg p-5">
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div className="max-w-2xl">
          <h2 className="text-lg font-semibold text-slate-900">
            Model usage &amp; pricing — {scope === "vendor" ? "all tenants, this month" : "this month"}
          </h2>
          <p className="text-sm text-slate-600 mt-1">
            {scope === "vendor" ? (
              <>Cross-tenant metering by model — tokens, unit price, and cost. Metadata only; no prompt content.</>
            ) : (
              <>
                Your administrator enabled <b>{enabledCount}</b> of <b>{models.length}</b> models available in your
                Bedrock account. Disabled models are refused at the perimeter.
              </>
            )}
            {region && <> Served by <span className="font-medium">AWS Bedrock · {region}</span>.</>}
          </p>
        </div>
        <label className="text-xs text-slate-600 flex items-center gap-1.5 cursor-pointer select-none whitespace-nowrap">
          <input type="checkbox" checked={hideUnused} onChange={(e) => setHideUnused(e.target.checked)} />
          Hide unused models
        </label>
      </div>

      {err && <div className="mt-3 text-sm text-red-700 bg-red-50 border border-red-200 rounded p-2">{err}</div>}

      <div className="mt-4 overflow-x-auto">
        <table className="w-full text-sm">
          <thead className="text-[11px] uppercase tracking-wide text-slate-500 border-b border-slate-200">
            <tr>
              <th className="text-left py-2 pr-3">Model</th>
              <th className="text-left pr-3 hidden lg:table-cell">Provider</th>
              <th className="text-left pr-3">Status</th>
              <th className="text-right pr-3 whitespace-nowrap hidden sm:table-cell">Unit price (in / out · /MTok)</th>
              <th className="text-right pr-3 hidden md:table-cell">Calls</th>
              <th className="text-right pr-3 hidden lg:table-cell">In tok</th>
              <th className="text-right pr-3 hidden lg:table-cell">Out tok</th>
              {scope === "vendor" && <th className="text-right pr-3 hidden md:table-cell">Tenants</th>}
              <th className="text-right">Cost (USD)</th>
            </tr>
          </thead>
          <tbody>
            {loading && (
              <tr><td colSpan={cols} className="py-6 text-center text-slate-400">Loading…</td></tr>
            )}
            {!loading && rows.length === 0 && (
              <tr><td colSpan={cols} className="py-6 text-center text-slate-400">No models to show.</td></tr>
            )}
            {rows.map((m) => {
              const used = m.calls > 0;
              return (
                <tr key={m.id} className="border-b border-slate-100" style={m.enabled ? undefined : { opacity: 0.5 }}>
                  <td className="py-2 pr-3">
                    <div className="font-medium text-slate-900">{m.display_name}</div>
                    <div className="text-[10px] font-mono text-slate-400 break-all">{m.id}</div>
                    {/* tier rides along on mobile, where the Provider column is hidden */}
                    <div className="text-[10px] uppercase tracking-wide text-slate-400 lg:hidden">{m.provider} · {m.tier}</div>
                  </td>
                  <td className="pr-3 text-slate-700 hidden lg:table-cell">
                    {m.provider}
                    <span className="text-[10px] uppercase tracking-wide text-slate-400 ml-1">{m.tier}</span>
                  </td>
                  <td className="pr-3">
                    {m.enabled ? (
                      <span className="text-[11px] font-medium px-1.5 py-0.5 rounded bg-green-100 text-green-800">enabled</span>
                    ) : (
                      <span
                        className="text-[11px] font-medium px-1.5 py-0.5 rounded bg-slate-100 text-slate-500"
                        title="Disabled by your administrator's model policy — the router refuses requests for this model"
                      >
                        disabled
                      </span>
                    )}
                  </td>
                  <td className="pr-3 text-right font-mono text-slate-600 whitespace-nowrap hidden sm:table-cell">
                    ${fmtPrice(m.input_per_mtok)} / ${fmtPrice(m.output_per_mtok)}
                  </td>
                  <td className="pr-3 text-right tabular-nums text-slate-700 hidden md:table-cell">{used ? m.calls.toLocaleString() : "—"}</td>
                  <td className="pr-3 text-right tabular-nums text-slate-700 hidden lg:table-cell">{used ? m.input_tokens.toLocaleString() : "—"}</td>
                  <td className="pr-3 text-right tabular-nums text-slate-700 hidden lg:table-cell">{used ? m.output_tokens.toLocaleString() : "—"}</td>
                  {scope === "vendor" && (
                    <td className="pr-3 text-right tabular-nums text-slate-700 hidden md:table-cell">{used ? (m.tenants ?? 0) : "—"}</td>
                  )}
                  <td className="text-right font-mono text-slate-900">{used ? `$${m.total_cost_usd.toFixed(6)}` : "—"}</td>
                </tr>
              );
            })}
          </tbody>
          {totals.calls > 0 && (
            <tfoot>
              <tr className="border-t border-slate-200 font-semibold">
                <td className="py-2 pr-3 text-slate-900 whitespace-nowrap">Total — {usedCount} model{usedCount === 1 ? "" : "s"} used</td>
                <td className="pr-3 hidden lg:table-cell"></td>
                <td className="pr-3"></td>
                <td className="pr-3 hidden sm:table-cell"></td>
                <td className="pr-3 text-right tabular-nums text-slate-900 hidden md:table-cell">{totals.calls.toLocaleString()}</td>
                <td className="pr-3 text-right tabular-nums text-slate-900 hidden lg:table-cell">{totals.input.toLocaleString()}</td>
                <td className="pr-3 text-right tabular-nums text-slate-900 hidden lg:table-cell">{totals.output.toLocaleString()}</td>
                {scope === "vendor" && <td className="hidden md:table-cell"></td>}
                <td className="text-right font-mono text-slate-900">${totals.cost.toFixed(6)}</td>
              </tr>
            </tfoot>
          )}
        </table>
      </div>
    </section>
  );
}

// fmtPrice renders a per-MTok price with enough precision for cheap models
// ($0.035) without trailing noise on pricier ones ($15.00).
function fmtPrice(perMTok: number): string {
  if (perMTok >= 0.1) return perMTok.toFixed(2);
  return perMTok.toFixed(3);
}

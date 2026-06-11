"use client";

// SecurityFeed — the live SOC / IT-auditor console. This is "what your
// security team sees in real time": every coding-agent call as it happens,
// with blocks surfaced as ALERTS, the DLP rule that fired, the workspace it
// came from, and the running spend — auto-refreshing. Plus the load-bearing
// trust statement: OpenScope sees this metadata and *that* a block happened,
// but never the prompt or code itself.
//
// Modeled on the trusted-ds auditor view: stat tiles, a plain-language privacy
// banner, color-coded action chips, and a continuously-updating event table.

import { useCallback, useEffect, useRef, useState } from "react";
import { consoleApi, RouterEvent, UsageSummary, isAuthError, redirectToLogin } from "@/lib/api";

const POLL_MS = 3500;

export function SecurityFeed() {
  const [events, setEvents] = useState<RouterEvent[]>([]);
  const [usage, setUsage] = useState<UsageSummary | null>(null);
  const [live, setLive] = useState(true);
  const [err, setErr] = useState<string | null>(null);
  const [lastBeat, setLastBeat] = useState<number>(0);
  const seen = useRef<Set<string>>(new Set());
  const [fresh, setFresh] = useState<Set<string>>(new Set());

  const load = useCallback(async () => {
    try {
      const [e, u] = await Promise.all([consoleApi.events(40), consoleApi.usage()]);
      const evs = e.events ?? []; // backend sends null for an empty list
      // mark newly-arrived request_ids so we can flash them
      const incoming = new Set<string>();
      for (const ev of evs) {
        if (!seen.current.has(ev.request_id)) incoming.add(ev.request_id);
        seen.current.add(ev.request_id);
      }
      setEvents(evs);
      setUsage(u);
      setErr(null);
      setLastBeat(Date.now());
      if (incoming.size) {
        setFresh(incoming);
        setTimeout(() => setFresh(new Set()), 1500);
      }
    } catch (e) {
      // Session timed out while the feed was polling — bounce to login
      // instead of spinning on a dead poll with a stale error banner.
      if (isAuthError(e)) { redirectToLogin(); return; }
      setErr(String(e));
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  useEffect(() => {
    if (!live) return;
    const id = setInterval(() => void load(), POLL_MS);
    return () => clearInterval(id);
  }, [live, load]);

  const blocked = events.filter((e) => e.decision === "deny").length;
  const allowed = events.filter((e) => e.decision === "allow").length;
  const served = servedSummary(events);

  return (
    <div className="space-y-4">
      {/* Trust banner — what OpenScope can and can't see */}
      <div className="bg-slate-50 border border-slate-200 rounded-lg p-4">
        <div className="flex items-start gap-3">
          <span className="text-lg leading-none mt-0.5">🔒</span>
          <div className="text-sm text-slate-700">
            <span className="font-semibold text-slate-900">What OpenScope can see — and what it can&apos;t.</span>{" "}
            This feed is metadata: which agent called, the decision, the DLP rule that fired, token
            counts, and cost. The <span className="font-medium">prompt and code never appear here</span> —
            bodies live in <code className="text-xs bg-white border border-slate-200 px-1 rounded">sensitive.*</code>,
            which OpenScope&apos;s <code className="text-xs bg-white border border-slate-200 px-1 rounded">vendor_reader</code> role
            is GRANT-denied at the database. It runs in your VPC, the source is yours to read, and
            nothing transits a third party to be scanned — so this isn&apos;t a promise, it&apos;s
            something your team can verify.
          </div>
        </div>
      </div>

      {/* Stat tiles */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <Tile label="Agent calls" value={events.length} />
        <Tile label="Blocked (alerts)" value={blocked} tone={blocked > 0 ? "alert" : "neutral"} />
        <Tile label="Allowed" value={allowed} tone="ok" />
        <Tile
          label="Spend / cap"
          value={usage ? `$${usage.total_cost_usd.toFixed(4)} / $${usage.monthly_cap_usd.toFixed(2)}` : "—"}
        />
      </div>

      {/* Served-by strip — where the calls actually went. The pitch made
          concrete: a dedicated account, a known region, named models. */}
      <div className="flex items-center gap-2 flex-wrap text-xs">
        <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md border border-slate-200 bg-white">
          <span className="text-[10px] uppercase tracking-wide text-slate-400">served by</span>
          <span className="font-medium text-slate-800">☁ {served.platform ?? "AWS Bedrock · us-west-2"}</span>
        </span>
        {served.models.length > 0 && (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md border border-slate-200 bg-white">
            <span className="text-[10px] uppercase tracking-wide text-slate-400">models</span>
            <span className="font-mono text-slate-800">{served.models.join(" · ")}</span>
          </span>
        )}
        <span className="text-slate-400">— your dedicated Bedrock account; calls never leave this region.</span>
      </div>

      {/* Live feed */}
      <section className="bg-white border border-slate-200 rounded-lg overflow-hidden">
        <div className="px-4 py-2.5 border-b border-slate-200 flex items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <span className={`inline-block w-2 h-2 rounded-full ${live ? "bg-green-500 animate-pulse" : "bg-slate-300"}`} />
            <h3 className="text-sm font-semibold text-slate-900">Live agent activity</h3>
            <span className="text-xs text-slate-400">
              {lastBeat ? `updated ${new Date(lastBeat).toLocaleTimeString()}` : "loading…"}
            </span>
          </div>
          <div className="flex items-center gap-3">
            <button onClick={() => downloadCSV(events)} className="text-xs text-blue-600 hover:underline" title="Export to your SIEM — your data, your tooling">
              export CSV
            </button>
            <button onClick={() => setLive((v) => !v)} className="text-xs text-blue-600 hover:underline">
              {live ? "pause" : "resume"}
            </button>
            <button onClick={() => void load()} className="text-xs text-blue-600 hover:underline">refresh</button>
          </div>
        </div>

        {err && <div className="px-4 py-2 text-xs text-red-700 bg-red-50">{err}</div>}

        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="text-[11px] uppercase tracking-wide text-slate-500 bg-slate-50 border-b border-slate-200">
              <tr>
                <th className="text-left px-3 sm:px-4 py-2">Time</th>
                <th className="text-left px-3 sm:px-4 py-2 hidden lg:table-cell">Workspace</th>
                <th className="text-left px-3 sm:px-4 py-2 hidden md:table-cell">Endpoint</th>
                <th className="text-left px-3 sm:px-4 py-2 hidden sm:table-cell">Model · served by</th>
                <th className="text-left px-3 sm:px-4 py-2">Decision</th>
                <th className="text-left px-3 sm:px-4 py-2">Alert / rule</th>
                <th className="text-right px-3 sm:px-4 py-2 hidden md:table-cell">Withheld / sent</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {events.length === 0 && (
                <tr><td colSpan={7} className="px-4 py-8 text-center text-slate-400">
                  Waiting for agent activity — run the governed console (Developer view) or point a real agent at the endpoint.
                </td></tr>
              )}
              {events.map((e) => <EventRow key={e.request_id} e={e} fresh={fresh.has(e.request_id)} />)}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}

function EventRow({ e, fresh }: { e: RouterEvent; fresh: boolean }) {
  const deny = e.decision === "deny";
  const ws = parseWorkspace(e.reason);
  // Use the theme-adaptive --danger-bg var for the alert-row tint (dark + light
  // both defined) and a left accent bar, rather than a fixed light-red wash.
  return (
    <tr
      style={deny ? { background: "var(--danger-bg)", boxShadow: "inset 3px 0 0 var(--danger)" } : undefined}
      className={fresh ? "ring-2 ring-inset ring-blue-300" : ""}
    >
      <td className="px-3 sm:px-4 py-2 text-xs text-slate-500 whitespace-nowrap font-mono">{shortTime(e.ts)}</td>
      <td className="px-3 sm:px-4 py-2 hidden lg:table-cell">
        {ws ? (
          <span className="text-xs font-mono text-slate-700">{ws}</span>
        ) : (
          <span className="text-xs text-slate-400">—</span>
        )}
      </td>
      <td className="px-3 sm:px-4 py-2 hidden md:table-cell"><code className="text-xs text-slate-600">{e.endpoint}</code></td>
      <td className="px-3 sm:px-4 py-2 hidden sm:table-cell">
        {e.model ? (
          <div className="leading-tight">
            <div className="text-xs font-medium text-slate-700">{e.model_label || e.model}</div>
            <div className="text-[10px] text-slate-400">
              {e.provider ?? "AWS Bedrock"}{e.region ? ` · ${e.region}` : ""}
            </div>
          </div>
        ) : (
          <span className="text-xs text-slate-400">—</span>
        )}
      </td>
      <td className="px-3 sm:px-4 py-2">
        {deny ? (
          <span className="inline-block text-[11px] font-semibold px-2 py-0.5 rounded bg-red-100 text-red-800">⛔ {alertLabel(e.result)}</span>
        ) : (
          <span className="inline-block text-[11px] font-medium px-2 py-0.5 rounded bg-green-100 text-green-800">✅ allowed</span>
        )}
      </td>
      <td className="px-3 sm:px-4 py-2">
        {e.dlp_rule_ids?.length ? (
          <span className="flex flex-wrap gap-1">
            {e.dlp_rule_ids.map((id) => (
              <code key={id} className="text-[11px] bg-red-100 text-red-800 px-1.5 py-0.5 rounded font-mono">{id}</code>
            ))}
          </span>
        ) : (
          <span className="text-xs text-slate-400">—</span>
        )}
      </td>
      <td className="px-3 sm:px-4 py-2 text-right font-mono text-xs text-slate-600 hidden md:table-cell">
        {deny ? <span className="text-red-700">{e.bytes_in} B withheld</span> : `${e.bytes_in}/${e.bytes_out} B`}
      </td>
    </tr>
  );
}

function Tile({ label, value, tone = "neutral" }: { label: string; value: string | number; tone?: "neutral" | "alert" | "ok" }) {
  const valueColor = tone === "alert" ? "text-red-700" : tone === "ok" ? "text-green-700" : "text-slate-900";
  return (
    <div className="bg-white border border-slate-200 rounded-lg p-3">
      <div className="text-[11px] uppercase tracking-wide text-slate-500">{label}</div>
      <div className={`text-2xl font-bold mt-0.5 ${valueColor}`}>{value}</div>
    </div>
  );
}

// servedSummary derives the "where did the calls go" header from the events:
// the serving platform/region (e.g. "AWS Bedrock · us-west-2") and the set of
// distinct models seen. Both come from the router (catalog label + configured
// region), so the feed names exactly what served each request — no guessing.
function servedSummary(events: RouterEvent[]): { platform: string | null; models: string[] } {
  let platform: string | null = null;
  const models: string[] = [];
  for (const e of events) {
    if (!platform && e.provider && e.region) platform = `${e.provider} · ${e.region}`;
    const label = e.model_label || e.model;
    if (label && !models.includes(label)) models.push(label);
  }
  return { platform, models };
}

// reason carries "[ws:northwind-rtl] …" since router_events has no workspace
// column in the MVP schema; pull it back out for display.
function parseWorkspace(reason?: string): string | null {
  if (!reason) return null;
  const m = reason.match(/\[ws:([^\]]+)\]/);
  return m ? m[1] : null;
}

function downloadCSV(events: RouterEvent[]) {
  const blob = new Blob([eventsToCSV(events)], { type: "text/csv" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "openscope-audit.csv";
  a.click();
  URL.revokeObjectURL(url);
}

function shortTime(ts: string): string {
  // ts like "2026-06-05 09:16:41.985806" or ISO; show HH:MM:SS
  const t = ts.includes("T") ? ts.split("T")[1] : ts.split(" ")[1];
  return t ? t.split(".")[0] : ts;
}

function alertLabel(result: string): string {
  switch (result) {
    case "dlp_block": return "DLP block";
    case "channel_block": return "channel policy";
    case "budget_exceeded": return "budget block";
    default: return "blocked";
  }
}

// exportCSV builds a CSV from the current events and triggers a download —
// the "your audit trail, in your SIEM" story: it's your data, exportable with
// your own tooling, not locked in a vendor dashboard.
export function eventsToCSV(events: RouterEvent[]): string {
  const head = ["ts", "request_id", "role", "endpoint", "decision", "result", "dlp_rule_ids", "bytes_in", "bytes_out", "reason"];
  const rows = events.map((e) => [
    e.ts, e.request_id, e.role, e.endpoint, e.decision, e.result,
    (e.dlp_rule_ids ?? []).join("|"), String(e.bytes_in), String(e.bytes_out),
    (e.reason ?? "").replace(/[\r\n,]+/g, " "),
  ]);
  return [head, ...rows].map((r) => r.map((c) => `"${String(c).replace(/"/g, '""')}"`).join(",")).join("\n");
}

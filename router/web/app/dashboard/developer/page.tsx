"use client";

import { useState } from "react";
import { routerApi, ScanResponse, ChatResponse, ApiError } from "@/lib/api";
import { GovernedConsole } from "@/components/governed-console";
import { DetectionGallery } from "@/components/detection-gallery";
import { ConnectAgent } from "@/components/connect-agent";
import { TopologyDiagram } from "@/components/topology-diagram";
import { ConsoleShell, type ConsoleSection } from "@/components/console-shell";

const MODELS = [
  { id: "us.amazon.nova-micro-v1:0", label: "Nova Micro (cheap dev)", tier: "dev" },
  { id: "us.anthropic.claude-haiku-4-5-20251001-v1:0", label: "Claude Haiku 4.5 (standard)", tier: "standard" },
  { id: "anthropic.claude-opus-4-7", label: "Claude Opus 4.7 (premium — gated)", tier: "premium" },
];

export default function DeveloperDashboard() {
  const sections: ConsoleSection[] = [
    { id: "console", label: "Governed console", element: <GovernedConsole /> },
    { id: "detection", label: "Detection coverage", element: <DetectionGallery /> },
    { id: "topology", label: "Topology", element: <TopologyDiagram /> },
    { id: "connect", label: "Connect your agent", element: <ConnectAgent /> },
    {
      id: "more",
      label: "More tools",
      element: (
        <div className="space-y-8">
          <ScenarioA />
          <ScenarioB />
        </div>
      ),
    },
  ];
  return <ConsoleShell sections={sections} />;
}

function ScenarioA() {
  const [file, setFile] = useState<File | null>(null);
  const [result, setResult] = useState<ScanResponse | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!file) return;
    setLoading(true);
    setErr(null); setResult(null);
    try {
      const token = sessionStorage.getItem("openscope_token") ?? "";
      const r = await routerApi.scan(token, file);
      setResult(r);
    } catch (e) {
      setErr(e instanceof ApiError ? `${e.code}: ${e.message}` : String(e));
    } finally {
      setLoading(false);
    }
  }

  return (
    <Card title="Scenario A — Upload a document">
      <p className="text-sm text-slate-600 mb-3">
        Upload a source or text file. The router runs a content-aware DLP pass before any model
        call — proprietary HDL/RTL, SPICE, layout, confidentiality &amp; export markers, and
        secrets are blocked at the perimeter. (PDFs aren&apos;t supported — paste text.)
      </p>
      <form onSubmit={submit} className="flex gap-2 items-center">
        <input
          type="file"
          accept=".txt,.md,.json,.csv,.log,.v,.sv,.vh,.svh,.vhd,.vhdl,.sp,.cir,.spice,.sdc,.lib,.lef,.def,.tcl,.py,.ts,text/*"
          onChange={(e) => setFile(e.target.files?.[0] ?? null)}
          className="text-sm"
        />
        <button
          type="submit"
          disabled={!file || loading}
          className="btn-accent disabled:opacity-50 text-sm px-4 py-2 rounded"
        >
          {loading ? "Scanning…" : "Scan"}
        </button>
      </form>
      {err && <ErrorBlock msg={err} />}
      {result && <ScanResultDisplay r={result} />}
    </Card>
  );
}

function ScanResultDisplay({ r }: { r: ScanResponse }) {
  const allow = r.decision === "allow";
  return (
    <div className="mt-4 border rounded p-3" style={{ borderColor: allow ? "#86efac" : "#fca5a5", background: allow ? "#f0fdf4" : "#fef2f2" }}>
      <div className="flex items-center gap-2">
        <Badge tone={allow ? "ok" : "deny"}>{r.decision.toUpperCase()}</Badge>
        <code className="text-xs text-slate-500">{r.request_id}</code>
      </div>
      {r.reason && <p className="text-sm text-slate-700 mt-2">{r.reason}</p>}
      {r.findings && r.findings.length > 0 && (
        <div className="mt-2">
          <div className="text-xs uppercase tracking-wide text-slate-500 mb-1">DLP findings</div>
          <ul className="text-sm text-slate-700 list-disc ml-5">
            {r.findings.map((f) => (
              <li key={f.rule_id}>
                <code className="text-xs">{f.rule_id}</code> — {f.rule_name} (×{f.count}, {f.severity})
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

function ScenarioB() {
  const [model, setModel] = useState(MODELS[0].id);
  const [prompt, setPrompt] = useState("Write a Python program that prints 'Hello, World!'.");
  const [result, setResult] = useState<ChatResponse | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setErr(null); setResult(null);
    try {
      const token = sessionStorage.getItem("openscope_token") ?? "";
      const r = await routerApi.chat(token, {
        model,
        messages: [{ role: "user", content: prompt }],
        max_tokens: 256,
      });
      setResult(r);
    } catch (e) {
      setErr(e instanceof ApiError ? `${e.code}: ${e.message}` : String(e));
    } finally {
      setLoading(false);
    }
  }

  return (
    <Card title="Scenario B — Ask Claude / Nova via the router">
      <p className="text-sm text-slate-600 mb-3">
        Prompt goes through DLP, then to the selected model in your dedicated Bedrock account.
        Every call produces an Ed25519-signed receipt with cost &amp; SHA-256 of bodies — your IT team can verify charges without seeing prompt content.
      </p>
      <form onSubmit={submit} className="space-y-3">
        <div className="flex gap-2 items-center">
          <label className="text-sm text-slate-700">Model:</label>
          <select
            value={model}
            onChange={(e) => setModel(e.target.value)}
            className="text-sm border border-slate-300 rounded px-2 py-1.5"
          >
            {MODELS.map((m) => (
              <option key={m.id} value={m.id}>{m.label}</option>
            ))}
          </select>
        </div>
        <textarea
          value={prompt}
          onChange={(e) => setPrompt(e.target.value)}
          rows={4}
          className="w-full text-sm border border-slate-300 rounded p-2 font-mono"
        />
        <button
          type="submit"
          disabled={loading}
          className="btn-accent disabled:opacity-50 text-sm px-4 py-2 rounded"
        >
          {loading ? "Calling Bedrock…" : "Send"}
        </button>
      </form>
      {err && <ErrorBlock msg={err} />}
      {result && <ChatResultDisplay r={result} />}
    </Card>
  );
}

function ChatResultDisplay({ r }: { r: ChatResponse }) {
  const allow = r.decision === "allow";
  return (
    <div className="mt-4 space-y-3">
      <div className="border rounded p-3" style={{ borderColor: allow ? "#86efac" : "#fca5a5", background: allow ? "#f0fdf4" : "#fef2f2" }}>
        <div className="flex items-center gap-2 flex-wrap">
          <Badge tone={allow ? "ok" : "deny"}>{r.decision.toUpperCase()}</Badge>
          <code className="text-xs text-slate-500">{r.request_id}</code>
        </div>
        <div className="text-xs text-slate-600 mt-1">
          served by <span className="font-medium text-slate-800">{r.model_label || r.model}</span>
          {r.provider ? ` · ${r.provider}` : ""}{r.region ? ` · ${r.region}` : ""}
          {r.requested_model && (
            <span className="text-amber-700"> (agent requested <code className="text-[11px]">{r.requested_model}</code> → remapped)</span>
          )}
        </div>
        {r.reason && <p className="text-sm text-slate-700 mt-2">{r.reason}</p>}
        {r.findings && r.findings.length > 0 && (
          <ul className="text-sm text-slate-700 list-disc ml-5 mt-2">
            {r.findings.map((f) => (
              <li key={f.rule_id}><code className="text-xs">{f.rule_id}</code> — {f.rule_name}</li>
            ))}
          </ul>
        )}
        {r.content && (
          <pre className="mt-2 text-sm bg-white border border-slate-200 rounded p-2 whitespace-pre-wrap">{r.content}</pre>
        )}
      </div>
      {r.usage && (
        <div className="border border-slate-200 rounded p-3 bg-white">
          <div className="text-xs uppercase tracking-wide text-slate-500 mb-1">Usage &amp; spend</div>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-sm">
            <Stat label="Input tokens" value={r.usage.input_tokens} />
            <Stat label="Output tokens" value={r.usage.output_tokens} />
            <Stat label="This call" value={`$${r.usage.total_cost_usd.toFixed(6)}`} />
            <Stat label="MTD" value={`$${r.usage.month_to_date_usd.toFixed(6)} / $${r.usage.monthly_cap_usd.toFixed(2)}`} />
          </div>
        </div>
      )}
      {r.receipt && (
        <div className="border border-slate-200 rounded p-3 bg-white">
          <div className="text-xs uppercase tracking-wide text-slate-500 mb-1">Signed receipt</div>
          <div className="text-xs text-slate-700 font-mono break-all">
            <div><b>key_id:</b> {r.receipt.public_key_id}</div>
            <div className="mt-1"><b>signature:</b> {r.receipt.signature.substring(0, 80)}…</div>
            <details className="mt-1">
              <summary className="cursor-pointer">Payload</summary>
              <pre className="mt-1 bg-slate-50 p-2 rounded text-[11px] whitespace-pre-wrap">{JSON.stringify(r.receipt.payload, null, 2)}</pre>
            </details>
          </div>
        </div>
      )}
    </div>
  );
}

function Card({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="bg-white border border-slate-200 rounded-lg p-5">
      <h2 className="text-lg font-semibold text-slate-900 mb-3">{title}</h2>
      {children}
    </section>
  );
}

function Badge({ tone, children }: { tone: "ok" | "deny"; children: React.ReactNode }) {
  return (
    <span className={`text-xs font-mono px-2 py-0.5 rounded ${
      tone === "ok" ? "bg-green-100 text-green-800" : "bg-red-100 text-red-800"
    }`}>{children}</span>
  );
}

function ErrorBlock({ msg }: { msg: string }) {
  return <div className="mt-3 text-sm text-red-700 bg-red-50 border border-red-200 rounded p-2">{msg}</div>;
}

function Stat({ label, value }: { label: string; value: string | number }) {
  return (
    <div>
      <div className="text-xs text-slate-500">{label}</div>
      <div className="text-sm font-medium text-slate-900">{value}</div>
    </div>
  );
}

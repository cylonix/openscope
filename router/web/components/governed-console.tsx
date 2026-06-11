"use client";

// GovernedConsole — the two-column governance demo.
//
// LEFT pane is a detection runner driven by a dropdown: pick which block to
// show — the repo CHANNEL policy (deny-by-default) or any CONTENT detector
// (HDL, SPICE, SDC, tapeout, markers, secrets…). Channel scenarios run through
// /v1/chat with a restricted workspace; content scenarios run through /v1/scan
// (pure DLP — what the payload *is*, regardless of repo).
//
// RIGHT pane is the "allowed work flows" control: ordinary code in an allowed
// repo, forwarded to the model, audited + receipted, unreadable by OpenScope.

import { useState } from "react";
import { routerApi, ChatResponse, ScanResponse, ApiError } from "@/lib/api";

const DEMO_MODEL = "us.amazon.nova-micro-v1:0";
const DEFAULT_INSTRUCTION = "Explain what this file does and suggest one improvement.";

type Finding = { rule_id: string; rule_name: string; category: string; severity: string; count: number };
type RunResult = {
  decision: "allow" | "deny";
  reason?: string;
  findings?: Finding[];
  content?: string;
  usage?: ChatResponse["usage"];
  receiptSig?: string;
  requestId?: string;
  modelLabel?: string;
  provider?: string;
  region?: string;
  requestedModel?: string;
};

// ---- LEFT pane: detection scenarios --------------------------------------

type Scenario = {
  key: string;
  label: string;
  kind: "channel" | "content";
  workspace?: string; // channel scenarios only
  target: string; // shown in the pane header
  filename: string;
  text?: string;
  bytes?: number[];
};

const SCENARIOS: Scenario[] = [
  {
    key: "channel", label: "Repo policy — deny-by-default (channel)", kind: "channel",
    workspace: "northwind-rtl", target: "northwind-rtl · restricted", filename: "rtl/aes_sbox.sv",
    text: "// COMPANY CONFIDENTIAL\n`timescale 1ns/1ps\nmodule aes_sbox(input [7:0] b, output reg [7:0] o);\n always_comb o=b;\nendmodule",
  },
  { key: "hdl", label: "Content — proprietary HDL (Verilog)", kind: "content", target: "content inspection", filename: "alu.sv",
    text: "`timescale 1ns/1ps\nmodule alu(input clk, input [7:0] a, output reg [7:0] y);\n always_ff @(posedge clk) y <= a + 8'd1;\nendmodule" },
  { key: "spice", label: "Content — SPICE netlist", kind: "content", target: "content inspection", filename: "ckt.sp",
    text: ".subckt opamp inp inn out vdd vss\n.model nmos1 nmos level=54\n.param vdd=1.8\n.ends\n.tran 1n 200n" },
  { key: "sdc", label: "Content — SDC timing constraints", kind: "content", target: "content inspection", filename: "top.sdc",
    text: "create_clock -name clk -period 2.0 [get_ports clk]\nset_input_delay 0.4 -clock clk [all_inputs]\nset_false_path -from [get_clocks jtag]" },
  { key: "tapeout", label: "Content — GDSII tapeout (binary magic)", kind: "content", target: "content inspection", filename: "chip.gds",
    bytes: [0x00, 0x06, 0x00, 0x02, 0x00, 0x05, 0x42, 0x47, 0x4e, 0x4c, 0x49, 0x42] },
  { key: "classification", label: "Content — confidential / trade-secret marker", kind: "content", target: "content inspection", filename: "spec.md",
    text: "NORTHWIND SEMICONDUCTOR — COMPANY CONFIDENTIAL — TRADE SECRET — NOT FOR EXTERNAL USE" },
  { key: "export", label: "Content — export-control (ITAR/EAR/ECCN)", kind: "content", target: "content inspection", filename: "notice.txt",
    text: "Classification: EXPORT-CONTROLLED. ECCN 3A001. Subject to the Export Administration Regulations." },
  { key: "foundry", label: "Content — foundry / PDK identifier", kind: "content", target: "content inspection", filename: "pdk.txt",
    text: "Built on the TSMC N3 PDK (3nm process) — process design kit under NDA." },
  { key: "secret", label: "Content — AWS key + private key", kind: "content", target: "content inspection", filename: "flow.tcl",
    text: 'set k "AKIAIOSFODNN7EXAMPLE"\n-----BEGIN RSA PRIVATE KEY-----\nMIIEfake-not-real-demo-only\n-----END RSA PRIVATE KEY-----' },
  { key: "ieee1735", label: "Content — IEEE-1735 encrypted IP", kind: "content", target: "content inspection", filename: "ip.v",
    text: '`pragma protect begin_protected\n`pragma protect data_method="aes128-cbc"' },
  { key: "ssn", label: "Content — US SSN (PII)", kind: "content", target: "content inspection", filename: "hr.txt",
    text: "Employee record — SSN: 123-45-6789" },
];

// ---- RIGHT pane: allowed sample files ------------------------------------

type SampleFile = { name: string; body: string };
const ALLOWED_WS = "northwind-webapp";
const ALLOWED_FILES: SampleFile[] = [
  { name: "src/cart.ts", body: "export const subtotal = (xs:{p:number,q:number}[]) => xs.reduce((s,i)=>s+i.p*i.q,0);" },
  { name: "src/hello.py", body: "def fib(n):\n a,b=0,1\n for _ in range(n): a,b=b,a+b\n return a" },
  { name: "docs/notes.txt", body: "Sprint: ship cart redesign, fix checkout rounding, add tests." },
];

export function GovernedConsole() {
  const [instruction, setInstruction] = useState(DEFAULT_INSTRUCTION);
  const [scenarioKey, setScenarioKey] = useState(SCENARIOS[0].key);
  const [left, setLeft] = useState<PaneState>({ result: null, loading: false, error: null });
  const [rightIdx, setRightIdx] = useState(0);
  const [right, setRight] = useState<PaneState>({ result: null, loading: false, error: null });

  const scenario = SCENARIOS.find((s) => s.key === scenarioKey) ?? SCENARIOS[0];

  async function runLeft(s: Scenario) {
    setLeft({ result: null, loading: true, error: null });
    try {
      const token = sessionStorage.getItem("openscope_token") ?? "";
      let res: RunResult;
      if (s.kind === "channel") {
        const r = await routerApi.chat(token, {
          model: DEMO_MODEL, workspace: s.workspace,
          messages: [{ role: "user", content: `${instruction}\n\n--- ${s.filename} ---\n${s.text}` }],
          max_tokens: 256,
        });
        res = fromChat(r);
      } else {
        const data: BlobPart = s.bytes ? new Uint8Array(s.bytes) : (s.text ?? "");
        const r = await routerApi.scan(token, new File([data], s.filename));
        res = fromScan(r);
      }
      setLeft({ result: res, loading: false, error: null });
    } catch (e) {
      setLeft({ result: null, loading: false, error: e instanceof ApiError ? `${e.code}: ${e.message}` : String(e) });
    }
  }

  async function runRight(idx: number) {
    const f = ALLOWED_FILES[idx];
    setRight({ result: null, loading: true, error: null });
    try {
      const token = sessionStorage.getItem("openscope_token") ?? "";
      const r = await routerApi.chat(token, {
        model: DEMO_MODEL, workspace: ALLOWED_WS,
        messages: [{ role: "user", content: `${instruction}\n\n--- ${f.name} ---\n${f.body}` }],
        max_tokens: 256,
      });
      setRight({ result: fromChat(r), loading: false, error: null });
    } catch (e) {
      setRight({ result: null, loading: false, error: e instanceof ApiError ? `${e.code}: ${e.message}` : String(e) });
    }
  }

  function runBoth() {
    void runLeft(scenario);
    void runRight(rightIdx);
  }

  const busy = left.loading || right.loading;

  return (
    <section className="bg-white border border-slate-200 rounded-lg p-5">
      <div className="flex items-start justify-between gap-6 flex-wrap">
        <div className="max-w-xl">
          <h2 className="text-lg font-semibold text-slate-900">Governed agent console</h2>
          <p className="text-sm text-slate-600 mt-1">
            Pick a block to demonstrate on the left — the repo <span className="font-medium">channel policy</span>,
            or any <span className="font-medium">content</span> detector — and watch ordinary work flow on the
            right. Both audited, both receipted, neither readable by OpenScope.
          </p>
        </div>
        <div className="bg-slate-50 border border-slate-200 rounded-lg p-3 text-xs text-slate-600 min-w-[240px]">
          <div className="uppercase tracking-wide text-slate-500 mb-2">What you&apos;ll see</div>
          <div className="space-y-1.5">
            <div><span className="text-red-700 font-medium">⛔ left</span> → blocked, 0 bytes to model</div>
            <div><span className="text-green-700 font-medium">✅ right</span> → flows, audited + receipted</div>
            <div><span className="text-slate-700 font-medium">🔒 either way</span> → OpenScope can&apos;t read it</div>
          </div>
        </div>
      </div>

      {/* ① Prominent detection selector — the primary control */}
      <div className="mt-4 rounded-lg p-3 border-2" style={{ background: "var(--teal-soft)", borderColor: "var(--teal)" }}>
        <label className="block text-xs font-semibold uppercase tracking-wide mb-1.5" style={{ color: "var(--text-strong)" }}>
          ① Pick a detection to demonstrate
        </label>
        <div className="flex gap-2 items-center flex-wrap">
          <select
            value={scenarioKey}
            onChange={(e) => { setScenarioKey(e.target.value); setLeft({ result: null, loading: false, error: null }); }}
            className="flex-1 min-w-[280px] text-sm border border-slate-300 rounded px-3 py-2.5 font-mono"
            style={{ background: "var(--panel-lowest)" }}
          >
            {SCENARIOS.map((s) => <option key={s.key} value={s.key}>{s.label}</option>)}
          </select>
          <button onClick={runBoth} disabled={busy} className="btn-accent text-sm font-medium px-5 py-2.5 rounded">
            {busy ? "Running…" : "Run in both ▶"}
          </button>
        </div>
      </div>

      {/* ② Secondary: agent instruction */}
      <div className="mt-3">
        <label className="block text-[11px] uppercase tracking-wide text-slate-500 mb-1">Agent instruction</label>
        <input
          value={instruction}
          onChange={(e) => setInstruction(e.target.value)}
          className="w-full text-sm border border-slate-300 rounded px-3 py-2 font-mono"
        />
      </div>

      <div className="mt-4 grid grid-cols-1 lg:grid-cols-2 gap-4 items-stretch">
        {/* LEFT — detection runner */}
        <div className="border border-slate-200 rounded-lg overflow-hidden flex flex-col h-full">
          <div className="px-3 py-2 border-b border-slate-200 flex items-center justify-between gap-2">
            <div className="flex items-center gap-2 min-w-0">
              <span className="font-mono text-sm text-slate-900 truncate">{scenario.target}</span>
              <span className="text-[11px] font-mono px-1.5 py-0.5 rounded bg-red-100 text-red-800">
                {scenario.kind === "channel" ? "channel policy" : "content scan"}
              </span>
            </div>
            <button onClick={() => runLeft(scenario)} disabled={left.loading} className="text-xs text-blue-600 hover:underline disabled:text-slate-400">
              {left.loading ? "running…" : "run ▶"}
            </button>
          </div>
          <div className="px-3 py-2 border-b border-slate-100 min-h-[78px]">
            <div className="text-[11px] uppercase tracking-wide text-slate-500 mb-1">Payload</div>
            <div className="text-xs font-mono text-slate-700">{scenario.filename}</div>
            <div className="text-[11px] text-slate-500 mt-0.5">
              {scenario.kind === "channel"
                ? "blocked by repo policy — regardless of content"
                : "blocked by content — what the payload is"}
            </div>
          </div>
          <div className="console-surface p-3 text-xs leading-relaxed flex-1 min-h-[300px]">
            <div>
              <span className="c-accent">agent@{scenario.kind === "channel" ? scenario.workspace : "sandbox"}</span>
              <span className="c-muted"> $ </span>
              send {scenario.filename}
            </div>
            {left.loading && <div className="c-muted mt-1">▌ inspecting at the perimeter…</div>}
            {left.error && <div className="c-deny mt-1">error: {left.error}</div>}
            {left.result && <Transcript r={left.result} />}
            {!left.loading && !left.result && !left.error && (
              <div className="c-deny mt-1">→ expected: BLOCKED<div className="c-muted mt-0.5">pick a detection · press run</div></div>
            )}
          </div>
        </div>

        {/* RIGHT — allowed flows */}
        <div className="border border-slate-200 rounded-lg overflow-hidden flex flex-col h-full">
          <div className="px-3 py-2 border-b border-slate-200 flex items-center justify-between gap-2">
            <div className="flex items-center gap-2 min-w-0">
              <span className="font-mono text-sm text-slate-900 truncate">{ALLOWED_WS}</span>
              <span className="text-[11px] font-mono px-1.5 py-0.5 rounded bg-green-100 text-green-800">allowed</span>
            </div>
            <button onClick={() => runRight(rightIdx)} disabled={right.loading} className="text-xs text-blue-600 hover:underline disabled:text-slate-400">
              {right.loading ? "running…" : "run ▶"}
            </button>
          </div>
          <div className="px-3 py-2 border-b border-slate-100 min-h-[78px]">
            <div className="text-[11px] uppercase tracking-wide text-slate-500 mb-1">Ordinary app code — attach a file:</div>
            <div className="flex flex-wrap gap-1.5">
              {ALLOWED_FILES.map((f, i) => (
                <button key={f.name} onClick={() => { setRightIdx(i); setRight({ result: null, loading: false, error: null }); }}
                  className={`text-[11px] font-mono px-2 py-1 rounded border ${i === rightIdx ? "chip-active" : "bg-white text-slate-700 border-slate-300 hover:bg-slate-100"}`}>
                  {f.name}
                </button>
              ))}
            </div>
          </div>
          <div className="console-surface p-3 text-xs leading-relaxed flex-1 min-h-[300px]">
            <div>
              <span className="c-accent">agent@{ALLOWED_WS}</span>
              <span className="c-muted"> $ </span>
              send {ALLOWED_FILES[rightIdx].name}
            </div>
            {right.loading && <div className="c-muted mt-1">▌ sending to model via OpenScope…</div>}
            {right.error && <div className="c-deny mt-1">error: {right.error}</div>}
            {right.result && <Transcript r={right.result} />}
            {!right.loading && !right.result && !right.error && (
              <div className="c-ok mt-1">→ expected: ALLOWED<div className="c-muted mt-0.5">press “Run in both ▶”</div></div>
            )}
          </div>
        </div>
      </div>
    </section>
  );
}

type PaneState = { result: RunResult | null; loading: boolean; error: string | null };

function fromChat(r: ChatResponse): RunResult {
  return {
    decision: r.decision, reason: r.reason, findings: r.findings as Finding[] | undefined,
    content: r.content, usage: r.usage, receiptSig: r.receipt?.signature, requestId: r.request_id,
    modelLabel: r.model_label || r.model, provider: r.provider, region: r.region,
    requestedModel: r.requested_model,
  };
}
function fromScan(r: ScanResponse): RunResult {
  return { decision: r.decision, reason: r.reason, findings: r.findings as Finding[] | undefined, requestId: r.request_id };
}

function Transcript({ r }: { r: RunResult }) {
  const rid = (r.requestId ?? "").slice(0, 8);
  if (r.decision === "deny") {
    return (
      <div className="mt-1">
        <div className="c-deny">⛔ BLOCKED at perimeter — 0 bytes sent to model</div>
        {r.reason && <div className="c-warn mt-0.5">policy: {r.reason}</div>}
        {r.findings && r.findings.length > 0 && <div className="c-muted mt-0.5">content flagged:</div>}
        {r.findings?.map((f) => (
          <div key={f.rule_id} className="c-warn">· {f.category} — {f.rule_name} <span className="c-muted">[{f.rule_id}]</span></div>
        ))}
        <div className="c-muted mt-1">{r.receiptSig ? `receipt ${r.receiptSig.slice(0, 10)}… · ` : ""}{rid ? `request ${rid} · ` : ""}audited</div>
      </div>
    );
  }
  return (
    <div className="mt-1">
      <div className="c-ok">✅ forwarded · model replied</div>
      {r.modelLabel && (
        <div className="c-muted mt-0.5">
          served by <span className="c-accent">{r.modelLabel}</span>
          {r.provider ? ` · ${r.provider}` : ""}{r.region ? ` ${r.region}` : ""}
          {r.requestedModel ? <span className="c-warn"> (agent requested {r.requestedModel})</span> : null}
        </div>
      )}
      {r.content && <div className="mt-1 whitespace-pre-wrap">{r.content.length > 600 ? r.content.slice(0, 600) + "…" : r.content}</div>}
      <div className="c-accent mt-1">🔒 prompt stored where OpenScope can&apos;t read it — your security team verifies</div>
      <div className="c-muted mt-0.5">
        {r.usage ? `${r.usage.input_tokens}→${r.usage.output_tokens} tok · $${r.usage.total_cost_usd.toFixed(6)} · ` : ""}
        {r.receiptSig ? `receipt ${r.receiptSig.slice(0, 10)}… · ` : ""}{rid ? `request ${rid} · ` : ""}audited
      </div>
    </div>
  );
}

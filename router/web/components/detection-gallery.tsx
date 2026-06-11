"use client";

// DetectionGallery — a one-click palette of the content engine's tripwires.
// The two-column console demonstrates the CHANNEL policy (deny-by-default by
// repo). This panel demonstrates the CONTENT engine: every Tier A/B/C detector
// firing on what the payload *is*, regardless of where it came from. It uses
// /v1/scan (pure DLP — no channel policy, no model call, no cost), so each chip
// shows the live decision + the exact rule(s) that fired.

import { useState } from "react";
import { routerApi, ScanResponse, ApiError } from "@/lib/api";

type Sample = {
  key: string;
  label: string;
  tier: "A · content-class" | "B · markers" | "C · secrets / PII" | "clean";
  filename: string;
  text?: string;
  bytes?: number[];
};

const SAMPLES: Sample[] = [
  { key: "verilog", label: "Verilog / SystemVerilog RTL", tier: "A · content-class", filename: "m.sv",
    text: "`timescale 1ns/1ps\nmodule m(input clk, input d, output reg q);\n always_ff @(posedge clk) q<=d;\nendmodule" },
  { key: "vhdl", label: "VHDL source", tier: "A · content-class", filename: "m.vhd",
    text: "entity alu is port(a: in std_logic_vector(7 downto 0));\narchitecture rtl of alu is\nbegin\n process(a) begin end process;\nend rtl;" },
  { key: "spice", label: "SPICE netlist", tier: "A · content-class", filename: "n.sp",
    text: ".subckt opamp inp inn out\n.model nmos1 nmos level=54\n.ends\n.tran 1n 200n" },
  { key: "sdc", label: "SDC timing constraints", tier: "A · content-class", filename: "c.sdc",
    text: "create_clock -name clk -period 2.0 [get_ports clk]\nset_input_delay 0.4 -clock clk [all_inputs]" },
  { key: "gds", label: "GDSII tapeout stream (binary magic)", tier: "A · content-class", filename: "chip.gds",
    bytes: [0x00, 0x06, 0x00, 0x02, 0x00, 0x05, 0x42, 0x47, 0x4e, 0x4c, 0x49, 0x42] },
  { key: "classification", label: "Confidential / Trade-secret marker", tier: "B · markers", filename: "spec.md",
    text: "NORTHWIND SEMICONDUCTOR — COMPANY CONFIDENTIAL — TRADE SECRET — NOT FOR EXTERNAL USE" },
  { key: "export", label: "Export-control (ITAR/EAR/ECCN)", tier: "B · markers", filename: "notice.txt",
    text: "Classification: EXPORT-CONTROLLED. ECCN 3A001. Subject to the Export Administration Regulations." },
  { key: "foundry", label: "Foundry / PDK identifier", tier: "B · markers", filename: "pdk.txt",
    text: "Built on the TSMC N3 PDK (3nm process) — process design kit under NDA." },
  { key: "aws", label: "AWS key + private key", tier: "C · secrets / PII", filename: "flow.tcl",
    text: 'set k "AKIAIOSFODNN7EXAMPLE"\n-----BEGIN RSA PRIVATE KEY-----\nMIIEfake-not-real\n-----END RSA PRIVATE KEY-----' },
  { key: "token", label: "API token / bearer secret", tier: "C · secrets / PII", filename: "env",
    text: "GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123456789" },
  { key: "ieee1735", label: "IEEE-1735 encrypted IP", tier: "C · secrets / PII", filename: "ip.v",
    text: "`pragma protect begin_protected\n`pragma protect data_method=\"aes128-cbc\"" },
  { key: "ssn", label: "US SSN (PII)", tier: "C · secrets / PII", filename: "hr.txt",
    text: "Employee SSN: 123-45-6789" },
  { key: "clean", label: "Ordinary app code", tier: "clean", filename: "cart.ts",
    text: "export const subtotal = (xs: number[]) => xs.reduce((a, b) => a + b, 0);" },
];

type Cell = { loading?: boolean; r?: ScanResponse; err?: string };

export function DetectionGallery() {
  const [cells, setCells] = useState<Record<string, Cell>>({});

  async function scan(s: Sample) {
    setCells((c) => ({ ...c, [s.key]: { loading: true } }));
    try {
      const token = sessionStorage.getItem("openscope_token") ?? "";
      const data: BlobPart = s.bytes ? new Uint8Array(s.bytes) : (s.text ?? "");
      const file = new File([data], s.filename);
      const r = await routerApi.scan(token, file);
      setCells((c) => ({ ...c, [s.key]: { r } }));
    } catch (e) {
      setCells((c) => ({ ...c, [s.key]: { err: e instanceof ApiError ? `${e.code}: ${e.message}` : String(e) } }));
    }
  }

  function scanAll() {
    SAMPLES.forEach((s, i) => setTimeout(() => void scan(s), i * 120));
  }

  return (
    <section className="bg-white border border-slate-200 rounded-lg p-5">
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div className="max-w-2xl">
          <h2 className="text-lg font-semibold text-slate-900">Detection coverage — the content engine</h2>
          <p className="text-sm text-slate-600 mt-1">
            The console above blocks by <span className="font-medium">channel</span> (deny-by-default by repo).
            This is the <span className="font-medium">content</span> backstop — it catches IP, markers, and
            secrets by what the payload <em>is</em>, so it fires even from an allowed repo or a renamed file.
            Each chip runs the live DLP scan (no model call).
          </p>
        </div>
        <button onClick={scanAll} className="btn-accent text-sm font-medium px-4 py-2 rounded">
          Scan all ▶
        </button>
      </div>

      <div className="mt-4 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
        {SAMPLES.map((s) => {
          const cell = cells[s.key];
          return (
            <button
              key={s.key}
              onClick={() => void scan(s)}
              className="text-left border border-slate-200 rounded-lg p-3 hover:border-slate-400 transition"
            >
              <div className="flex items-center justify-between gap-2">
                <span className="text-sm font-medium text-slate-900">{s.label}</span>
                <Verdict cell={cell} />
              </div>
              <div className="text-[10px] uppercase tracking-wide text-slate-400 mt-0.5">{s.tier}</div>
              {cell?.r?.findings && cell.r.findings.length > 0 && (
                <div className="flex flex-wrap gap-1 mt-2">
                  {cell.r.findings.map((f) => (
                    <code key={f.rule_id} className="text-[10px] bg-red-100 text-red-800 px-1.5 py-0.5 rounded font-mono">{f.rule_id}</code>
                  ))}
                </div>
              )}
              {cell?.err && <div className="text-[11px] text-red-700 mt-1">{cell.err}</div>}
            </button>
          );
        })}
      </div>
    </section>
  );
}

function Verdict({ cell }: { cell?: Cell }) {
  if (!cell) return <span className="text-[11px] text-slate-400">scan →</span>;
  if (cell.loading) return <span className="text-[11px] text-slate-400">…</span>;
  if (cell.err) return <span className="text-[11px] text-red-700">error</span>;
  if (!cell.r) return null;
  const deny = cell.r.decision === "deny";
  return (
    <span className={`text-[11px] font-semibold px-1.5 py-0.5 rounded ${deny ? "bg-red-100 text-red-800" : "bg-green-100 text-green-800"}`}>
      {deny ? "⛔ DENY" : "✅ ALLOW"}
    </span>
  );
}

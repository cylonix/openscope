"use client";

import { useEffect, useState } from "react";
import { consoleApi, PromptRow, ReceiptRow } from "@/lib/api";
import { SecurityFeed } from "@/components/security-feed";
import { ModelBreakdown } from "@/components/model-breakdown";
import { ConsoleShell, type ConsoleSection } from "@/components/console-shell";

export default function ITDashboard() {
  const [prompts, setPrompts] = useState<PromptRow[]>([]);
  const [receipts, setReceipts] = useState<ReceiptRow[]>([]);
  const [err, setErr] = useState<string | null>(null);

  async function reload() {
    setErr(null);
    try {
      const [p, r] = await Promise.all([
        consoleApi.prompts(10),
        consoleApi.receipts(5),
      ]);
      setPrompts(p.prompts ?? []);
      setReceipts(r.receipts ?? []);
    } catch (e) {
      setErr(String(e));
    }
  }
  useEffect(() => { void reload(); }, []);

  const sections: ConsoleSection[] = [
    { id: "feed", label: "Live feed", element: <SecurityFeed /> },
    { id: "models", label: "Models & spend", element: <ModelBreakdown scope="tenant" /> },
    {
      id: "prompts",
      label: "Prompts",
      element: (
        <Card title={`Prompt detail — tenant-only (${prompts.length})`}>
          {err && <div className="text-sm text-red-700 bg-red-50 border border-red-200 rounded p-2 mb-3">{err}</div>}
          <p className="text-xs text-slate-500 mb-2">Stored in <code className="bg-slate-100 px-1 rounded">sensitive.prompt_records</code> — accessible to your tenant_reader role only. OpenScope&apos;s vendor_reader role is denied at the schema GRANT level.</p>
          <p className="text-xs text-slate-500 mb-2">
            <span className="font-medium text-slate-700">Demo hygiene:</span> a coding agent&apos;s injected
            environment scaffolding (cwd, git status, file paths) is <span className="font-medium">trimmed from storage</span> —
            it&apos;s still DLP-scanned in full, just not retained — and these bodies <span className="font-medium">auto-clear after 60 min</span>.
            In a real tenant, retention is your policy.
          </p>
          <div className="space-y-2">
            {prompts.length === 0 && <p className="text-sm text-slate-500">No prompts yet.</p>}
            {prompts.map((p) => (
              <div key={p.request_id} className="border border-slate-200 rounded p-2 text-sm">
                <div className="flex items-center gap-2 mb-1">
                  <code className="text-xs text-slate-500">{p.ts.split(".")[0].replace(" ", "T")}</code>
                  {p.dlp_rule_ids?.length ? p.dlp_rule_ids.map((id) => <code key={id} className="text-xs bg-red-50 text-red-700 px-1 rounded">{id}</code>) : null}
                </div>
                <pre className="whitespace-pre-wrap text-slate-800 font-mono text-xs">{p.prompt_text}</pre>
              </div>
            ))}
          </div>
        </Card>
      ),
    },
    {
      id: "receipts",
      label: "Receipts",
      element: (
        <Card title={`Signed receipts (${receipts.length})`}>
          <p className="text-xs text-slate-500 mb-2">Ed25519 signatures over canonical JSON of metadata (no body content). Reconcile against AWS billing without sharing prompts.</p>
          <div className="space-y-2">
            {receipts.length === 0 && <p className="text-sm text-slate-500">No receipts yet.</p>}
            {receipts.map((r) => (
              <details key={r.request_id} className="border border-slate-200 rounded p-2 text-sm">
                <summary className="cursor-pointer flex items-center gap-2">
                  <code className="text-xs text-slate-500">{r.ts.split(".")[0].replace(" ", "T")}</code>
                  <code className="text-xs">{r.public_key_id}</code>
                  <code className="text-xs text-slate-500 truncate">{r.signature.substring(0, 32)}…</code>
                </summary>
                <pre className="mt-2 bg-slate-50 p-2 rounded text-[11px] whitespace-pre-wrap">{JSON.stringify(JSON.parse(r.payload), null, 2)}</pre>
              </details>
            ))}
          </div>
        </Card>
      ),
    },
  ];

  return <ConsoleShell sections={sections} />;
}

function Card({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="bg-white border border-slate-200 rounded-lg p-5">
      <h2 className="text-lg font-semibold text-slate-900 mb-3">{title}</h2>
      {children}
    </section>
  );
}

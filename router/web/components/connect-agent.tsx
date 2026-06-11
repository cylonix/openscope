"use client";

// ConnectAgent — the "bring your own coding agent" panel. Surfaces the live
// endpoint URLs, the signed-in developer's token (the API key agents need),
// and copy-paste config for Claude Code / opencode / Cursor / Codex CLI. This
// is the engineer conversion path: point your real tool at OpenScope and watch
// the same governance apply. Claude Code leads (native Anthropic API, cleanest
// setup); the OpenAI-compatible tools follow.

import { useEffect, useState, type ReactNode } from "react";

type AgentTab = "claude" | "opencode" | "cursor" | "codex";

// The demo's default model. Unknown model names sent by an agent are remapped
// to this, so a copy-paste example that just uses it always works regardless
// of which models the admin has enabled. Mirrors OPENSCOPE_DEFAULT_MODEL_ID.
const DEFAULT_MODEL = "us.amazon.nova-micro-v1:0";

export function ConnectAgent() {
  const [origin, setOrigin] = useState("https://demo.openscopeai.com");
  const [token, setToken] = useState("");
  const [reveal, setReveal] = useState(false);
  const [tab, setTab] = useState<AgentTab>("claude");

  useEffect(() => {
    setOrigin(window.location.origin);
    setToken(sessionStorage.getItem("openscope_token") ?? "");
  }, []);

  const openaiBase = `${origin}/api/router/v1`;
  const anthropicBase = `${origin}/api/router`;
  const key = token || "osk_developer_…";
  const keyShown = reveal || !token ? key : maskKey(key);

  const snippets: Record<AgentTab, { label: string; intro: ReactNode; code: string }> = {
    claude: {
      label: "Claude Code",
      intro: <><span className="font-medium text-slate-800">Recommended.</span> Claude Code speaks the Anthropic API natively — just point <code>ANTHROPIC_BASE_URL</code> at OpenScope and pass your token. No model name to set; the demo serves the default model.</>,
      code: `export ANTHROPIC_BASE_URL=${anthropicBase}
export ANTHROPIC_AUTH_TOKEN=${key}
claude`,
    },
    opencode: {
      label: "opencode",
      intro: <>Add a custom OpenAI-compatible provider in <code>opencode.json</code> (project root, or <code>~/.config/opencode/</code>):</>,
      code: `// opencode.json
{
  "$schema": "https://opencode.ai/config.json",
  "provider": {
    "openscope": {
      "npm": "@ai-sdk/openai-compatible",
      "name": "OpenScope (governed)",
      "options": {
        "baseURL": "${openaiBase}",
        "apiKey": "${key}"
      },
      "models": {
        "${DEFAULT_MODEL}": { "name": "OpenScope demo" }
      }
    }
  }
}

# then run opencode and pick "OpenScope" via /models`,
    },
    cursor: {
      label: "Cursor",
      intro: <>Settings → <b>Models</b> → enable “Override OpenAI Base URL”, then add a custom model. Cursor needs <em>a</em> model name, but any string works — unknown names are remapped to the demo default, so just use it:</>,
      code: `Base URL:  ${openaiBase}\nAPI Key:   ${key}\nModel:     ${DEFAULT_MODEL}   (the demo default — any name maps here)`,
    },
    codex: {
      label: "Codex CLI",
      intro: <>Add a custom provider in <code>~/.codex/config.toml</code> (the <b>CLI</b> only — the Codex app can&apos;t be repointed):</>,
      code: `# ~/.codex/config.toml
model          = "${DEFAULT_MODEL}"
model_provider = "openscope"

[model_providers.openscope]
name     = "OpenScope (governed)"
base_url = "${openaiBase}"
env_key  = "OPENSCOPE_KEY"
wire_api = "chat"

# then:
export OPENSCOPE_KEY=${key}
codex`,
    },
  };

  const active = snippets[tab];

  return (
    <section className="bg-white border border-slate-200 rounded-lg p-5">
      <h2 className="text-lg font-semibold text-slate-900">Connect your own coding agent</h2>
      <p className="text-sm text-slate-600 mt-1 max-w-2xl">
        Point Claude&nbsp;Code, opencode, Cursor, or Codex&nbsp;CLI at OpenScope — your real tool, the
        same governance. Work in the allowed sample repo flows; pull in restricted IP and it&apos;s
        blocked at the perimeter, with the block surfaced right in your agent.
      </p>

      {/* Endpoints + key */}
      <div className="mt-4 grid grid-cols-1 md:grid-cols-3 gap-3">
        <Field label="Anthropic base URL" value={anthropicBase} hint="Claude Code" />
        <Field label="OpenAI base URL" value={openaiBase} hint="opencode · Cursor · Codex CLI · Cline · Aider" />
        <Field
          label="API key (your developer token)"
          value={keyShown}
          copyValue={key}
          hint={token ? undefined : "log in with a developer code to populate this"}
          trailing={
            token ? (
              <button onClick={() => setReveal((r) => !r)} className="text-xs text-blue-600 hover:underline">
                {reveal ? "hide" : "reveal"}
              </button>
            ) : undefined
          }
        />
      </div>

      {/* Per-agent config */}
      <div className="mt-5">
        <div className="flex gap-1 border-b border-slate-200">
          {(Object.keys(snippets) as AgentTab[]).map((k) => (
            <button
              key={k}
              onClick={() => setTab(k)}
              className={`text-sm px-3 py-1.5 -mb-px border-b-2 ${
                tab === k ? "border-blue-600 text-slate-900 font-medium" : "border-transparent text-slate-500 hover:text-slate-800"
              }`}
            >
              {snippets[k].label}
            </button>
          ))}
        </div>
        <p className="text-sm text-slate-600 mt-3">{active.intro}</p>
        <CodeBlock code={active.code} />
      </div>

      {/* Villain note — sanctioned vs shadow traffic, honestly scoped */}
      <div className="mt-4 text-xs text-slate-600 bg-slate-50 border border-slate-200 rounded-lg p-3">
        <span className="font-medium text-slate-800">Sanctioned vs. shadow traffic.</span>{" "}
        The Codex <b>CLI</b> can be repointed at OpenScope (above), so it&apos;s governed. The Codex{" "}
        <b>app</b>/cloud (ChatGPT login) and GitHub Copilot are wired to their own backends and
        can&apos;t flow through OpenScope. The enterprise pattern for those is{" "}
        <span className="font-medium text-slate-800">block-and-funnel</span>: block direct egress to
        AI endpoints at your corporate network/SWG and funnel all AI traffic to the sanctioned
        OpenScope path — the network does the forcing, OpenScope does the inspecting.
      </div>

      <p className="mt-3 text-xs text-slate-500">
        Try it against the two sample repos (<code>samples/northwind-rtl</code> blocks,{" "}
        <code>samples/northwind-webapp</code> flows). Full guide:{" "}
        <code>docs/bring-your-own-agent.md</code>.
      </p>
    </section>
  );
}

function Field({
  label,
  value,
  copyValue,
  hint,
  trailing,
}: {
  label: string;
  value: string;
  copyValue?: string;
  hint?: string;
  trailing?: React.ReactNode;
}) {
  return (
    <div className="border border-slate-200 rounded-lg p-3 bg-slate-50">
      <div className="flex items-center justify-between gap-2">
        <div className="text-[11px] uppercase tracking-wide text-slate-500">{label}</div>
        <div className="flex items-center gap-2">
          {trailing}
          <CopyButton text={copyValue ?? value} />
        </div>
      </div>
      <div className="mt-1 font-mono text-xs text-slate-900 break-all">{value}</div>
      {hint && <div className="mt-1 text-[11px] text-slate-500">{hint}</div>}
    </div>
  );
}

function CodeBlock({ code }: { code: string }) {
  return (
    <div className="relative mt-2">
      <div className="absolute right-2 top-2">
        <CopyButton text={code} dark />
      </div>
      <pre className="console-surface rounded-lg p-3 text-xs overflow-x-auto whitespace-pre">{code}</pre>
    </div>
  );
}

function CopyButton({ text, dark }: { text: string; dark?: boolean }) {
  const [copied, setCopied] = useState(false);
  async function copy() {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 1200);
    } catch {
      /* clipboard blocked — no-op */
    }
  }
  return (
    <button
      onClick={copy}
      className={`text-[11px] px-1.5 py-0.5 rounded border ${
        dark
          ? "border-slate-600 text-slate-200 hover:bg-slate-700"
          : "border-slate-300 text-slate-600 hover:bg-slate-100"
      }`}
      style={dark ? { background: "rgba(255,255,255,0.06)" } : undefined}
    >
      {copied ? "copied ✓" : "copy"}
    </button>
  );
}

function maskKey(k: string): string {
  if (k.length <= 14) return k;
  return k.slice(0, 14) + "…" + "•".repeat(6);
}

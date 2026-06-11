"use client";

// TopologyDiagram — "how it works, and where it can't reach." Renders the
// corrected deployment topology: TLS terminates at the router (content
// inspection in plaintext — a reverse proxy, NOT a MITM), a separate
// network-egress layer controls destinations with no decryption, everything
// runs inside the customer's own VPC, and logs go to the customer's SIEM.
// The shadow row shows the agents that can't be repointed and the
// block-and-funnel pattern that handles them.

export function TopologyDiagram() {
  return (
    <section className="bg-white border border-slate-200 rounded-lg p-5">
      <h2 className="text-lg font-semibold text-slate-900">How it works — and where it can&apos;t reach</h2>
      <p className="text-sm text-slate-600 mt-1 max-w-2xl">
        Content inspection happens <span className="font-medium">at the router</span> (the client&apos;s
        TLS terminates there — a reverse proxy, not a man-in-the-middle). Destination control is a{" "}
        <span className="font-medium">separate network layer with no decryption</span>. Both run inside
        a VPC you own; nothing transits a third party to be scanned.
      </p>

      {/* Sanctioned path */}
      <div className="mt-4 flex flex-col lg:flex-row items-stretch gap-2 text-xs">
        <Box tone="agent" title="Sanctioned agents" sub="Cursor · Codex CLI · Claude Code" />
        <Arrow label="TLS" />
        <div className="flex-1 border-2 border-teal-400 rounded-lg p-2 bg-slate-50">
          <div className="text-[10px] uppercase tracking-wide text-slate-500 mb-2">Your AWS VPC — you own this</div>
          <div className="flex flex-col sm:flex-row items-stretch gap-2">
            <Box tone="core" title="OpenScope router" sub="TLS terminates · inspect / redact / block plaintext" />
            <Arrow />
            <Box tone="net" title="Egress allowlist" sub="network layer · no decryption · destinations only" />
          </div>
          <div className="mt-2 text-[11px] text-slate-500">↳ every allow/block decision → <span className="font-medium text-slate-700">your SIEM</span></div>
        </div>
        <Arrow label="TLS" />
        <Box tone="provider" title="Approved providers" sub="Bedrock · Azure OpenAI · Anthropic" />
      </div>

      {/* Shadow path — three columns: who · the block (middle) · the remedy.
          The shadow box gets a fixed width so it isn't squeezed to a sliver by
          the longer remedy text. */}
      <div className="mt-3 flex flex-col sm:flex-row items-center gap-3 text-xs">
        <div className="w-full sm:w-60 sm:shrink-0 border border-red-300 bg-red-50 rounded-lg p-2">
          <div className="font-medium text-slate-900">Shadow agents</div>
          <div className="text-[11px] text-slate-500 mt-0.5">Codex app/cloud · Copilot — can&apos;t be repointed</div>
        </div>
        <div className="text-red-600 font-mono whitespace-nowrap sm:shrink-0">✗ blocked at corporate egress →</div>
        <div className="text-slate-600 flex-1">
          <span className="font-medium text-slate-800">block-and-funnel:</span> deny direct egress to AI
          endpoints at your network/SWG, force all AI traffic to the sanctioned OpenScope path.
        </div>
      </div>

      <p className="mt-3 text-[11px] text-slate-500">
        Layered identity, not just paths: a restricted repo is deny-by-default, content-class catches
        the same IP if it&apos;s moved or relabeled, and fingerprinting (roadmap) catches the exact
        registered file anywhere. It composes with your own file-access controls — it raises the bar and
        makes the sanctioned path auditable; it isn&apos;t a substitute for read-only / no-copy-out.
      </p>

      {/* Full OpenScope topology — desktop only (the diagram is wide). The demo
          governs what agents SEE (the AI Router perimeter above); the full
          platform also governs what agents DO via the Executor / Action Broker,
          with human approval and an out-of-band kill switch. */}
      <div className="hidden md:block mt-6 pt-5 border-t border-slate-200">
        <h3 className="text-sm font-semibold text-slate-900">The full OpenScope picture</h3>
        <p className="text-xs text-slate-600 mt-1 max-w-2xl">
          This demo is the <span className="font-medium">AI&nbsp;Router</span> perimeter — what agents{" "}
          <span className="font-medium">see</span>. The full platform pairs it with the{" "}
          <span className="font-medium">Executor / Action&nbsp;Broker</span> — governing what agents{" "}
          <span className="font-medium">do</span> on privileged resources, with human approval and an
          out-of-band kill switch.
        </p>
        <div className="mt-3 rounded-lg border border-slate-200 overflow-hidden bg-white">
          {/* eslint-disable-next-line @next/next/no-img-element */}
          <img
            src="/diagrams/openscope-full-topology.svg"
            alt="Full OpenScope topology — AI Router (what agents see) and Executor / Action Broker (what agents do), inside the customer's VPC, with human approval and an out-of-band kill switch"
            className="w-full h-auto"
          />
        </div>
      </div>
    </section>
  );
}

function Box({ tone, title, sub }: { tone: "agent" | "core" | "net" | "provider" | "shadow"; title: string; sub: string }) {
  const styles: Record<string, string> = {
    agent: "border-slate-300 bg-white",
    core: "border-teal-400 bg-white",
    net: "border-slate-300 bg-white",
    provider: "border-slate-300 bg-white",
    shadow: "border-red-300 bg-red-50",
  };
  return (
    <div className={`flex-1 border rounded-lg p-2 ${styles[tone]}`}>
      <div className="font-medium text-slate-900">{title}</div>
      <div className="text-[11px] text-slate-500 mt-0.5">{sub}</div>
    </div>
  );
}

function Arrow({ label }: { label?: string }) {
  return (
    <div className="flex flex-col items-center justify-center text-slate-400 px-1">
      <span className="font-mono">→</span>
      {label && <span className="text-[9px]">{label}</span>}
    </div>
  );
}

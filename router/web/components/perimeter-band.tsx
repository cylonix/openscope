"use client";

// Two pieces of shared chrome:
//   RoleStrip       — a slim band under the header. Its chips switch the
//                     session to that role (same tenant) and load its
//                     dashboard, so a presenter flips Developer / Security /
//                     Ops in one click.
//   PositioningHero — a hero card at the TOP of the page content (not a full-
//                     width band) carrying the spine: in-VPC, customer-owned,
//                     auditable, unreadable-by-OpenScope.

import { useState } from "react";
import { consoleApi, Role, isAuthError, redirectToLogin } from "@/lib/api";

const ROLES: { key: Role; label: string; caption: string; path: string }[] = [
  { key: "developer", label: "Developer", caption: "Uses coding agents. Sees its own governed calls + receipts.", path: "/dashboard/developer" },
  { key: "it", label: "Security / IT", caption: "Audits every prompt + alert in real time. Verifies OpenScope is blind to content.", path: "/dashboard/it" },
  { key: "engineer", label: "OpenScope Ops", caption: "Cross-tenant metering only. No prompt access — by IAM + DB GRANT.", path: "/dashboard/ops" },
];

export function RoleStrip({ role }: { role: Role }) {
  const current: Role = role === "admin" ? "it" : role;
  const [busy, setBusy] = useState<Role | null>(null);

  async function go(target: Role, path: string) {
    if (target === current || busy) return;
    setBusy(target);
    try {
      await consoleApi.switchRole(target);
      window.location.assign(path); // full reload so the layout re-fetches me()
    } catch (e) {
      // Session expired while the page sat idle — the click would otherwise do
      // nothing (dead button). Bounce to login so the user can re-enter.
      if (isAuthError(e)) { redirectToLogin(); return; }
      setBusy(null);
    }
  }

  // Pill tabs with a leading hint — sits inside the header, no band of its own
  // (reads as a tab control, not a banner). One line: centered on desktop (the
  // header wrapper centers it), horizontally scrollable on mobile.
  return (
    <div className="flex items-center gap-1.5 w-max" role="tablist" aria-label="Switch role view">
      <span className="text-[11px] uppercase tracking-wide text-slate-400 mr-1 shrink-0">View as</span>
      {ROLES.map((r) => {
        const active = r.key === current;
        return (
          <button
            key={r.key}
            role="tab"
            aria-selected={active}
            onClick={() => go(r.key, r.path)}
            disabled={busy !== null}
            title={r.caption}
            className={`text-sm px-3 py-1.5 rounded-full whitespace-nowrap shrink-0 transition ${
              active ? "chip-active font-medium" : "text-slate-500 hover:text-slate-900 hover:bg-slate-100"
            } ${busy === r.key ? "opacity-60" : ""}`}
          >
            {busy === r.key ? "switching…" : r.label}
          </button>
        );
      })}
    </div>
  );
}

export function PositioningHero() {
  return (
    <section
      className="rounded-xl border p-5 mb-6"
      style={{ background: "var(--teal-soft)", borderColor: "var(--line)" }}
    >
      <div className="flex items-start gap-3">
        <span className="text-2xl leading-none">🛡️</span>
        <div>
          <h2 className="text-base sm:text-lg font-semibold" style={{ color: "var(--text-strong)" }}>
            Customer-owned, in-VPC trust perimeter for AI coding agents
          </h2>
          <p className="text-sm mt-1" style={{ color: "var(--text)" }}>
            DLP at the edge · every call receipted ·{" "}
            <span className="font-medium" style={{ color: "var(--text-strong)" }}>
              prompt &amp; code unreadable by OpenScope
            </span>{" "}
            — a property you can verify with your own tooling, not one you take on faith. Nothing
            transits a third party to be scanned.
          </p>
          <a
            href="https://openscopeai.com"
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1 text-sm font-medium mt-2 hover:underline"
            style={{ color: "var(--teal)" }}
          >
            Learn more at openscopeai.com ↗
          </a>
        </div>
      </div>
    </section>
  );
}

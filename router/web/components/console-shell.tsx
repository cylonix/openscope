"use client";

// ConsoleShell — the console layout for a role dashboard. A full-height left
// sidebar (at the page edge, like a normal admin console) lists the role's
// sections; the content column shows either ONE section (focused, the default)
// or ALL of them stacked when the "Show all sections" switch is on.
//
//   - Focused (default): sidebar item selects the section. Reads like a product
//     console — one thing at a time, fast to navigate.
//   - Show all (opt-in, remembered): every section renders in a scroll; the
//     sidebar becomes jump-nav and highlights the section currently in view.
//
// Each role page passes its existing components wrapped as `sections` — the
// sections themselves are unchanged. The positioning hero sits at the top of
// the content column so the pitch is anchored in both modes.

import { ReactNode, useEffect, useState } from "react";
import { PositioningHero } from "@/components/perimeter-band";

export type ConsoleSection = { id: string; label: string; element: ReactNode };

const SHOW_ALL_KEY = "openscope-show-all";

export function ConsoleShell({ sections }: { sections: ConsoleSection[] }) {
  const [activeId, setActiveId] = useState(sections[0]?.id ?? "");
  const [showAll, setShowAll] = useState(false); // default OFF — focused console

  // Restore the user's show-all preference (default off if never set).
  useEffect(() => {
    try {
      if (localStorage.getItem(SHOW_ALL_KEY) === "1") setShowAll(true);
    } catch {}
  }, []);

  function toggleShowAll(next: boolean) {
    setShowAll(next);
    try { localStorage.setItem(SHOW_ALL_KEY, next ? "1" : "0"); } catch {}
  }

  // Scroll-spy: in show-all mode, highlight whichever section is in view.
  useEffect(() => {
    if (!showAll) return;
    const els = sections
      .map((s) => document.getElementById("sec-" + s.id))
      .filter((e): e is HTMLElement => e !== null);
    if (!els.length) return;
    const obs = new IntersectionObserver(
      (entries) => {
        const visible = entries
          .filter((e) => e.isIntersecting)
          .sort((a, b) => a.boundingClientRect.top - b.boundingClientRect.top);
        if (visible[0]) setActiveId(visible[0].target.id.replace(/^sec-/, ""));
      },
      { rootMargin: "-15% 0px -75% 0px", threshold: 0 }
    );
    els.forEach((el) => obs.observe(el));
    return () => obs.disconnect();
  }, [showAll, sections]);

  function goTo(id: string) {
    setActiveId(id);
    if (showAll) {
      document.getElementById("sec-" + id)?.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  }

  const active = sections.find((s) => s.id === activeId) ?? sections[0];

  return (
    <div className="md:flex" style={{ minHeight: "calc(100vh - 53px)" }}>
      {/* Full-height left sidebar — at the page edge, console-style. */}
      <aside
        className="hidden md:block md:w-60 md:shrink-0 border-r border-slate-200"
        style={{ background: "var(--panel)" }}
      >
        <div className="sticky top-0 p-4">
          <SectionRail sections={sections} activeId={active?.id ?? ""} onGo={goTo} showAll={showAll} onToggle={toggleShowAll} />
        </div>
      </aside>

      {/* Content column */}
      <div className="min-w-0 flex-1">
        <div className="max-w-5xl mx-auto px-4 sm:px-6 py-6 sm:py-8">
          {/* Mobile section nav: label + switch on one line, scrollable chips below */}
          <div className="md:hidden mb-4">
            <div className="flex items-center justify-between gap-2 mb-2">
              <div className="text-[10px] uppercase tracking-wide text-slate-400">Sections</div>
              <ShowAllToggle showAll={showAll} onToggle={toggleShowAll} />
            </div>
            <div className="flex gap-1.5 overflow-x-auto pb-1 -mx-4 px-4">
              {sections.map((s) => {
                const on = s.id === active?.id;
                return (
                  <button
                    key={s.id}
                    onClick={() => goTo(s.id)}
                    className={`text-xs whitespace-nowrap shrink-0 px-3 py-1.5 rounded-full border ${
                      on ? "chip-active" : "bg-white text-slate-600 border-slate-200"
                    }`}
                  >
                    {s.label}
                  </button>
                );
              })}
            </div>
          </div>

          <PositioningHero />

          <div className="mt-6">
            {showAll ? (
              sections.map((s) => (
                <section key={s.id} id={"sec-" + s.id} className="scroll-mt-4 mb-8">
                  {s.element}
                </section>
              ))
            ) : (
              <section id={"sec-" + active?.id}>{active?.element}</section>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

function SectionRail({
  sections,
  activeId,
  onGo,
  showAll,
  onToggle,
}: {
  sections: ConsoleSection[];
  activeId: string;
  onGo: (id: string) => void;
  showAll: boolean;
  onToggle: (v: boolean) => void;
}) {
  return (
    <nav>
      <div className="text-[10px] uppercase tracking-wide text-slate-400 mb-2 px-1">Sections</div>
      <ul className="space-y-0.5">
        {sections.map((s) => {
          const active = s.id === activeId;
          return (
            <li key={s.id}>
              <button
                onClick={() => onGo(s.id)}
                className={`w-full text-left text-sm px-3 py-2 rounded-md border-l-2 transition ${
                  active ? "text-slate-900 font-medium" : "border-transparent text-slate-600 hover:text-slate-900 hover:bg-slate-50"
                }`}
                style={active ? { borderLeftColor: "var(--teal)", background: "var(--teal-soft)" } : { borderLeftColor: "transparent" }}
              >
                {s.label}
              </button>
            </li>
          );
        })}
      </ul>
      <div className="mt-3 pt-3 border-t border-slate-200 px-1">
        <ShowAllToggle showAll={showAll} onToggle={onToggle} />
      </div>
    </nav>
  );
}

function ShowAllToggle({ showAll, onToggle }: { showAll: boolean; onToggle: (v: boolean) => void }) {
  return (
    <button
      role="switch"
      aria-checked={showAll}
      onClick={() => onToggle(!showAll)}
      className="flex items-center gap-2 text-xs text-slate-600 hover:text-slate-900"
      title="Show every section on one scrolling page"
    >
      <span
        className="relative inline-block w-8 h-4 rounded-full transition-colors shrink-0"
        style={{ background: showAll ? "var(--teal)" : "var(--panel-strong)", border: "1px solid var(--line)" }}
      >
        <span
          className="absolute top-0.5 w-3 h-3 rounded-full bg-white transition-all"
          style={{ left: showAll ? "16px" : "2px" }}
        />
      </span>
      <span className="whitespace-nowrap">Show all sections</span>
    </button>
  );
}

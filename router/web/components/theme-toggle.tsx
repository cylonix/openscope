"use client";

import { useEffect, useState } from "react";

type ThemePref = "system" | "light" | "dark";

const STORAGE_KEY = "openscope-theme";

function resolveTheme(theme: ThemePref): "light" | "dark" {
  if (theme === "system") {
    return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  }
  return theme;
}

// Brightness picker — same UX as the marketing site's ThemeToggle.
// Three states: System / Light / Dark. Writes to localStorage so the
// pre-hydration ThemeScript can read it on next load.
export function ThemeToggle() {
  const [theme, setTheme] = useState<ThemePref>("system");

  useEffect(() => {
    const root = document.documentElement;
    const initial = (root.dataset.themePreference as ThemePref | undefined) ?? "system";
    setTheme(initial);

    const media = window.matchMedia("(prefers-color-scheme: dark)");
    const updateSystem = () => {
      const pref = (document.documentElement.dataset.themePreference as ThemePref | undefined) ?? "system";
      if (pref === "system") {
        document.documentElement.dataset.theme = resolveTheme("system");
      }
    };
    media.addEventListener("change", updateSystem);
    return () => media.removeEventListener("change", updateSystem);
  }, []);

  function update(next: ThemePref) {
    const root = document.documentElement;
    root.dataset.themePreference = next;
    root.dataset.theme = resolveTheme(next);
    try { localStorage.setItem(STORAGE_KEY, next); } catch {}
    setTheme(next);
  }

  return (
    <label
      style={{
        alignItems: "center",
        background: "var(--panel-strong)",
        border: "1px solid var(--line)",
        borderRadius: 6,
        display: "inline-flex",
        gap: 8,
        padding: "4px 10px",
      }}
    >
      <span
        className="hidden sm:inline"
        style={{
          color: "var(--muted)",
          fontSize: "0.65rem",
          fontWeight: 700,
          letterSpacing: "0.14em",
          lineHeight: 1,
          textTransform: "uppercase",
        }}
      >
        Brightness
      </span>
      <select
        aria-label="Brightness setting"
        onChange={(event) => update(event.target.value as ThemePref)}
        style={{
          background: "transparent",
          border: "none",
          color: "var(--text)",
          fontSize: "0.78rem",
          fontWeight: 600,
          lineHeight: 1,
          margin: 0,
          outline: "none",
          padding: 0,
          paddingRight: 4,
        }}
        value={theme}
      >
        <option value="system">System</option>
        <option value="light">Light</option>
        <option value="dark">Dark</option>
      </select>
    </label>
  );
}

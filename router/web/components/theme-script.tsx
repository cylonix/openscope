// Inline script run before hydration to set `data-theme` and
// `data-theme-preference` on <html> from localStorage (or system). Mirrors
// the openscopeai.com marketing site so the demo flips on the same toggle.

export function ThemeScript() {
  const script = `
    (function() {
      var storageKey = 'openscope-theme';
      var root = document.documentElement;
      var stored = null;
      try { stored = localStorage.getItem(storageKey); } catch (e) {}
      var systemDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
      var theme = stored === 'light' || stored === 'dark' || stored === 'system' ? stored : 'system';
      var resolved = theme === 'system' ? (systemDark ? 'dark' : 'light') : theme;
      root.dataset.themePreference = theme;
      root.dataset.theme = resolved;
    })();
  `;
  return <script dangerouslySetInnerHTML={{ __html: script }} />;
}

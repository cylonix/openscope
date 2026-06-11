"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { consoleApi, Role } from "@/lib/api";
import { ThemeToggle } from "@/components/theme-toggle";
import { RoleStrip } from "@/components/perimeter-band";

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const [me, setMe] = useState<{ tenant_id: string; role: Role } | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let mounted = true;
    consoleApi.me().then(
      (m) => { if (mounted) setMe(m); },
      (err) => {
        if (mounted) {
          setError(String(err));
          router.replace("/?expired=1");
        }
      }
    );
    return () => { mounted = false; };
  }, [router]);

  // Keepalive: while this tab is open, ping /me every few minutes. The console
  // renews the session cookie on each authenticated request (sliding window),
  // so an open dashboard never times out mid-demo. If the session has already
  // lapsed (laptop slept past the window), bounce cleanly to login instead of
  // leaving the role tabs silently dead until a manual refresh.
  useEffect(() => {
    const id = setInterval(() => {
      consoleApi.me().catch(() => {
        sessionStorage.removeItem("openscope_token");
        router.replace("/?expired=1");
      });
    }, 4 * 60 * 1000);
    return () => clearInterval(id);
  }, [router]);

  async function logout() {
    try { await consoleApi.logout(); } catch {}
    sessionStorage.removeItem("openscope_token");
    sessionStorage.removeItem("openscope_role");
    router.push("/");
  }

  if (error) {
    return <div className="p-8 text-red-600">Session expired. Redirecting…</div>;
  }
  if (!me) {
    return <div className="p-8 text-slate-500">Loading…</div>;
  }

  return (
    <div className="min-h-screen bg-slate-50">
      {/* Full-width top bar: logo · role tabs (centered) · controls. The role
          tabs live in the header so there's no separate banner band. */}
      <header className="bg-white border-b border-slate-200">
        <div className="px-4 sm:px-6 py-2.5">
          <div className="flex items-center justify-between gap-3">
            <Link href={dashFor(me.role)} className="whitespace-nowrap" title="OpenScope demo — back to your dashboard">
              <span className="font-semibold text-slate-900">OpenScope</span>{" "}
              <span className="font-normal text-slate-500">demo</span>
            </Link>
            <div className="hidden md:flex flex-1 justify-center">
              <RoleStrip role={me.role} />
            </div>
            <div className="flex items-center gap-2 sm:gap-4 shrink-0">
              <ThemeToggle />
              <button
                onClick={logout}
                className="text-sm text-slate-600 hover:text-slate-900 whitespace-nowrap"
              >
                Sign out
              </button>
            </div>
          </div>
          {/* Mobile: role tabs on their own row under the top bar — one line,
              horizontally scrollable (no awkward wrap). */}
          <div className="md:hidden mt-2 overflow-x-auto">
            <RoleStrip role={me.role} />
          </div>
        </div>
      </header>
      <main>{children}</main>
    </div>
  );
}

// dashFor maps a role to its dashboard path. The header brand links here (not
// "/") so clicking it while signed in returns to the dashboard instead of the
// login page.
function dashFor(role: Role): string {
  switch (role) {
    case "developer": return "/dashboard/developer";
    case "it":        return "/dashboard/it";
    case "engineer":  return "/dashboard/ops";
    default:          return "/dashboard/it";
  }
}

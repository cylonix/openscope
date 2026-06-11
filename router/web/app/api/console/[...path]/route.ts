// Proxy /api/console/<...> → openscope-console (default http://localhost:8081/<...>).
//
// We use a Route Handler instead of next.config rewrites because Next.js 16
// + Turbopack dev didn't honor the rewrites configuration reliably.
// Forwards body, headers (except hop-by-hop), and cookies in both directions.

import { NextRequest, NextResponse } from "next/server";

const CONSOLE_URL = process.env.OPENSCOPE_CONSOLE_URL || "http://localhost:8081";

async function proxy(req: NextRequest, ctx: { params: Promise<{ path: string[] }> }) {
  const { path } = await ctx.params;
  const subpath = path.join("/");
  const url = new URL(`/${subpath}`, CONSOLE_URL);
  url.search = req.nextUrl.search;

  const headers = new Headers(req.headers);
  headers.delete("host");
  headers.delete("content-length");
  // Preserve cookies — openscope-console reads openscope_session.

  const body = req.method === "GET" || req.method === "HEAD" ? null : await req.arrayBuffer();
  const upstream = await fetch(url, {
    method: req.method,
    headers,
    body,
    redirect: "manual",
  });

  // Forward Set-Cookie verbatim so the openscope_session cookie reaches the browser.
  const outHeaders = new Headers(upstream.headers);
  outHeaders.delete("transfer-encoding");
  outHeaders.delete("content-encoding");

  return new NextResponse(upstream.body, {
    status: upstream.status,
    headers: outHeaders,
  });
}

export const GET = proxy;
export const POST = proxy;
export const PUT = proxy;
export const DELETE = proxy;
export const PATCH = proxy;
export const HEAD = proxy;

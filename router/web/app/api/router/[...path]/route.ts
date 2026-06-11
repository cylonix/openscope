// Proxy /api/router/<...> → openscope-router (default http://localhost:8080/<...>).
// Used by the developer dashboard's Scenario A (/v1/scan) and B (/v1/chat).
// Forwards the Authorization: Bearer header so the router's tenancy
// resolver can identify the principal.

import { NextRequest, NextResponse } from "next/server";

const ROUTER_URL = process.env.OPENSCOPE_ROUTER_URL || "http://localhost:8080";

async function proxy(req: NextRequest, ctx: { params: Promise<{ path: string[] }> }) {
  const { path } = await ctx.params;
  const subpath = path.join("/");
  const url = new URL(`/${subpath}`, ROUTER_URL);
  url.search = req.nextUrl.search;

  const headers = new Headers(req.headers);
  headers.delete("host");
  headers.delete("content-length");

  const body = req.method === "GET" || req.method === "HEAD" ? null : await req.arrayBuffer();
  const upstream = await fetch(url, {
    method: req.method,
    headers,
    body,
    redirect: "manual",
  });

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

import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Required for the production Docker image (web/Dockerfile) — emits
  // a self-contained server.js + minimal node_modules in .next/standalone.
  // Proxying for /api/console + /api/router happens via Route Handlers
  // under app/api/{console,router}/[...path]/route.ts.
  output: "standalone",
};

export default nextConfig;

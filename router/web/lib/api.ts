// Thin typed fetch wrappers. All calls include credentials so the
// session cookie (HttpOnly, set by openscope-console) is sent.

export type Role = "developer" | "it" | "engineer" | "admin";

export type Session = {
  tenant_id: string;
  role: Role;
  exp: number;
};

export type RouterEvent = {
  ts: string;
  request_id: string;
  role: string;
  endpoint: string;
  model?: string;
  model_label?: string; // human label, e.g. "Claude Haiku 4.5"
  provider?: string;    // serving platform, e.g. "AWS Bedrock"
  region?: string;      // serving region, e.g. "us-west-2"
  decision: string;
  result: string;
  reason?: string;
  dlp_rule_ids?: string[];
  bytes_in: number;
  bytes_out: number;
};

export type UsageSummary = {
  calls: number;
  input_tokens: number;
  output_tokens: number;
  total_cost_usd: number;
  monthly_cap_usd: number;
};

export type PromptRow = {
  ts: string;
  request_id: string;
  prompt_text: string;
  dlp_rule_ids?: string[];
};

export type ReceiptRow = {
  ts: string;
  request_id: string;
  payload: string;
  signature: string;
  public_key_id: string;
};

// ModelInfo is one row of the per-model breakdown: catalog metadata (label,
// provider, tier, unit price per MTok) + admin enablement + this month's usage.
export type ModelInfo = {
  id: string;
  display_name: string;
  provider: string;
  region: string;
  tier: string;
  input_per_mtok: number;
  output_per_mtok: number;
  enabled: boolean;
  calls: number;
  input_tokens: number;
  output_tokens: number;
  total_cost_usd: number;
  tenants?: number; // cross-tenant (Ops) only
};

export type VendorUsageRow = {
  tenant_slug: string;
  day: string;
  requests: number;
  input_tokens: number;
  output_tokens: number;
  total_cost_usd: number;
};

async function jsonFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, {
    credentials: "include",
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...(init?.headers ?? {}),
    },
  });
  if (!res.ok) {
    let body: { code?: string; message?: string } = {};
    try { body = await res.json(); } catch {}
    throw new ApiError(res.status, body.code ?? "http_error", body.message ?? res.statusText);
  }
  return (await res.json()) as T;
}

export class ApiError extends Error {
  constructor(public status: number, public code: string, message: string) {
    super(message);
  }
}

// isAuthError reports whether an error is an expired/missing session (401).
// Used by the dashboards to bounce cleanly to /login instead of leaving a
// silently-dead button when the session has timed out.
export function isAuthError(e: unknown): boolean {
  return e instanceof ApiError && e.status === 401;
}

// redirectToLogin sends the user to the home/login page with a flag so the
// landing page can show "your session expired, sign in again."
export function redirectToLogin() {
  if (typeof window !== "undefined") {
    window.location.assign("/?expired=1");
  }
}

// --- console (read API) ---

export const consoleApi = {
  login: (token: string) =>
    jsonFetch<{
      tenant_id: string;
      role: Role;
      exp: number;
      // Present when the input was an 8-char demo code; carries the real
      // osk_… token so the dashboard can use it for /v1/scan and /v1/chat.
      resolved_token?: string;
    }>(
      "/api/console/api/v1/session",
      { method: "POST", body: JSON.stringify({ token }) }
    ),
  logout: () => jsonFetch<{ status: string }>("/api/console/api/v1/logout", { method: "POST" }),
  // Demo-only: re-issue the session under a different role within the same
  // tenant, so the role-map can flip between views without re-entering codes.
  switchRole: (role: Role) =>
    jsonFetch<{ tenant_id: string; role: Role }>("/api/console/api/v1/session/switch", {
      method: "POST",
      body: JSON.stringify({ role }),
    }),
  me: () => jsonFetch<{ tenant_id: string; role: Role; key_id: string; exp: number }>("/api/console/api/v1/me"),
  events: (limit = 20) =>
    jsonFetch<{ events: RouterEvent[] }>(`/api/console/api/v1/events?limit=${limit}`),
  usage: () => jsonFetch<UsageSummary>("/api/console/api/v1/usage"),
  // Per-model breakdown — entitled catalog + admin enablement + this month's
  // usage. models() is per-tenant (developer/IT); vendorModels() is cross-tenant
  // (OpenScope Ops).
  models: () => jsonFetch<{ region: string; models: ModelInfo[] }>("/api/console/api/v1/models"),
  vendorModels: () => jsonFetch<{ region: string; models: ModelInfo[] }>("/api/console/api/v1/vendor/models"),
  prompts: (limit = 10) =>
    jsonFetch<{ prompts: PromptRow[] }>(`/api/console/api/v1/prompts?limit=${limit}`),
  receipts: (limit = 5) =>
    jsonFetch<{ receipts: ReceiptRow[] }>(`/api/console/api/v1/receipts?limit=${limit}`),
  vendorUsage: () => jsonFetch<{ daily: VendorUsageRow[] }>("/api/console/api/v1/vendor/usage"),
  verifyNoPromptAccess: () =>
    jsonFetch<{
      attempted_query: string;
      pool: string;
      result: string;
      postgres_message: string;
    }>("/api/console/api/v1/vendor/verify_no_prompt_access", { method: "POST" }),
};

// --- router (action API) ---

export type ScanResponse = {
  request_id: string;
  decision: "allow" | "deny";
  reason?: string;
  findings?: { rule_id: string; rule_name: string; category: string; severity: string; count: number }[];
};

export type ChatRequest = {
  model?: string;
  messages: { role: "user" | "assistant" | "system"; content: string }[];
  max_tokens?: number;
  // Repo/workspace the agent is "working in". Recorded in the signed receipt
  // and audit. DLP runs on the payload regardless of this label.
  workspace?: string;
};

export type ChatResponse = {
  request_id: string;
  model: string;
  model_label?: string;     // human label, e.g. "Claude Haiku 4.5"
  requested_model?: string; // set when the agent asked for a model we remapped
  provider?: string;        // "AWS Bedrock"
  region?: string;          // "us-west-2"
  workspace?: string;
  decision: "allow" | "deny";
  reason?: string;
  findings?: { rule_id: string; rule_name: string; category: string; severity: string; count: number }[];
  content?: string;
  usage?: {
    input_tokens: number;
    output_tokens: number;
    total_cost_usd: number;
    month_to_date_usd: number;
    monthly_cap_usd: number;
  };
  receipt?: {
    payload: Record<string, unknown>;
    signature: string;
    public_key_id: string;
  };
};

// /v1/scan and /v1/chat need the bearer token directly — the router doesn't
// share the console's session cookie. The dashboard stores the token after
// login (in sessionStorage) for these calls.

export const routerApi = {
  scan: async (token: string, file: File) => {
    const form = new FormData();
    form.append("file", file);
    const res = await fetch("/api/router/v1/scan", {
      method: "POST",
      headers: { Authorization: `Bearer ${token}` },
      body: form,
    });
    if (!res.ok) {
      let body: { code?: string; message?: string } = {};
      try { body = await res.json(); } catch {}
      throw new ApiError(res.status, body.code ?? "http_error", body.message ?? res.statusText);
    }
    return (await res.json()) as ScanResponse;
  },
  chat: (token: string, req: ChatRequest) =>
    fetch("/api/router/v1/chat", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(req),
    }).then(async (r) => {
      if (!r.ok) {
        let body: { code?: string; message?: string } = {};
        try { body = await r.json(); } catch {}
        throw new ApiError(r.status, body.code ?? "http_error", body.message ?? r.statusText);
      }
      return (await r.json()) as ChatResponse;
    }),
};

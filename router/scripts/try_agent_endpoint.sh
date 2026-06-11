#!/usr/bin/env bash
# Smoke-test the agent-compatible shims (/v1/chat/completions, /v1/messages)
# against a base URL + token. Exercises an allow case and a block case for
# each dialect and prints the decision headers.
#
# Usage:
#   OPENSCOPE_KEY=osk_developer_… ./scripts/try_agent_endpoint.sh
#   ./scripts/try_agent_endpoint.sh https://demo.openscopeai.com/api/router osk_developer_…
#
# Exit non-zero if any case doesn't match its expected HTTP status.

set -uo pipefail

BASE="${1:-${OPENSCOPE_BASE:-https://demo.openscopeai.com/api/router}}"
TOKEN="${2:-${OPENSCOPE_KEY:-}}"

if [[ -z "$TOKEN" ]]; then
  echo "error: set OPENSCOPE_KEY (or pass the token as arg 2)" >&2
  exit 2
fi

# Verilog snippet that must trip content-class (hdl-verilog, MinHits 2).
RTL='`timescale 1ns/1ps\nmodule m(input clk, input d, output reg q); always_ff @(posedge clk) q<=d; endmodule'

pass=0; fail=0

# check NAME EXPECTED_STATUS URL DATA EXTRA_HEADER...
check() {
  local name="$1" want="$2" url="$3" data="$4"; shift 4
  local hdr body code
  hdr="$(mktemp)"; body="$(mktemp)"
  code=$(curl -s -o "$body" -D "$hdr" -w '%{http_code}' \
    -H "Authorization: Bearer ${TOKEN}" \
    -H "Content-Type: application/json" \
    "$@" \
    --data "$data" "$url")
  local decision
  decision=$(grep -i '^x-openscope-decision:' "$hdr" | tr -d '\r' | awk '{print $2}')
  local rules
  rules=$(grep -i '^x-openscope-dlp-rules:' "$hdr" | tr -d '\r' | cut -d' ' -f2-)
  if [[ "$code" == "$want" ]]; then
    echo "  ✓ ${name}: HTTP ${code} decision=${decision:-?} ${rules:+rules=$rules}"
    pass=$((pass+1))
  else
    echo "  ✗ ${name}: HTTP ${code} (wanted ${want}) decision=${decision:-?}"
    echo "      body: $(head -c 240 "$body")"
    fail=$((fail+1))
  fi
  rm -f "$hdr" "$body"
}

echo "Agent endpoint smoke test → ${BASE}"
echo ""
echo "OpenAI /v1/chat/completions:"
check "allow (webapp)" 200 "${BASE}/v1/chat/completions" \
  '{"model":"gpt-4o","messages":[{"role":"user","content":"Say hello in one short line."}]}' \
  -H "X-OpenScope-Workspace: northwind-webapp"
check "block (rtl)" 403 "${BASE}/v1/chat/completions" \
  "{\"model\":\"gpt-4o\",\"messages\":[{\"role\":\"user\",\"content\":\"Explain this:\\n${RTL}\"}]}" \
  -H "X-OpenScope-Workspace: northwind-rtl"

echo ""
echo "Anthropic /v1/messages:"
check "allow (webapp)" 200 "${BASE}/v1/messages" \
  '{"model":"claude-3-5-sonnet","max_tokens":128,"messages":[{"role":"user","content":"Say hello in one short line."}]}' \
  -H "X-OpenScope-Workspace: northwind-webapp"
check "block (rtl)" 403 "${BASE}/v1/messages" \
  "{\"model\":\"claude-3-5-sonnet\",\"max_tokens\":128,\"messages\":[{\"role\":\"user\",\"content\":\"Explain this:\\n${RTL}\"}]}" \
  -H "X-OpenScope-Workspace: northwind-rtl"

echo ""
echo "passed=${pass} failed=${fail}"
[[ "$fail" -eq 0 ]]

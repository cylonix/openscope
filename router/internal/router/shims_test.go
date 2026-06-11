package router

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/openscope/openscope/router/internal/dlp"
)

func TestExtractText(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{"plain string", `"hello world"`, "hello world"},
		{"empty", ``, ""},
		{"text parts array", `[{"type":"text","text":"a"},{"type":"text","text":"b"}]`, "a\nb"},
		{"mixed array skips non-text", `[{"type":"image"},{"type":"text","text":"only"}]`, "only"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := extractText(json.RawMessage(c.raw))
			if got != c.want {
				t.Errorf("extractText(%s) = %q, want %q", c.raw, got, c.want)
			}
		})
	}
}

func TestNormalizeRole(t *testing.T) {
	cases := map[string]string{
		"system": "system", "assistant": "assistant", "user": "user",
		"developer": "system", "tool": "user", "function": "user", "weird": "user",
	}
	for in, want := range cases {
		if got := normalizeRole(in); got != want {
			t.Errorf("normalizeRole(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestBuildOpenAICompletionShape(t *testing.T) {
	out := &chatOutcome{
		RequestID: uuid.New(), RequestedModel: "gpt-4o",
		Content: "hi", InputTokens: 3, OutputTokens: 1,
	}
	m := buildOpenAICompletion(out)
	if m["object"] != "chat.completion" {
		t.Errorf("object = %v", m["object"])
	}
	if m["model"] != "gpt-4o" {
		t.Errorf("model should echo requested = %v", m["model"])
	}
	choices, ok := m["choices"].([]map[string]any)
	if !ok || len(choices) != 1 {
		t.Fatalf("choices malformed: %v", m["choices"])
	}
	msg := choices[0]["message"].(map[string]any)
	if msg["content"] != "hi" || msg["role"] != "assistant" {
		t.Errorf("message malformed: %v", msg)
	}
	usage := m["usage"].(map[string]any)
	if usage["total_tokens"] != 4 {
		t.Errorf("total_tokens = %v, want 4", usage["total_tokens"])
	}
}

func TestBuildAnthropicMessageShape(t *testing.T) {
	out := &chatOutcome{
		RequestID: uuid.New(), RequestedModel: "claude-3-5-sonnet",
		Content: "yo", InputTokens: 5, OutputTokens: 2,
	}
	m := buildAnthropicMessage(out)
	if m["type"] != "message" || m["role"] != "assistant" {
		t.Errorf("envelope malformed: %v", m)
	}
	content := m["content"].([]map[string]any)
	if content[0]["type"] != "text" || content[0]["text"] != "yo" {
		t.Errorf("content malformed: %v", content)
	}
	if m["stop_reason"] != "end_turn" {
		t.Errorf("stop_reason = %v", m["stop_reason"])
	}
}

func TestDLPBlockMessageNamesRuleAndRequest(t *testing.T) {
	rid := uuid.New()
	out := &chatOutcome{
		RequestID: rid,
		Result:    "dlp_block",
		Findings: []dlp.Finding{
			{RuleID: "hdl-verilog", Category: dlp.CategoryContentClass, RuleName: "Verilog / SystemVerilog source"},
		},
	}
	msg := blockMessage(out)
	if !strings.Contains(msg, "proprietary source/IP") {
		t.Errorf("message should name the category: %q", msg)
	}
	if !strings.Contains(msg, rid.String()) {
		t.Errorf("message should include the request id: %q", msg)
	}
	if !strings.Contains(msg, "hdl-verilog") {
		t.Errorf("message should include the rule id: %q", msg)
	}
}

func TestClampTokens(t *testing.T) {
	cases := map[int]int{0: 512, -5: 512, 100: 100, 4096: 4096, 99999: maxTokensCeiling}
	for in, want := range cases {
		if got := clampTokens(in, maxTokensCeiling); got != want {
			t.Errorf("clampTokens(%d) = %d, want %d", in, got, want)
		}
	}
}

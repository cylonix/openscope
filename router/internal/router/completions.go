package router

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/openscope/openscope/router/internal/dlp"
)

// CompletionsHandler implements POST /v1/chat/completions — the
// OpenAI-compatible shim. Coding agents (Cursor, Codex CLI with
// wire_api="chat", Cline, Aider, Continue) point their OpenAI base_url here.
//
// It parses the OpenAI request, runs the shared governed pipeline, and renders
// either an OpenAI ChatCompletion (allow) or an OpenAI error envelope (deny /
// budget / upstream). On a DLP block the agent sees a 403 whose message names
// what was caught — the engineer's own tool surfaces the block.
type CompletionsHandler struct{ *ChatHandler }

// openAIRequest is the subset of the OpenAI Chat Completions request we read.
// content may be a plain string or an array of content parts; we extract text
// from both.
type openAIRequest struct {
	Model     string             `json:"model"`
	Messages  []openAIReqMessage `json:"messages"`
	MaxTokens int                `json:"max_tokens"`
	Stream    bool               `json:"stream"`
}

type openAIReqMessage struct {
	Role    string          `json:"role"`
	Content json.RawMessage `json:"content"`
}

func (h *CompletionsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	principal, err := h.Resolver.Resolve(ctx, r.Header.Get("Authorization"))
	if err != nil {
		writeOpenAIError(w, http.StatusUnauthorized, "invalid_request_error", "unauthorized", "invalid or missing API key")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, h.MaxBodyBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid_request_error", "body_read_failed", err.Error())
		return
	}
	var req openAIRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeOpenAIError(w, http.StatusBadRequest, "invalid_request_error", "bad_json", err.Error())
		return
	}
	msgs := make([]ChatMessage, 0, len(req.Messages))
	for _, m := range req.Messages {
		msgs = append(msgs, ChatMessage{Role: normalizeRole(m.Role), Content: extractText(m.Content)})
	}
	if len(msgs) == 0 {
		writeOpenAIError(w, http.StatusBadRequest, "invalid_request_error", "no_messages", "messages must be non-empty")
		return
	}

	out, err := h.process(ctx, principal, chatInput{
		Endpoint:       "/v1/chat/completions",
		Workspace:      r.Header.Get("X-OpenScope-Workspace"),
		RequestedModel: req.Model,
		Messages:       msgs,
		MaxTokens:      req.MaxTokens,
		Lenient:        true,
	})
	if err != nil {
		writeOpenAIError(w, http.StatusInternalServerError, "server_error", "internal_error", err.Error())
		return
	}

	setOpenScopeHeaders(w, out)

	switch out.Result {
	case "success":
		if req.Stream {
			writeOpenAIStream(w, out)
			return
		}
		writeJSON(w, http.StatusOK, buildOpenAICompletion(out))
	case "dlp_block", "channel_block":
		// Surface the block inside the agent. 403 + a message naming what was
		// caught and the request id for the audit trail.
		writeOpenAIError(w, http.StatusForbidden, "openscope_"+out.Result, out.Result, blockMessage(out))
	default: // budget_exceeded | upstream_error | premium_gated | unknown_model
		writeOpenAIError(w, errStatus(out), "openscope_"+out.Result, out.ErrCode, out.ErrMessage)
	}
}

// --- OpenAI response shaping ----------------------------------------------

func buildOpenAICompletion(out *chatOutcome) map[string]any {
	return map[string]any{
		"id":      "chatcmpl-" + out.RequestID.String(),
		"object":  "chat.completion",
		"created": 0,
		"model":   out.RequestedModel,
		"choices": []map[string]any{{
			"index":         0,
			"message":       map[string]any{"role": "assistant", "content": out.Content},
			"finish_reason": "stop",
		}},
		"usage": map[string]any{
			"prompt_tokens":     out.InputTokens,
			"completion_tokens": out.OutputTokens,
			"total_tokens":      out.InputTokens + out.OutputTokens,
		},
	}
}

// writeOpenAIStream emits the allow content as a minimal SSE stream so agents
// configured for streaming work. We send one delta with the full content then
// [DONE] — non-incremental but protocol-correct.
func writeOpenAIStream(w http.ResponseWriter, out *chatOutcome) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)

	id := "chatcmpl-" + out.RequestID.String()
	role := map[string]any{
		"id": id, "object": "chat.completion.chunk", "created": 0, "model": out.RequestedModel,
		"choices": []map[string]any{{"index": 0, "delta": map[string]any{"role": "assistant"}, "finish_reason": nil}},
	}
	delta := map[string]any{
		"id": id, "object": "chat.completion.chunk", "created": 0, "model": out.RequestedModel,
		"choices": []map[string]any{{"index": 0, "delta": map[string]any{"content": out.Content}, "finish_reason": nil}},
	}
	stop := map[string]any{
		"id": id, "object": "chat.completion.chunk", "created": 0, "model": out.RequestedModel,
		"choices": []map[string]any{{"index": 0, "delta": map[string]any{}, "finish_reason": "stop"}},
	}
	for _, chunk := range []map[string]any{role, delta, stop} {
		b, _ := json.Marshal(chunk)
		fmt.Fprintf(w, "data: %s\n\n", b)
		if flusher != nil {
			flusher.Flush()
		}
	}
	fmt.Fprint(w, "data: [DONE]\n\n")
	if flusher != nil {
		flusher.Flush()
	}
}

type openAIErrorEnvelope struct {
	Error openAIErrorBody `json:"error"`
}
type openAIErrorBody struct {
	Message string `json:"message"`
	Type    string `json:"type"`
	Code    string `json:"code"`
}

func writeOpenAIError(w http.ResponseWriter, status int, typ, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(openAIErrorEnvelope{Error: openAIErrorBody{Message: msg, Type: typ, Code: code}})
}

// --- shared shim helpers ---------------------------------------------------

// blockMessage is the agent-facing one-liner. For a content block it names the
// strongest finding; for a channel block it states the deny-by-default policy.
// Either way it includes the request id (for the audit trail) and any
// corroborating content findings.
func blockMessage(out *chatOutcome) string {
	lead := out.Reason
	if out.Result == "dlp_block" {
		lead = dlp.PrimaryReason(out.Findings)
	}
	msg := fmt.Sprintf("[OpenScope] blocked at the perimeter: %s. Request %s withheld from the model — recorded in the audit log with a signed receipt.",
		lead, out.RequestID.String())
	if rules := strings.Join(dlp.RuleIDs(out.Findings), ", "); rules != "" {
		msg += " Content also flagged: " + rules + "."
	}
	return msg
}

func setOpenScopeHeaders(w http.ResponseWriter, out *chatOutcome) {
	w.Header().Set("X-OpenScope-Decision", out.Decision)
	w.Header().Set("X-OpenScope-Result", out.Result)
	w.Header().Set("X-OpenScope-Request-Id", out.RequestID.String())
	if out.Workspace != "" {
		w.Header().Set("X-OpenScope-Workspace", out.Workspace)
	}
	if len(out.Findings) > 0 {
		w.Header().Set("X-OpenScope-Dlp-Rules", strings.Join(dlp.RuleIDs(out.Findings), ","))
	}
}

func errStatus(out *chatOutcome) int {
	if out.HTTPStatus != 0 {
		return out.HTTPStatus
	}
	return http.StatusBadGateway
}

// normalizeRole maps incoming roles to the three we forward. OpenAI "tool"/
// "function" roles are folded to user so the conversation still flows.
func normalizeRole(role string) string {
	switch role {
	case "system", "assistant", "user":
		return role
	case "developer": // OpenAI's newer system-equivalent
		return "system"
	default:
		return "user"
	}
}

// extractText pulls text from an OpenAI/Anthropic content field that may be a
// plain JSON string or an array of {type:"text", text:"..."} parts.
func extractText(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	var parts []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if err := json.Unmarshal(raw, &parts); err == nil {
		var b strings.Builder
		for _, p := range parts {
			if p.Text != "" {
				if b.Len() > 0 {
					b.WriteString("\n")
				}
				b.WriteString(p.Text)
			}
		}
		return b.String()
	}
	return ""
}

package router

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/openscope/openscope/router/internal/dlp"
)

// MessagesHandler implements POST /v1/messages — the Anthropic-compatible
// shim. Claude Code points ANTHROPIC_BASE_URL here. It parses the Anthropic
// Messages request, runs the shared governed pipeline, and renders an
// Anthropic Messages response (allow) or an Anthropic error envelope (deny).
//
// Claude Code defaults to streaming, so we implement the Anthropic SSE event
// sequence for the allow path.
type MessagesHandler struct{ *ChatHandler }

type anthropicRequest struct {
	Model     string                `json:"model"`
	System    json.RawMessage       `json:"system"` // string or array of blocks
	Messages  []anthropicReqMessage `json:"messages"`
	MaxTokens int                   `json:"max_tokens"`
	Stream    bool                  `json:"stream"`
}

type anthropicReqMessage struct {
	Role    string          `json:"role"`
	Content json.RawMessage `json:"content"`
}

func (h *MessagesHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Anthropic clients authenticate with x-api-key; accept that or Bearer.
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		if k := r.Header.Get("x-api-key"); k != "" {
			authHeader = "Bearer " + k
		}
	}
	principal, err := h.Resolver.Resolve(ctx, authHeader)
	if err != nil {
		writeAnthropicError(w, http.StatusUnauthorized, "authentication_error", "invalid or missing API key")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, h.MaxBodyBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeAnthropicError(w, http.StatusBadRequest, "invalid_request_error", err.Error())
		return
	}
	var req anthropicRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeAnthropicError(w, http.StatusBadRequest, "invalid_request_error", err.Error())
		return
	}

	var msgs []ChatMessage
	if sys := extractText(req.System); sys != "" {
		msgs = append(msgs, ChatMessage{Role: "system", Content: sys})
	}
	for _, m := range req.Messages {
		msgs = append(msgs, ChatMessage{Role: normalizeRole(m.Role), Content: extractText(m.Content)})
	}
	if len(msgs) == 0 {
		writeAnthropicError(w, http.StatusBadRequest, "invalid_request_error", "messages must be non-empty")
		return
	}

	out, err := h.process(ctx, principal, chatInput{
		Endpoint:       "/v1/messages",
		Workspace:      r.Header.Get("X-OpenScope-Workspace"),
		RequestedModel: req.Model,
		Messages:       msgs,
		MaxTokens:      req.MaxTokens,
		Lenient:        true,
	})
	if err != nil {
		writeAnthropicError(w, http.StatusInternalServerError, "api_error", err.Error())
		return
	}

	setOpenScopeHeaders(w, out)

	switch out.Result {
	case "success":
		if req.Stream {
			writeAnthropicStream(w, out)
			return
		}
		writeJSON(w, http.StatusOK, buildAnthropicMessage(out))
	case "dlp_block", "channel_block":
		writeAnthropicError(w, http.StatusForbidden, "permission_error", blockMessage(out))
	default: // budget_exceeded | upstream_error | premium_gated | unknown_model
		writeAnthropicError(w, errStatus(out), anthropicErrType(out.Result), out.ErrMessage)
	}
}

func buildAnthropicMessage(out *chatOutcome) map[string]any {
	return map[string]any{
		"id":            "msg_" + out.RequestID.String(),
		"type":          "message",
		"role":          "assistant",
		"model":         out.RequestedModel,
		"content":       []map[string]any{{"type": "text", "text": out.Content}},
		"stop_reason":   "end_turn",
		"stop_sequence": nil,
		"usage": map[string]any{
			"input_tokens":  out.InputTokens,
			"output_tokens": out.OutputTokens,
		},
	}
}

// writeAnthropicStream emits the Anthropic SSE event sequence: message_start →
// content_block_start → content_block_delta → content_block_stop →
// message_delta → message_stop. We send the full text in a single delta.
func writeAnthropicStream(w http.ResponseWriter, out *chatOutcome) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)

	send := func(event string, data map[string]any) {
		b, _ := json.Marshal(data)
		fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, b)
		if flusher != nil {
			flusher.Flush()
		}
	}
	id := "msg_" + out.RequestID.String()
	send("message_start", map[string]any{
		"type": "message_start",
		"message": map[string]any{
			"id": id, "type": "message", "role": "assistant", "model": out.RequestedModel,
			"content": []any{}, "stop_reason": nil, "stop_sequence": nil,
			"usage": map[string]any{"input_tokens": out.InputTokens, "output_tokens": 0},
		},
	})
	send("content_block_start", map[string]any{
		"type": "content_block_start", "index": 0,
		"content_block": map[string]any{"type": "text", "text": ""},
	})
	send("content_block_delta", map[string]any{
		"type": "content_block_delta", "index": 0,
		"delta": map[string]any{"type": "text_delta", "text": out.Content},
	})
	send("content_block_stop", map[string]any{"type": "content_block_stop", "index": 0})
	send("message_delta", map[string]any{
		"type":  "message_delta",
		"delta": map[string]any{"stop_reason": "end_turn", "stop_sequence": nil},
		"usage": map[string]any{"output_tokens": out.OutputTokens},
	})
	send("message_stop", map[string]any{"type": "message_stop"})
}

type anthropicErrorEnvelope struct {
	Type  string             `json:"type"` // always "error"
	Error anthropicErrorBody `json:"error"`
}
type anthropicErrorBody struct {
	Type    string `json:"type"`
	Message string `json:"message"`
}

func writeAnthropicError(w http.ResponseWriter, status int, typ, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(anthropicErrorEnvelope{
		Type:  "error",
		Error: anthropicErrorBody{Type: typ, Message: msg},
	})
}

func anthropicErrType(result string) string {
	switch result {
	case "budget_exceeded":
		return "rate_limit_error"
	case "upstream_error":
		return "api_error"
	case "premium_gated":
		return "permission_error"
	default:
		return "invalid_request_error"
	}
}

var _ = dlp.RuleIDs

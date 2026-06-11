package router

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/openscope/openscope/cpclient"
	"github.com/openscope/openscope/router/internal/billing"
	"github.com/openscope/openscope/router/internal/dlp"
	"github.com/openscope/openscope/router/internal/provider"
	"github.com/openscope/openscope/router/internal/store"
	"github.com/openscope/openscope/router/internal/tenancy"
	"github.com/openscope/openscope/router/pkg/receipts"
)

// ChatHandler implements the model-forwarding endpoints. It exposes three
// dialects over one shared pipeline (process):
//
//	POST /v1/chat              — native OpenScope shape (rich decision JSON;
//	                             powers the web dashboards / governed console)
//	POST /v1/chat/completions  — OpenAI-compatible (Cursor, Codex CLI, Cline,
//	                             Aider, Continue)
//	POST /v1/messages          — Anthropic-compatible (Claude Code)
//
// All three run the same governance: auth → budget → DLP (content-class +
// markers + secrets) → Bedrock Converse → transactional persist → signed
// receipt. The only difference is request parsing and response shaping.
//
// Workspace tag: agents may send X-OpenScope-Workspace (or a "workspace"
// body field on the native endpoint) naming the repo they're working in. It's
// recorded in the signed receipt and audit. Crucially, DLP runs on the payload
// regardless of the claimed workspace — so relabeling a restricted repo as an
// allowed one does NOT smuggle RTL past the gate.
type ChatHandler struct {
	Resolver         *tenancy.Resolver
	Scanner          *dlp.Scanner
	Store            RecordStore
	Provider         provider.Invoker
	Signer           *receipts.Signer
	DefaultModelID   string
	AllowPremiumTier bool
	MaxBodyBytes     int64

	// DefaultMonthlyBudgetUSD is the deployment-wide soft cap applied to
	// tenants without an app.tenants.monthly_budget_usd override.
	DefaultMonthlyBudgetUSD float64

	// MaxTokensCeiling bounds per-request max_tokens; 0 means the package
	// default (4096).
	MaxTokensCeiling int

	// PolicyVersion (OPENSCOPE_POLICY_VERSION) and DLPRulesetVersion (hash
	// of the loaded DLP ruleset) are stamped onto every receipt so an
	// auditor can tie a decision to the exact policy that produced it.
	PolicyVersion     string
	DLPRulesetVersion string

	// Usage, when set, receives one metadata-only event per processed
	// request — the control-plane metering hook (cpclient.Client.Record).
	// Never receives prompt or response bodies.
	Usage func(cpclient.UsageEvent)

	// EnabledModels is the customer admin's model allowlist: a request for a
	// catalog model that isn't in this set is refused ("disabled by your
	// administrator"). Lets a customer turn off expensive or low-quality
	// models. Nil means "all catalog models enabled" (no policy). The default
	// model must be in the set. Agent shims remap unknown names to the default,
	// so this only bites callers that explicitly name a disabled model.
	EnabledModels map[string]bool

	// RestrictedWorkspaces are deny-by-default channels: any request tagged
	// with one of these workspaces is blocked outright, regardless of content
	// ("blocked because it was never allowed to leave, not because a
	// classifier got lucky"). Content-class DLP still runs as a backstop for
	// unrestricted/unknown workspaces — so a restricted file relabeled as an
	// allowed workspace is still caught by what it *is*.
	RestrictedWorkspaces map[string]bool
}

// --- native /v1/chat request/response --------------------------------------

type ChatRequest struct {
	Model     string        `json:"model,omitempty"`
	Messages  []ChatMessage `json:"messages"`
	MaxTokens int           `json:"max_tokens,omitempty"`
	Workspace string        `json:"workspace,omitempty"`
}

type ChatMessage struct {
	Role    string `json:"role"` // "user" | "assistant" | "system"
	Content string `json:"content"`
}

type ChatResponse struct {
	RequestID      string           `json:"request_id"`
	Model          string           `json:"model"`
	ModelLabel     string           `json:"model_label,omitempty"`     // human label, e.g. "Claude Haiku 4.5"
	RequestedModel string           `json:"requested_model,omitempty"` // set when the caller asked for a model we remapped (agent shims)
	Provider       string           `json:"provider,omitempty"`        // "AWS Bedrock"
	Region         string           `json:"region,omitempty"`          // "us-west-2"
	Workspace      string           `json:"workspace,omitempty"`
	Decision       string           `json:"decision"` // "allow" | "deny"
	Reason         string           `json:"reason,omitempty"`
	Findings       []dlp.Finding    `json:"findings,omitempty"` // present when DLP blocks
	Content        string           `json:"content,omitempty"`
	Usage          *UsageBlock      `json:"usage,omitempty"`
	Receipt        *ReceiptResponse `json:"receipt,omitempty"`
}

type UsageBlock struct {
	InputTokens    int     `json:"input_tokens"`
	OutputTokens   int     `json:"output_tokens"`
	TotalCostUSD   float64 `json:"total_cost_usd"`
	MonthToDateUSD float64 `json:"month_to_date_usd"`
	MonthlyCapUSD  float64 `json:"monthly_cap_usd"`
}

type ReceiptResponse struct {
	Payload     json.RawMessage `json:"payload"`   // canonical JSON
	Signature   string          `json:"signature"` // base64
	PublicKeyID string          `json:"public_key_id"`
}

// ServeHTTP is the native /v1/chat adapter.
func (h *ChatHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	principal, err := h.Resolver.Resolve(ctx, r.Header.Get("Authorization"))
	if err != nil {
		writeError(w, http.StatusUnauthorized, "unauthorized", "invalid or missing Authorization header")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, h.MaxBodyBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "body_read_failed", err.Error())
		return
	}
	var req ChatRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "bad_json", err.Error())
		return
	}
	if len(req.Messages) == 0 {
		writeError(w, http.StatusBadRequest, "no_messages", "messages must be non-empty")
		return
	}

	out, err := h.process(ctx, principal, chatInput{
		Endpoint:       "/v1/chat",
		Workspace:      firstNonEmpty(req.Workspace, r.Header.Get("X-OpenScope-Workspace")),
		RequestedModel: req.Model,
		Messages:       req.Messages,
		MaxTokens:      req.MaxTokens,
		Lenient:        false, // native callers must use a catalog model id
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}

	// The native dialect returns 200 for both allow and DLP-deny (the decision
	// is in the body). Error-ish results map to their HTTP status.
	switch out.Result {
	case "success", "dlp_block", "channel_block":
		writeJSON(w, http.StatusOK, h.nativeResponse(out))
	case "budget_exceeded":
		writeJSON(w, http.StatusTooManyRequests, h.nativeResponse(out))
	default: // unknown_model | premium_gated | upstream_error
		writeError(w, out.HTTPStatus, out.ErrCode, out.ErrMessage)
	}
}

func (h *ChatHandler) nativeResponse(out *chatOutcome) ChatResponse {
	resp := ChatResponse{
		RequestID:  out.RequestID.String(),
		Model:      out.Model,
		ModelLabel: billing.DisplayName(out.Model),
		Provider:   h.Provider.Name(),
		Region:     h.Provider.Region(),
		Workspace:  out.Workspace,
		Decision:   out.Decision,
		Reason:     out.Reason,
		Findings:   out.Findings,
		Content:    out.Content,
	}
	if out.RequestedModel != "" && out.RequestedModel != out.Model {
		resp.RequestedModel = out.RequestedModel
	}
	if out.Receipt != nil && len(out.Receipt.PayloadJSON) > 0 {
		resp.Receipt = &ReceiptResponse{
			Payload:     out.Receipt.PayloadJSON,
			Signature:   base64.StdEncoding.EncodeToString(out.Receipt.Signature),
			PublicKeyID: out.Receipt.PublicKeyID,
		}
	}
	if out.Result == "success" || out.Result == "budget_exceeded" {
		resp.Usage = &UsageBlock{
			InputTokens:    out.InputTokens,
			OutputTokens:   out.OutputTokens,
			TotalCostUSD:   out.TotalCostUSD,
			MonthToDateUSD: out.MonthToDateUSD,
			MonthlyCapUSD:  out.MonthlyCapUSD,
		}
	}
	return resp
}

// --- shared pipeline -------------------------------------------------------

// chatInput is the dialect-neutral request the adapters build.
type chatInput struct {
	Endpoint       string
	Workspace      string
	RequestedModel string // what the caller asked for ("" → default)
	Messages       []ChatMessage
	MaxTokens      int
	Lenient        bool // true for agent shims: unknown model → default instead of 400
}

// chatOutcome is the dialect-neutral result the adapters render.
type chatOutcome struct {
	RequestID      uuid.UUID
	RequestedModel string
	Model          string // actual catalog model id used
	Workspace      string
	Decision       string // allow | deny
	Result         string // success | dlp_block | budget_exceeded | upstream_error | unknown_model | premium_gated
	Reason         string
	Findings       []dlp.Finding
	Content        string
	InputTokens    int
	OutputTokens   int
	TotalCostUSD   float64
	MonthToDateUSD float64
	MonthlyCapUSD  float64
	Receipt        *receipts.Receipt

	// Error-ish rendering hints (set when Result is not success/dlp_block).
	HTTPStatus int
	ErrCode    string
	ErrMessage string
}

const maxTokensCeiling = 4096

func (h *ChatHandler) maxTokensOrDefault() int {
	if h.MaxTokensCeiling > 0 {
		return h.MaxTokensCeiling
	}
	return maxTokensCeiling
}

func (h *ChatHandler) defaultBudgetOrFallback() float64 {
	if h.DefaultMonthlyBudgetUSD > 0 {
		return h.DefaultMonthlyBudgetUSD
	}
	return billing.DefaultMonthlyBudgetUSD
}

// process runs the governed pipeline and feeds the control-plane metering
// hook with the outcome's metadata.
func (h *ChatHandler) process(ctx context.Context, principal tenancy.Principal, in chatInput) (*chatOutcome, error) {
	start := time.Now()
	out, err := h.processInner(ctx, principal, in)
	if err == nil && out != nil && h.Usage != nil {
		h.Usage(cpclient.UsageEvent{
			Timestamp:    start.UTC(),
			RequestID:    out.RequestID.String(),
			Kind:         "chat",
			Action:       in.Endpoint,
			Model:        out.Model,
			Decision:     out.Decision,
			Result:       out.Result,
			DLPRuleIDs:   dlp.RuleIDs(out.Findings),
			InputTokens:  out.InputTokens,
			OutputTokens: out.OutputTokens,
			CostUSD:      out.TotalCostUSD,
			DurationMs:   time.Since(start).Milliseconds(),
		})
	}
	return out, err
}

// processInner is the full governed pipeline. It returns an error only for
// true infrastructure failures (DB tx) → HTTP 500; every business outcome
// (deny, budget, upstream error, etc.) is encoded in the returned chatOutcome.
func (h *ChatHandler) processInner(ctx context.Context, principal tenancy.Principal, in chatInput) (*chatOutcome, error) {
	keyID := principal.KeyID
	requestID := uuid.New()

	// --- Resolve + validate model --------------------------------------
	modelID := in.RequestedModel
	if modelID == "" {
		modelID = h.DefaultModelID
	}
	m := billing.Find(modelID)
	if m == nil {
		if !in.Lenient {
			return &chatOutcome{
				RequestID: requestID, Result: "unknown_model", Decision: "deny",
				HTTPStatus: http.StatusBadRequest, ErrCode: "unknown_model",
				ErrMessage: fmt.Sprintf("model %q not in catalog; see /v1/models", modelID),
			}, nil
		}
		// Agent shims: callers send foreign model names (gpt-4o,
		// claude-3-5-sonnet…). Map to our default and keep the requested
		// name for the audit/echo.
		modelID = h.DefaultModelID
		m = billing.Find(modelID)
	}
	if m == nil {
		return nil, fmt.Errorf("default model %q missing from catalog", modelID)
	}
	if h.EnabledModels != nil && !h.EnabledModels[modelID] {
		return &chatOutcome{
			RequestID: requestID, Model: modelID, Result: "model_disabled", Decision: "deny",
			HTTPStatus: http.StatusForbidden, ErrCode: "model_disabled",
			ErrMessage: fmt.Sprintf("model %q is disabled by your administrator's model policy", modelID),
		}, nil
	}
	if m.Tier == billing.TierPremium && !h.AllowPremiumTier {
		return &chatOutcome{
			RequestID: requestID, Model: modelID, Result: "premium_gated", Decision: "deny",
			HTTPStatus: http.StatusForbidden, ErrCode: "premium_gated",
			ErrMessage: fmt.Sprintf("model %q is premium-tier; set OPENSCOPE_ALLOW_PREMIUM_TIER=true to enable", modelID),
		}, nil
	}

	out := &chatOutcome{
		RequestID:      requestID,
		RequestedModel: firstNonEmpty(in.RequestedModel, modelID),
		Model:          modelID,
		Workspace:      in.Workspace,
	}

	// reqModel is recorded on the receipt only when the caller asked for a
	// model we remapped — agent shims send foreign names (gpt-4o,
	// claude-opus-4-8…) which we route to a catalog model. It makes the
	// audit explicit: "requested claude-opus-4-8 → served Amazon Nova Micro."
	reqModel := ""
	if in.RequestedModel != "" && in.RequestedModel != modelID {
		reqModel = in.RequestedModel
	}

	// --- Layer-1 budget check ------------------------------------------
	// Cap resolution: per-tenant override (app.tenants.monthly_budget_usd)
	// when set, else the deployment-wide default.
	capUSD := h.defaultBudgetOrFallback()
	if override, err := h.Store.GetTenantBudget(ctx, principal.TenantID); err != nil {
		return nil, fmt.Errorf("tenant budget lookup: %w", err)
	} else if override != nil {
		capUSD = *override
	}
	out.MonthlyCapUSD = capUSD

	mtd, budgetErr := billing.CheckMonthlyCap(ctx, h.Store, principal.TenantID, capUSD)
	if errors.Is(budgetErr, billing.ErrBudgetExceeded) {
		_ = h.Store.AppendRouterEvent(ctx, nil, store.RouterEvent{
			RequestID: requestID, TenantID: principal.TenantID, APIKeyID: &keyID,
			Role: principal.Role, Endpoint: in.Endpoint, Model: modelID,
			Decision: "deny", Result: "budget_exceeded",
			Reason: withWorkspace(in.Workspace, fmt.Sprintf("month-to-date spend $%.4f >= cap $%.2f", mtd, capUSD)),
		})
		out.Decision, out.Result = "deny", "budget_exceeded"
		out.MonthToDateUSD = mtd
		out.HTTPStatus, out.ErrCode = http.StatusTooManyRequests, "budget_exceeded"
		out.ErrMessage = fmt.Sprintf("monthly budget cap exceeded ($%.4f / $%.2f used)", mtd, capUSD)
		out.Reason = out.ErrMessage
		return out, nil
	}
	if budgetErr != nil {
		return nil, fmt.Errorf("budget check: %w", budgetErr)
	}

	concatenated := concatMessages(in.Messages)
	promptSHA := receipts.SHA256Hex([]byte(concatenated))
	// storedBody is what we persist: the full text with any large agent system
	// prompt (env scaffolding) summarized. promptSHA above commits to the FULL
	// text — the receipt attests what was actually sent/scanned, not the trim.
	storedBody := concatForStorage(in.Messages)

	// --- Channel policy: deny-by-default restricted workspaces ----------
	// A restricted workspace is an air-gapped channel — nothing from it may
	// reach an external model, period. We still scan so the audit can show the
	// content was (or wasn't) also IP, but the decision is the channel policy,
	// not the classifier.
	if h.RestrictedWorkspaces[in.Workspace] {
		findings := h.Scanner.Scan(concatenated)
		reason := "restricted workspace '" + in.Workspace + "' — deny-by-default channel (no external model egress)"
		findingsJSON, _ := json.Marshal(findings)
		_ = h.Store.AppendRouterEvent(ctx, nil, store.RouterEvent{
			RequestID: requestID, TenantID: principal.TenantID, APIKeyID: &keyID,
			Role: principal.Role, Endpoint: in.Endpoint, Model: modelID,
			Decision: "deny", Result: "channel_block",
			Reason:     withWorkspace(in.Workspace, reason),
			DLPRuleIDs: dlp.RuleIDs(findings), BytesIn: len(concatenated),
		})
		_ = h.Store.InsertPromptRecord(ctx, nil, store.PromptRecord{
			RequestID: requestID, TenantID: principal.TenantID,
			PromptText: storedBody, PromptSHA256: hexToBytes(promptSHA), DLPFindings: findingsJSON,
		})
		receipt := h.signReceipt(receipts.Payload{
			Version: 1, RequestID: requestID, TenantID: principal.TenantID,
			Timestamp: time.Now().UTC(), Endpoint: in.Endpoint, Workspace: in.Workspace,
			Model: modelID, RequestedModel: reqModel,
			Decision: "deny", Result: "channel_block",
			DLPRuleIDs: dlp.RuleIDs(findings), PromptSHA256: promptSHA,
		})
		_ = h.Store.InsertReceipt(ctx, nil, store.ReceiptRow{
			RequestID: requestID, TenantID: principal.TenantID,
			Payload: receipt.PayloadJSON, Signature: receipt.Signature, PublicKeyID: receipt.PublicKeyID,
		})
		out.Decision, out.Result, out.Reason = "deny", "channel_block", reason
		out.Findings, out.Receipt = findings, receipt
		return out, nil
	}

	// --- DLP scan (content backstop) ------------------------------------
	findings := h.Scanner.Scan(concatenated)

	if len(findings) > 0 {
		reason := "matched DLP rule(s): " + concatRuleIDs(findings)
		findingsJSON, _ := json.Marshal(findings)
		_ = h.Store.AppendRouterEvent(ctx, nil, store.RouterEvent{
			RequestID: requestID, TenantID: principal.TenantID, APIKeyID: &keyID,
			Role: principal.Role, Endpoint: in.Endpoint, Model: modelID,
			Decision: "deny", Result: "dlp_block",
			Reason:     withWorkspace(in.Workspace, reason),
			DLPRuleIDs: dlp.RuleIDs(findings), BytesIn: len(concatenated),
		})
		_ = h.Store.InsertPromptRecord(ctx, nil, store.PromptRecord{
			RequestID: requestID, TenantID: principal.TenantID,
			PromptText: storedBody, PromptSHA256: hexToBytes(promptSHA), DLPFindings: findingsJSON,
		})
		receipt := h.signReceipt(receipts.Payload{
			Version: 1, RequestID: requestID, TenantID: principal.TenantID,
			Timestamp: time.Now().UTC(), Endpoint: in.Endpoint, Workspace: in.Workspace,
			Model: modelID, RequestedModel: reqModel,
			Decision: "deny", Result: "dlp_block",
			DLPRuleIDs: dlp.RuleIDs(findings), PromptSHA256: promptSHA,
		})
		_ = h.Store.InsertReceipt(ctx, nil, store.ReceiptRow{
			RequestID: requestID, TenantID: principal.TenantID,
			Payload: receipt.PayloadJSON, Signature: receipt.Signature, PublicKeyID: receipt.PublicKeyID,
		})

		out.Decision, out.Result, out.Reason = "deny", "dlp_block", reason
		out.Findings, out.Receipt = findings, receipt
		return out, nil
	}

	// --- Forward to the model provider ----------------------------------
	brResp, err := h.Provider.Invoke(ctx, provider.Request{
		ModelID:   modelID,
		Messages:  toProviderMessages(in.Messages),
		MaxTokens: clampTokens(in.MaxTokens, h.maxTokensOrDefault()),
	})
	if err != nil {
		_ = h.Store.AppendRouterEvent(ctx, nil, store.RouterEvent{
			RequestID: requestID, TenantID: principal.TenantID, APIKeyID: &keyID,
			Role: principal.Role, Endpoint: in.Endpoint, Model: modelID,
			Decision: "allow", Result: "upstream_error",
			Reason: withWorkspace(in.Workspace, err.Error()), BytesIn: len(concatenated),
		})
		log.Printf("chat: provider invoke (%s) failed: %v", h.Provider.Name(), err)
		out.Result = "upstream_error"
		out.HTTPStatus, out.ErrCode, out.ErrMessage = http.StatusBadGateway, "upstream_error", err.Error()
		return out, nil
	}

	respSHA := receipts.SHA256Hex([]byte(brResp.Content))
	inCost, outCost, totalCost := costBreakdown(modelID, brResp.InputTokens, brResp.OutputTokens)

	// --- Transactional persist -----------------------------------------
	tx, err := h.Store.BeginTx(ctx)
	if err != nil {
		return nil, fmt.Errorf("tx begin: %w", err)
	}
	defer tx.Rollback(ctx)

	if err := h.Store.AppendRouterEvent(ctx, tx, store.RouterEvent{
		RequestID: requestID, TenantID: principal.TenantID, APIKeyID: &keyID,
		Role: principal.Role, Endpoint: in.Endpoint, Model: modelID,
		Decision: "allow", Result: "success",
		Reason: workspaceOnly(in.Workspace), BytesIn: len(concatenated), BytesOut: len(brResp.Content),
	}); err != nil {
		return nil, fmt.Errorf("audit write: %w", err)
	}
	if err := h.Store.InsertPromptRecord(ctx, tx, store.PromptRecord{
		RequestID: requestID, TenantID: principal.TenantID,
		PromptText: storedBody, PromptSHA256: hexToBytes(promptSHA),
	}); err != nil {
		return nil, fmt.Errorf("prompt write: %w", err)
	}
	if err := h.Store.InsertResponseRecord(ctx, tx, store.ResponseRecord{
		RequestID: requestID, TenantID: principal.TenantID,
		ResponseText: brResp.Content, FinishReason: brResp.FinishReason, Model: modelID,
	}); err != nil {
		return nil, fmt.Errorf("response write: %w", err)
	}
	if err := h.Store.InsertUsageMetric(ctx, tx, store.UsageMetric{
		TenantID: principal.TenantID, APIKeyID: &keyID, RequestID: requestID, Model: modelID,
		InputTokens: brResp.InputTokens, OutputTokens: brResp.OutputTokens,
		InputCostUSD: inCost, OutputCostUSD: outCost,
	}); err != nil {
		return nil, fmt.Errorf("usage write: %w", err)
	}
	receipt := h.signReceipt(receipts.Payload{
		Version: 1, RequestID: requestID, TenantID: principal.TenantID,
		Timestamp: time.Now().UTC(), Endpoint: in.Endpoint, Workspace: in.Workspace,
		Model: modelID, RequestedModel: reqModel,
		Decision: "allow", Result: "success",
		InputTokens: brResp.InputTokens, OutputTokens: brResp.OutputTokens,
		TotalCostUSD: totalCost, PromptSHA256: promptSHA, ResponseSHA256: respSHA,
	})
	if err := h.Store.InsertReceipt(ctx, tx, store.ReceiptRow{
		RequestID: requestID, TenantID: principal.TenantID,
		Payload: receipt.PayloadJSON, Signature: receipt.Signature, PublicKeyID: receipt.PublicKeyID,
	}); err != nil {
		return nil, fmt.Errorf("receipt write: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("tx commit: %w", err)
	}

	out.Decision, out.Result = "allow", "success"
	out.Content = brResp.Content
	out.InputTokens, out.OutputTokens = brResp.InputTokens, brResp.OutputTokens
	out.TotalCostUSD, out.MonthToDateUSD = totalCost, mtd+totalCost
	out.Receipt = receipt
	return out, nil
}

// signReceipt stamps the deployment context (provider, region, policy
// versions) onto the payload and signs it. Call sites fill the per-request
// fields only.
func (h *ChatHandler) signReceipt(p receipts.Payload) *receipts.Receipt {
	p.Provider = h.Provider.Name()
	p.Region = h.Provider.Region()
	p.PolicyVersion = h.PolicyVersion
	p.DLPRulesetVersion = h.DLPRulesetVersion
	r, err := h.Signer.Sign(p)
	if err != nil {
		log.Printf("chat: receipt sign failed: %v", err)
		return &receipts.Receipt{}
	}
	return r
}

// --- helpers ---------------------------------------------------------------

func concatMessages(msgs []ChatMessage) string {
	out := ""
	for i, m := range msgs {
		if i > 0 {
			out += "\n"
		}
		out += m.Role + ": " + m.Content
	}
	return out
}

// systemTrimBytes is the size above which an agent's system message is
// summarized in the STORED body (never in the scanned text). Coding agents —
// Claude Code, Cursor, Codex — inject a large system prompt carrying the
// tester's local environment: working directory, git branch/commits/status,
// OS, file paths. We DLP-scan it in full, but persisting that machine
// fingerprint is needlessly invasive for a demo, so we don't retain it.
// Smaller system prompts (e.g. the web console's own) pass through unchanged.
const systemTrimBytes = 400

// concatForStorage builds the prompt body we persist to sensitive.prompt_records.
// Identical to the scanned text EXCEPT a large system message is replaced with a
// one-line summary — so the IT prompt view shows the meaningful turns, not
// kilobytes of environment scaffolding. DLP always runs on the full text
// (concatMessages); only what we STORE is trimmed.
func concatForStorage(msgs []ChatMessage) string {
	out := ""
	for i, m := range msgs {
		if i > 0 {
			out += "\n"
		}
		content := m.Content
		if m.Role == "system" && len(content) > systemTrimBytes {
			content = fmt.Sprintf("[agent system prompt + environment trimmed — %s, DLP-scanned in full, not retained]", humanizeBytes(len(m.Content)))
		}
		out += m.Role + ": " + content
	}
	return out
}

func humanizeBytes(n int) string {
	if n >= 1024 {
		return fmt.Sprintf("%.1f KB", float64(n)/1024)
	}
	return fmt.Sprintf("%d B", n)
}

func concatRuleIDs(findings []dlp.Finding) string {
	return strings.Join(dlp.RuleIDs(findings), ", ")
}

func toProviderMessages(msgs []ChatMessage) []provider.Message {
	out := make([]provider.Message, len(msgs))
	for i, m := range msgs {
		out[i] = provider.Message{Role: m.Role, Content: m.Content}
	}
	return out
}

func costBreakdown(modelID string, in, out int) (inUSD, outUSD, totalUSD float64) {
	m := billing.Find(modelID)
	if m == nil {
		return 0, 0, 0
	}
	inUSD = float64(in) * m.InputUSDPerToken
	outUSD = float64(out) * m.OutputUSDPerToken
	totalUSD = inUSD + outUSD
	return
}

func clampTokens(v, ceiling int) int {
	if v <= 0 {
		return 512
	}
	if v > ceiling {
		return ceiling
	}
	return v
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// withWorkspace prefixes a reason with the workspace tag (for audit), since
// router_events has no dedicated workspace column in the MVP schema.
func withWorkspace(ws, reason string) string {
	if ws == "" {
		return reason
	}
	return "[ws:" + ws + "] " + reason
}

func workspaceOnly(ws string) string {
	if ws == "" {
		return ""
	}
	return "[ws:" + ws + "]"
}

func hexToBytes(h string) []byte {
	out := make([]byte, len(h)/2)
	for i := 0; i < len(h)/2; i++ {
		out[i] = unhex(h[i*2])<<4 | unhex(h[i*2+1])
	}
	return out
}

func unhex(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	}
	return 0
}

var _ = context.Background

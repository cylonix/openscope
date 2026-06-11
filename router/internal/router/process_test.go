package router

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/openscope/openscope/router/internal/dlp"
	"github.com/openscope/openscope/router/internal/provider"
	"github.com/openscope/openscope/router/internal/store"
	"github.com/openscope/openscope/router/internal/tenancy"
	"github.com/openscope/openscope/router/pkg/receipts"
)

// memStore is the in-memory RecordStore: the full pipeline (auth → budget →
// DLP → provider → persist → receipt) runs against it without Postgres.
type memStore struct {
	events    []store.RouterEvent
	prompts   []store.PromptRecord
	responses []store.ResponseRecord
	usage     []store.UsageMetric
	receipts  []store.ReceiptRow

	monthlySpend float64
	tenantBudget *float64

	committed  bool
	rolledBack bool
}

type memTx struct{ s *memStore }

func (t memTx) Commit(context.Context) error   { t.s.committed = true; return nil }
func (t memTx) Rollback(context.Context) error { t.s.rolledBack = true; return nil }

func (m *memStore) BeginTx(context.Context) (Tx, error) { return memTx{m}, nil }
func (m *memStore) AppendRouterEvent(_ context.Context, _ Tx, e store.RouterEvent) error {
	m.events = append(m.events, e)
	return nil
}
func (m *memStore) InsertPromptRecord(_ context.Context, _ Tx, p store.PromptRecord) error {
	m.prompts = append(m.prompts, p)
	return nil
}
func (m *memStore) InsertResponseRecord(_ context.Context, _ Tx, r store.ResponseRecord) error {
	m.responses = append(m.responses, r)
	return nil
}
func (m *memStore) InsertUsageMetric(_ context.Context, _ Tx, u store.UsageMetric) error {
	m.usage = append(m.usage, u)
	return nil
}
func (m *memStore) InsertReceipt(_ context.Context, _ Tx, r store.ReceiptRow) error {
	m.receipts = append(m.receipts, r)
	return nil
}
func (m *memStore) InsertUploadedDocument(_ context.Context, _ Tx, _ store.UploadedDocument) error {
	return nil
}
func (m *memStore) GetMonthlySpend(context.Context, uuid.UUID) (float64, error) {
	return m.monthlySpend, nil
}
func (m *memStore) GetTenantBudget(context.Context, uuid.UUID) (*float64, error) {
	return m.tenantBudget, nil
}

const testModel = "us.amazon.nova-micro-v1:0"

func newTestHandler(t *testing.T, ms *memStore, fake *provider.Fake) *ChatHandler {
	t.Helper()
	seed := []byte("0123456789abcdef0123456789abcdef")
	signer, err := receipts.NewSigner(seed, "test-key-1")
	if err != nil {
		t.Fatal(err)
	}
	return &ChatHandler{
		Scanner:              dlp.NewScanner(dlp.DefaultRules),
		Store:                ms,
		Provider:             fake,
		Signer:               signer,
		DefaultModelID:       testModel,
		MaxBodyBytes:         1 << 20,
		PolicyVersion:        "test-policy-7",
		DLPRulesetVersion:    dlp.RulesetVersion(dlp.DefaultRules),
		RestrictedWorkspaces: map[string]bool{"restricted-rtl": true},
	}
}

func testPrincipal() tenancy.Principal {
	return tenancy.Principal{KeyID: uuid.New(), TenantID: uuid.New(), Role: "developer"}
}

func userMsg(content string) []ChatMessage {
	return []ChatMessage{{Role: "user", Content: content}}
}

func run(t *testing.T, h *ChatHandler, in chatInput) *chatOutcome {
	t.Helper()
	out, err := h.process(context.Background(), testPrincipal(), in)
	if err != nil {
		t.Fatalf("process: %v", err)
	}
	return out
}

func TestProcessAllowPath(t *testing.T) {
	ms := &memStore{}
	fake := &provider.Fake{}
	h := newTestHandler(t, ms, fake)

	out := run(t, h, chatInput{Endpoint: "/v1/chat", Messages: userMsg("hello, summarize this README"), Workspace: "webapp"})

	if out.Decision != "allow" || out.Result != "success" {
		t.Fatalf("decision/result = %s/%s, want allow/success", out.Decision, out.Result)
	}
	if !strings.Contains(out.Content, "[mock]") {
		t.Errorf("content = %q, want mock reply", out.Content)
	}
	if len(fake.Requests()) != 1 {
		t.Fatalf("provider saw %d requests, want 1", len(fake.Requests()))
	}
	if !ms.committed {
		t.Error("success path did not commit the transaction")
	}
	if len(ms.events) != 1 || len(ms.prompts) != 1 || len(ms.responses) != 1 || len(ms.usage) != 1 || len(ms.receipts) != 1 {
		t.Errorf("persisted rows = events:%d prompts:%d responses:%d usage:%d receipts:%d, want 1 each",
			len(ms.events), len(ms.prompts), len(ms.responses), len(ms.usage), len(ms.receipts))
	}

	// Receipt must verify and carry the deployment context stamps.
	pub, err := base64.StdEncoding.DecodeString(h.Signer.PublicKeyBase64())
	if err != nil {
		t.Fatal(err)
	}
	if !receipts.VerifyCanonical(ed25519.PublicKey(pub), out.Receipt.PayloadJSON, out.Receipt.Signature) {
		t.Error("receipt signature does not verify")
	}
	var payload map[string]any
	if err := json.Unmarshal(out.Receipt.PayloadJSON, &payload); err != nil {
		t.Fatal(err)
	}
	if payload["provider"] != "Mock Provider" || payload["region"] != "local" {
		t.Errorf("payload provider/region = %v/%v", payload["provider"], payload["region"])
	}
	if payload["policy_version"] != "test-policy-7" {
		t.Errorf("policy_version = %v", payload["policy_version"])
	}
	if v, _ := payload["dlp_ruleset_version"].(string); !strings.HasPrefix(v, "dlp-") {
		t.Errorf("dlp_ruleset_version = %v", payload["dlp_ruleset_version"])
	}
}

func TestProcessDLPBlock(t *testing.T) {
	ms := &memStore{}
	fake := &provider.Fake{}
	h := newTestHandler(t, ms, fake)

	out := run(t, h, chatInput{Endpoint: "/v1/chat", Messages: userMsg("here is the key:\n-----BEGIN PRIVATE KEY-----\nabc")})

	if out.Decision != "deny" || out.Result != "dlp_block" {
		t.Fatalf("decision/result = %s/%s, want deny/dlp_block", out.Decision, out.Result)
	}
	if len(out.Findings) == 0 {
		t.Error("no findings on a DLP block")
	}
	if len(fake.Requests()) != 0 {
		t.Error("blocked content reached the provider")
	}
	if len(ms.prompts) != 1 {
		t.Errorf("prompt records = %d, want 1 (audit keeps the blocked prompt)", len(ms.prompts))
	}
	if len(ms.receipts) != 1 {
		t.Errorf("receipts = %d, want 1 (denials get receipts too)", len(ms.receipts))
	}
	if len(ms.responses) != 0 || len(ms.usage) != 0 {
		t.Error("deny path must not write response/usage rows")
	}
}

func TestProcessChannelBlock(t *testing.T) {
	ms := &memStore{}
	fake := &provider.Fake{}
	h := newTestHandler(t, ms, fake)

	// Clean content, restricted workspace: the channel policy decides, not
	// the classifier.
	out := run(t, h, chatInput{Endpoint: "/v1/chat", Messages: userMsg("perfectly clean text"), Workspace: "restricted-rtl"})

	if out.Decision != "deny" || out.Result != "channel_block" {
		t.Fatalf("decision/result = %s/%s, want deny/channel_block", out.Decision, out.Result)
	}
	if len(fake.Requests()) != 0 {
		t.Error("restricted-workspace content reached the provider")
	}
	if len(ms.events) != 1 || ms.events[0].Result != "channel_block" {
		t.Errorf("events = %+v", ms.events)
	}
}

func TestProcessBudgetExceeded(t *testing.T) {
	ms := &memStore{monthlySpend: 26.00} // over the 25.00 compiled default
	h := newTestHandler(t, ms, &provider.Fake{})

	out := run(t, h, chatInput{Endpoint: "/v1/chat", Messages: userMsg("hi")})

	if out.Result != "budget_exceeded" || out.Decision != "deny" {
		t.Fatalf("result = %s/%s, want deny/budget_exceeded", out.Decision, out.Result)
	}
	if out.MonthlyCapUSD != 25.00 {
		t.Errorf("cap = %v, want 25.00", out.MonthlyCapUSD)
	}
}

func TestProcessPerTenantBudgetOverride(t *testing.T) {
	tight := 0.01
	ms := &memStore{monthlySpend: 0.02, tenantBudget: &tight}
	h := newTestHandler(t, ms, &provider.Fake{})
	if out := run(t, h, chatInput{Endpoint: "/v1/chat", Messages: userMsg("hi")}); out.Result != "budget_exceeded" {
		t.Errorf("tight override: result = %s, want budget_exceeded", out.Result)
	}

	roomy := 100.0
	ms2 := &memStore{monthlySpend: 26.00, tenantBudget: &roomy} // over default, under override
	h2 := newTestHandler(t, ms2, &provider.Fake{})
	if out := run(t, h2, chatInput{Endpoint: "/v1/chat", Messages: userMsg("hi")}); out.Result != "success" {
		t.Errorf("roomy override: result = %s, want success", out.Result)
	}
}

func TestProcessModelGovernance(t *testing.T) {
	ms := &memStore{}
	h := newTestHandler(t, ms, &provider.Fake{})

	// Unknown model, strict (native) caller → unknown_model.
	if out := run(t, h, chatInput{Endpoint: "/v1/chat", Messages: userMsg("hi"), RequestedModel: "gpt-4o"}); out.Result != "unknown_model" {
		t.Errorf("strict unknown model: result = %s, want unknown_model", out.Result)
	}
	// Unknown model, lenient (agent shim) → remapped to default, success.
	out := run(t, h, chatInput{Endpoint: "/v1/chat/completions", Messages: userMsg("hi"), RequestedModel: "gpt-4o", Lenient: true})
	if out.Result != "success" || out.Model != testModel || out.RequestedModel != "gpt-4o" {
		t.Errorf("lenient remap: result=%s model=%s requested=%s", out.Result, out.Model, out.RequestedModel)
	}
	// Premium tier gated by default.
	if out := run(t, h, chatInput{Endpoint: "/v1/chat", Messages: userMsg("hi"), RequestedModel: "anthropic.claude-opus-4-7"}); out.Result != "premium_gated" {
		t.Errorf("premium gate: result = %s, want premium_gated", out.Result)
	}
	// Admin allowlist: default model not in the set → model_disabled.
	h.EnabledModels = map[string]bool{"us.amazon.nova-lite-v1:0": true}
	if out := run(t, h, chatInput{Endpoint: "/v1/chat", Messages: userMsg("hi"), RequestedModel: testModel}); out.Result != "model_disabled" {
		t.Errorf("allowlist: result = %s, want model_disabled", out.Result)
	}
}

func TestProcessUpstreamError(t *testing.T) {
	ms := &memStore{}
	fake := &provider.Fake{Reply: func(provider.Request) (*provider.Response, error) {
		return nil, errors.New("backend on fire")
	}}
	h := newTestHandler(t, ms, fake)

	out := run(t, h, chatInput{Endpoint: "/v1/chat", Messages: userMsg("hi")})

	if out.Result != "upstream_error" {
		t.Fatalf("result = %s, want upstream_error", out.Result)
	}
	if len(ms.events) != 1 || ms.events[0].Result != "upstream_error" {
		t.Errorf("upstream error not audited: %+v", ms.events)
	}
	if ms.committed {
		t.Error("failed call must not commit a transaction")
	}
}

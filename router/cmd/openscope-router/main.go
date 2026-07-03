// openscope-router — the governed LLM proxy. Runs in the customer's own
// VPC; every agent/model call flows through auth → budget → DLP →
// provider → signed receipt.
//
// Endpoints:
//
//	POST /v1/scan             — DLP scan, no upstream call
//	POST /v1/chat             — native dialect (rich decision JSON)
//	POST /v1/chat/completions — OpenAI-compatible shim (Cursor, Codex CLI, …)
//	POST /v1/messages         — Anthropic-compatible shim (Claude Code, …)
//	GET  /health              — liveness
//
// Providers: AWS Bedrock (default; assume-role + external ID into the
// customer's bedrock account) or mock (OPENSCOPE_PROVIDER=mock — offline
// demos and deployment smoke tests).
package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/openscope/openscope/cpclient"
	"github.com/openscope/openscope/router/internal/bedrock"
	"github.com/openscope/openscope/router/internal/billing"
	"github.com/openscope/openscope/router/internal/dlp"
	"github.com/openscope/openscope/router/internal/provider"
	"github.com/openscope/openscope/router/internal/router"
	"github.com/openscope/openscope/router/internal/serverconfig"
	"github.com/openscope/openscope/router/internal/store"
	"github.com/openscope/openscope/router/internal/tenancy"
	"github.com/openscope/openscope/router/pkg/receipts"
)

// version is stamped by the release build:
//
//	go build -ldflags "-X main.version=v0.2.0"
var version = "dev"

func main() {
	cfg, err := serverconfig.Load()
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	if cfg.IsDevPepper() {
		log.Printf("WARNING: OPENSCOPE_AUTH_PEPPER is the dev placeholder. NEVER use this in production.")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	st, err := store.New(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("connect store: %v", err)
	}
	defer st.Close()
	log.Printf("connected to postgres (%s)", redactDSN(cfg.DatabaseURL))

	records := router.NewPGRecordStore(st)
	if cfg.AuditJSONLPath != "" {
		records = router.WithJSONLMirror(records, cfg.AuditJSONLPath)
		log.Printf("audit JSONL mirror enabled: %s", cfg.AuditJSONLPath)
	}

	resolver, err := tenancy.New(st, []byte(cfg.AuthPepper), cfg.TokenCacheTTL)
	if err != nil {
		log.Fatalf("init resolver: %v", err)
	}

	// DLP rules: built-in chip-design tiers, optionally extended/replaced
	// via a YAML ruleset. The ruleset hash is stamped onto every receipt.
	rules := dlp.DefaultRules
	if cfg.DLPRulesFile != "" {
		rules, err = dlp.LoadRulesFile(cfg.DLPRulesFile)
		if err != nil {
			log.Fatalf("load DLP rules: %v", err)
		}
	}
	scanner := dlp.NewScanner(rules)
	rulesetVersion := dlp.RulesetVersion(rules)
	log.Printf("DLP scanner loaded: %d rules (%s)", len(rules), rulesetVersion)

	// Model provider. nil → chat endpoints disabled, /v1/scan + /health
	// still served (DLP-only mode).
	invoker := buildProvider(ctx, cfg)

	// Control plane (strictly optional): metadata-only usage metering.
	// Unreachability never blocks customer traffic.
	cpCfg := cpclient.FromEnv(os.Getenv("OPENSCOPE_CP_SPOOL_PATH"))
	cp := cpclient.New(cpCfg)
	if cp != nil {
		defer cp.Close()
		log.Printf("control plane enabled: %s", cpCfg.BaseURL)
	}

	mux := http.NewServeMux()
	mux.Handle("POST /v1/scan", &router.ScanHandler{
		Resolver:       resolver,
		Scanner:        scanner,
		Store:          records,
		MaxUploadBytes: cfg.MaxUploadBytes,
	})
	mux.Handle("GET /health", router.HealthHandler{Version: version})

	if invoker != nil {
		signer, err := loadSigner(cfg)
		if err != nil {
			log.Fatalf("init receipt signer: %v", err)
		}
		log.Printf("receipt signer loaded (key_id=%s, public=%s…)",
			signer.PublicKeyID(), signer.PublicKeyBase64()[:16])

		restricted := map[string]bool{}
		for _, ws := range cfg.RestrictedWorkspaces {
			restricted[ws] = true
		}
		log.Printf("deny-by-default restricted workspaces: %v", cfg.RestrictedWorkspaces)

		chatHandler := &router.ChatHandler{
			Resolver:                resolver,
			Scanner:                 scanner,
			Store:                   records,
			Provider:                invoker,
			Signer:                  signer,
			DefaultModelID:          cfg.DefaultModelID,
			AllowPremiumTier:        cfg.AllowPremiumTier,
			MaxBodyBytes:            cfg.MaxUploadBytes,
			MaxTokensCeiling:        cfg.MaxTokensCeiling,
			DefaultMonthlyBudgetUSD: cfg.DefaultMonthlyBudgetUSD,
			PolicyVersion:           cfg.PolicyVersion,
			DLPRulesetVersion:       rulesetVersion,
			RestrictedWorkspaces:    restricted,
			EnabledModels:           billing.ParseEnabledSet(cfg.EnabledModels),
			Usage:                   cp.Record,
		}
		log.Printf("admin-enabled models: %d of %d catalog models", len(chatHandler.EnabledModels), len(billing.Catalog))
		mux.Handle("POST /v1/chat", chatHandler)
		// Agent-compatible shims over the same governed pipeline:
		//   /v1/chat/completions — OpenAI (Cursor, Codex CLI, Cline, Aider, Continue)
		//   /v1/messages         — Anthropic (Claude Code)
		mux.Handle("POST /v1/chat/completions", &router.CompletionsHandler{ChatHandler: chatHandler})
		mux.Handle("POST /v1/messages", &router.MessagesHandler{ChatHandler: chatHandler})
		log.Printf("POST /v1/chat, /v1/chat/completions, /v1/messages enabled (provider=%s default_model=%s allow_premium=%v)",
			invoker.Name(), cfg.DefaultModelID, cfg.AllowPremiumTier)
	}

	server := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       60 * time.Second, // chat can be slower than scan
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		log.Printf("openscope-router %s listening on %s", version, cfg.ListenAddr)
		var err error
		if cfg.TLSCertFile != "" {
			err = server.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile)
		} else {
			err = server.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			log.Fatalf("server error: %v", err)
		}
	}()

	<-sig
	log.Println("shutting down...")
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	_ = server.Shutdown(shutdownCtx)
}

// buildProvider selects the model backend. Returns nil when no backend is
// configured (router serves /v1/scan + /health only).
//
// Adding a provider (anthropic, openai, azure): implement provider.Invoker,
// add a case here and to serverconfig's Provider validation.
func buildProvider(ctx context.Context, cfg serverconfig.Config) provider.Invoker {
	switch cfg.Provider {
	case "mock":
		log.Printf("provider: mock (in-process; no external model calls)")
		return &provider.Fake{}
	case "bedrock":
		if cfg.BedrockInvokeRoleArn == "" || cfg.BedrockExternalID == "" {
			log.Printf("Bedrock not configured (OPENSCOPE_BEDROCK_INVOKE_ROLE_ARN / _EXTERNAL_ID unset); /v1/chat disabled")
			return nil
		}
		client, err := bedrock.New(ctx, bedrock.Config{
			Region:        cfg.BedrockRegion,
			InvokeRoleArn: cfg.BedrockInvokeRoleArn,
			ExternalID:    cfg.BedrockExternalID,
		})
		if err != nil {
			log.Fatalf("init bedrock client: %v", err)
		}
		log.Printf("provider: AWS Bedrock (region=%s, role=%s)", cfg.BedrockRegion, cfg.BedrockInvokeRoleArn)
		return client
	}
	return nil
}

// loadSigner builds the Ed25519 receipt signer. ReceiptPrivateKey accepts
// hex or base64; empty generates a fixed dev key with a loud warning —
// production must set OPENSCOPE_RECEIPT_PRIVATE_KEY.
func loadSigner(cfg serverconfig.Config) (*receipts.Signer, error) {
	raw := strings.TrimSpace(cfg.ReceiptPrivateKey)
	if raw == "" {
		if !serverconfig.DevMode() {
			return nil, fmt.Errorf("OPENSCOPE_RECEIPT_PRIVATE_KEY is required; set a 32-byte Ed25519 seed, or OPENSCOPE_DEV=1 for local development")
		}
		log.Printf("WARNING: no OPENSCOPE_RECEIPT_PRIVATE_KEY set; using a fixed dev key. NEVER use this in production.")
		seed := []byte("openscope-dev-ephemeral-key-32bb") // exactly 32 bytes
		return receipts.NewSigner(seed[:32], cfg.ReceiptPublicKeyID)
	}
	if bs, err := hex.DecodeString(raw); err == nil {
		return receipts.NewSigner(bs, cfg.ReceiptPublicKeyID)
	}
	bs, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, err
	}
	return receipts.NewSigner(bs, cfg.ReceiptPublicKeyID)
}

func redactDSN(dsn string) string {
	atIdx := strings.LastIndex(dsn, "@")
	if atIdx < 0 {
		return dsn
	}
	colon := strings.LastIndex(dsn[:atIdx], ":")
	if colon < 0 {
		return dsn
	}
	return dsn[:colon+1] + "***" + dsn[atIdx:]
}

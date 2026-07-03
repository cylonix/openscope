// Package serverconfig loads env-driven configuration for openscope-router
// and openscope-console. Every knob the two binaries read from the
// environment is declared here — the mains contain no raw os.Getenv calls.
package serverconfig

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	// HTTP listen — default ":8080" for local dev.
	ListenAddr string

	// ConsoleListenAddr is openscope-console's listen address (":8081").
	ConsoleListenAddr string

	// Postgres DSN — required. Local dev:
	//   postgres://app_rw:dev_app_rw_password@127.0.0.1:5432/openscope?sslmode=disable
	DatabaseURL string

	// Role-scoped console DSNs. The privacy boundary lives at the Postgres
	// GRANT layer: vendor_reader cannot SELECT sensitive.*.
	TenantReaderDSN string
	VendorReaderDSN string
	AdminDSN        string

	// AuthPepper is the HMAC-SHA256 key used to hash API tokens before
	// comparing against app.api_keys.key_hash. Must match what's used to
	// mint keys via the seed script or the admin endpoint. Production:
	// load from a secrets store. Dev default is a fixed string and will
	// log a loud warning at startup.
	AuthPepper string

	// LogLevel: debug|info|warn|error. Default info.
	LogLevel string

	// TokenCacheTTL: how long to remember a resolved token in memory.
	TokenCacheTTL time.Duration

	// MaxUploadBytes: upper bound on /v1/scan file uploads and chat bodies.
	MaxUploadBytes int64

	// MaxTokensCeiling bounds per-request max_tokens on /v1/chat.
	MaxTokensCeiling int

	// DefaultModelID is what /v1/chat uses when the request doesn't specify.
	DefaultModelID string

	// AllowPremiumTier — gate for premium-tier models. When false, /v1/chat
	// rejects requests for premium-tier models even if listed in catalog.
	AllowPremiumTier bool

	// Provider selects the LLM backend: "bedrock" (default) or "mock"
	// (in-process fake for offline demos and deployment smoke tests).
	Provider string

	// Bedrock backend. InvokeRoleArn + ExternalID are required for the
	// bedrock provider; when unset the router serves /v1/scan + /health
	// only. Region falls back to AWS_REGION, then us-west-2.
	BedrockInvokeRoleArn string
	BedrockExternalID    string
	BedrockRegion        string

	// Receipt signing. PrivateKey is the Ed25519 seed/private key as hex or
	// base64; empty → ephemeral dev key with a loud warning.
	ReceiptPrivateKey  string
	ReceiptPublicKeyID string

	// RestrictedWorkspaces are deny-by-default channels (comma-separated):
	// requests tagged with one of these workspaces never reach a model.
	RestrictedWorkspaces []string

	// EnabledModels is the admin's model allowlist (comma-separated catalog
	// IDs). Empty → the catalog's default enabled set.
	EnabledModels string

	// DefaultMonthlyBudgetUSD is the deployment-wide soft cap for tenants
	// without an app.tenants.monthly_budget_usd override. 0 → the compiled
	// default (billing.DefaultMonthlyBudgetUSD).
	DefaultMonthlyBudgetUSD float64

	// DLPRulesFile points at an optional YAML ruleset
	// (see configs/dlp.example.yaml). Empty → built-in rules.
	DLPRulesFile string

	// PolicyVersion is an operator-set label stamped onto receipts so an
	// auditor can tie decisions to a policy revision ("2026-06-it-policy-3").
	PolicyVersion string

	// AuditJSONLPath, when set, mirrors every router event to an
	// ascope-format audit JSONL file alongside the canonical Postgres row.
	AuditJSONLPath string

	// TLS for the router/console listeners. Empty → plaintext (terminate
	// TLS at a reverse proxy instead).
	TLSCertFile string
	TLSKeyFile  string

	// Console session + admin auth.
	SessionSecret      string
	AdminToken         string
	DevInsecureCookies bool

	// BodyRetentionMinutes controls auto-purge of sensitive.* bodies
	// (prompts/responses/uploads). 0 = keep forever (the product default —
	// retention is the customer's call); >0 = purge rows older than N
	// minutes and wipe all bodies at boot (the hosted-demo posture).
	BodyRetentionMinutes int
}

const DevPepperPlaceholder = "DEV-PEPPER-CHANGE-ME-32-BYTES-OF-DEV"

func Load() (Config, error) {
	bedrockRegion := envOr("OPENSCOPE_BEDROCK_REGION", os.Getenv("AWS_REGION"))
	if bedrockRegion == "" {
		bedrockRegion = "us-west-2"
	}
	cfg := Config{
		ListenAddr:        envOr("OPENSCOPE_ROUTER_LISTEN", ":8080"),
		ConsoleListenAddr: envOr("OPENSCOPE_CONSOLE_LISTEN", ":8081"),
		DatabaseURL:       envOr("OPENSCOPE_DATABASE_URL", "postgres://app_rw:dev_app_rw_password@127.0.0.1:5432/openscope?sslmode=disable"),
		TenantReaderDSN: envOr("OPENSCOPE_TENANT_READER_DSN",
			"postgres://tenant_reader:dev_tenant_reader_password@127.0.0.1:5432/openscope?sslmode=disable"),
		VendorReaderDSN: envOr("OPENSCOPE_VENDOR_READER_DSN",
			"postgres://vendor_reader:dev_vendor_reader_password@127.0.0.1:5432/openscope?sslmode=disable"),
		AdminDSN: envOr("OPENSCOPE_ADMIN_DSN",
			"postgres://openscope_admin:dev_admin_password@127.0.0.1:5432/openscope?sslmode=disable"),
		AuthPepper:       envOr("OPENSCOPE_AUTH_PEPPER", DevPepperPlaceholder),
		LogLevel:         envOr("OPENSCOPE_LOG_LEVEL", "info"),
		TokenCacheTTL:    envDurationOr("OPENSCOPE_TOKEN_CACHE_TTL", 60*time.Second),
		MaxUploadBytes:   envInt64Or("OPENSCOPE_MAX_UPLOAD_BYTES", 10<<20), // 10 MB
		MaxTokensCeiling: int(envInt64Or("OPENSCOPE_MAX_TOKENS_CEILING", 4096)),
		// Default to nova-micro for dev cheapness. Production deploys
		// override via OPENSCOPE_DEFAULT_MODEL_ID=us.anthropic.claude-haiku-4-5-...
		DefaultModelID:          envOr("OPENSCOPE_DEFAULT_MODEL_ID", "us.amazon.nova-micro-v1:0"),
		AllowPremiumTier:        envBoolOr("OPENSCOPE_ALLOW_PREMIUM_TIER", false),
		Provider:                envOr("OPENSCOPE_PROVIDER", "bedrock"),
		BedrockInvokeRoleArn:    os.Getenv("OPENSCOPE_BEDROCK_INVOKE_ROLE_ARN"),
		BedrockExternalID:       os.Getenv("OPENSCOPE_BEDROCK_EXTERNAL_ID"),
		BedrockRegion:           bedrockRegion,
		ReceiptPrivateKey:       os.Getenv("OPENSCOPE_RECEIPT_PRIVATE_KEY"),
		ReceiptPublicKeyID:      envOr("OPENSCOPE_RECEIPT_PUBLIC_KEY_ID", "dev-ephemeral"),
		RestrictedWorkspaces:    splitCSV(os.Getenv("OPENSCOPE_RESTRICTED_WORKSPACES")),
		EnabledModels:           os.Getenv("OPENSCOPE_ENABLED_MODELS"),
		DefaultMonthlyBudgetUSD: envFloatOr("OPENSCOPE_DEFAULT_MONTHLY_BUDGET_USD", 0),
		DLPRulesFile:            os.Getenv("OPENSCOPE_DLP_RULES_FILE"),
		PolicyVersion:           os.Getenv("OPENSCOPE_POLICY_VERSION"),
		AuditJSONLPath:          os.Getenv("OPENSCOPE_AUDIT_JSONL_PATH"),
		TLSCertFile:             os.Getenv("OPENSCOPE_TLS_CERT_FILE"),
		TLSKeyFile:              os.Getenv("OPENSCOPE_TLS_KEY_FILE"),
		SessionSecret:           os.Getenv("OPENSCOPE_SESSION_SECRET"),
		AdminToken:              os.Getenv("OPENSCOPE_ADMIN_TOKEN"),
		DevInsecureCookies:      envBoolOr("OPENSCOPE_DEV_INSECURE_COOKIES", true),
		BodyRetentionMinutes:    bodyRetentionMinutes(),
	}
	if cfg.DatabaseURL == "" {
		return cfg, fmt.Errorf("OPENSCOPE_DATABASE_URL is required")
	}
	if cfg.AuthPepper == "" {
		return cfg, fmt.Errorf("OPENSCOPE_AUTH_PEPPER is required")
	}
	if cfg.IsDevPepper() && !DevMode() {
		return cfg, fmt.Errorf("OPENSCOPE_AUTH_PEPPER is unset (falling back to the public dev placeholder); set a real 32+ byte key, or OPENSCOPE_DEV=1 for local development")
	}
	if (cfg.TLSCertFile == "") != (cfg.TLSKeyFile == "") {
		return cfg, fmt.Errorf("OPENSCOPE_TLS_CERT_FILE and OPENSCOPE_TLS_KEY_FILE must be set together")
	}
	switch cfg.Provider {
	case "bedrock", "mock":
	default:
		return cfg, fmt.Errorf("OPENSCOPE_PROVIDER must be \"bedrock\" or \"mock\", got %q", cfg.Provider)
	}
	return cfg, nil
}

// bodyRetentionMinutes reads OPENSCOPE_BODY_RETENTION_MINUTES with a
// fallback to the legacy demo name OPENSCOPE_DEMO_BODY_TTL_MINUTES. The
// product default is 0 (keep bodies — retention is the customer's call);
// the hosted demo sets 60.
func bodyRetentionMinutes() int {
	if v := os.Getenv("OPENSCOPE_BODY_RETENTION_MINUTES"); v != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
			return n
		}
	}
	if v := os.Getenv("OPENSCOPE_DEMO_BODY_TTL_MINUTES"); v != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
			return n
		}
	}
	return 0
}

// IsDevPepper reports whether the loaded pepper is the unsafe default.
// main.go logs a warning when this is true.
func (c Config) IsDevPepper() bool { return c.AuthPepper == DevPepperPlaceholder }

// DevMode reports whether OPENSCOPE_DEV is set. It gates the insecure dev-only
// fallbacks (publicly-known placeholder secrets: session key, admin token,
// receipt seed, auth pepper) that would otherwise be fatal at startup. Never
// set OPENSCOPE_DEV in production — a known secret is a full auth/receipt
// bypass.
func DevMode() bool { return envBoolOr("OPENSCOPE_DEV", false) }

func splitCSV(raw string) []string {
	var out []string
	for _, part := range strings.Split(raw, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt64Or(key string, def int64) int64 {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return def
	}
	return n
}

func envFloatOr(key string, def float64) float64 {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return def
	}
	return f
}

func envBoolOr(key string, def bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}
	return b
}

func envDurationOr(key string, def time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return def
	}
	return d
}

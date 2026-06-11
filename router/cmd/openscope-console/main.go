// openscope-console — read API for the dashboards.
//
// Runs alongside openscope-router (which handles /v1/scan + /v1/chat).
// The console connects to Postgres with three role-scoped pools and
// serves dashboard endpoints under /api/v1/*. The privacy boundary lives
// at the Postgres GRANT layer: engineer-session queries against
// sensitive.* are refused by the database engine, not the application.
//
// Endpoints (Stage 5):
//
//	POST /api/v1/session                       — paste token → cookie
//	POST /api/v1/logout                        — clear cookie
//	GET  /api/v1/me                            — whoami
//	GET  /api/v1/events                        — router_events (tenant-scoped)
//	GET  /api/v1/usage                         — monthly usage + spend
//	GET  /api/v1/prompts                       — sensitive prompts (developer/it only)
//	GET  /api/v1/receipts                      — signed receipts (developer/it)
//	GET  /api/v1/vendor/usage                  — vendor cross-tenant aggregates (engineer)
//	POST /api/v1/vendor/verify_no_prompt_access — demo proof: postgres refuses
//	GET  /api/v1/health                        — liveness
package main

import (
	"context"
	"encoding/base64"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/openscope/openscope/router/internal/billing"
	"github.com/openscope/openscope/router/internal/console"
	"github.com/openscope/openscope/router/internal/serverconfig"
	"github.com/openscope/openscope/router/internal/store"
	"github.com/openscope/openscope/router/internal/tenancy"
)

func main() {
	// Re-use serverconfig for the shared env keys (DB URL is app_rw — but
	// the console uses three separate role-scoped DSNs from its own env).
	routerCfg, err := serverconfig.Load()
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	listen := routerCfg.ConsoleListenAddr
	tenantDSN := routerCfg.TenantReaderDSN
	vendorDSN := routerCfg.VendorReaderDSN
	adminDSN := routerCfg.AdminDSN

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Token resolver — reuses the router's tenancy package. The console
	// resolver connects to Postgres as app_rw to query app.api_keys.
	st, err := store.New(ctx, routerCfg.DatabaseURL)
	if err != nil {
		log.Fatalf("connect store (app_rw): %v", err)
	}
	defer st.Close()

	resolver, err := tenancy.New(st, []byte(routerCfg.AuthPepper), routerCfg.TokenCacheTTL)
	if err != nil {
		log.Fatalf("init resolver: %v", err)
	}

	read, err := console.NewReadStore(ctx, console.PoolConfig{
		TenantDSN: tenantDSN,
		VendorDSN: vendorDSN,
		AdminDSN:  adminDSN,
	})
	if err != nil {
		log.Fatalf("init read store: %v", err)
	}
	defer read.Close()
	log.Printf("3 pgxpools ready: tenant_reader / vendor_reader / openscope_admin")

	// Session secret. Dev default is a 32-byte all-zero key with a loud
	// warning — production sets OPENSCOPE_SESSION_SECRET from a secrets
	// manager.
	sessionSecret, err := loadSessionSecret(routerCfg.SessionSecret)
	if err != nil {
		log.Fatalf("session secret: %v", err)
	}
	sessions, err := console.NewManager(sessionSecret)
	if err != nil {
		log.Fatalf("init session manager: %v", err)
	}

	srv := &console.Server{
		Resolver:                resolver,
		Sessions:                sessions,
		Read:                    read,
		DevInsecure:             routerCfg.DevInsecureCookies,
		Region:                  routerCfg.BedrockRegion,
		EnabledModels:           billing.ParseEnabledSet(routerCfg.EnabledModels),
		DefaultMonthlyBudgetUSD: routerCfg.DefaultMonthlyBudgetUSD,
	}

	mux := http.NewServeMux()
	srv.Routes(mux)

	// Admin endpoints — gated by OPENSCOPE_ADMIN_TOKEN. The founder uses
	// these to mint demo keys for prospects.
	adminToken := routerCfg.AdminToken
	if adminToken == "" {
		adminToken = "dev-admin-token-change-me"
		log.Printf("WARNING: OPENSCOPE_ADMIN_TOKEN not set; using dev placeholder. NEVER use this in production.")
	}
	adm := &console.AdminServer{
		Token:      console.AdminToken(adminToken),
		Read:       read,
		AuthPepper: []byte(routerCfg.AuthPepper),
	}
	adm.Routes(mux)

	// Body retention: prompt/response/upload content in sensitive.* is
	// auto-purged after OPENSCOPE_BODY_RETENTION_MINUTES (legacy alias:
	// OPENSCOPE_DEMO_BODY_TTL_MINUTES). Metadata (events, receipts, usage)
	// is always retained. The product default is 0 — keep bodies; retention
	// is the customer's call. The hosted demo sets 60.
	if ttlMin := routerCfg.BodyRetentionMinutes; ttlMin > 0 {
		ttl := time.Duration(ttlMin) * time.Minute
		// One-time wipe at boot clears anything captured before retention
		// existed, so the demo starts from a clean slate.
		if n, err := read.PurgeAllBodies(context.Background()); err != nil {
			log.Printf("body retention purge (boot wipe): %v", err)
		} else if n > 0 {
			log.Printf("body retention purge (boot wipe): removed %d existing body rows", n)
		}
		go func() {
			t := time.NewTicker(10 * time.Minute)
			defer t.Stop()
			for range t.C {
				if n, err := read.PurgeExpiredBodies(context.Background(), ttl); err != nil {
					log.Printf("body retention purge: %v", err)
				} else if n > 0 {
					log.Printf("body retention purge: removed %d expired body rows (ttl=%dm)", n, ttlMin)
				}
			}
		}()
		log.Printf("body retention: %d min (sensitive.* bodies auto-purged; metadata retained)", ttlMin)
	}
	log.Printf("admin endpoints mounted at /api/v1/admin/*")

	httpSrv := &http.Server{
		Addr:              listen,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		log.Printf("openscope-console listening on %s", listen)
		var err error
		if routerCfg.TLSCertFile != "" {
			err = httpSrv.ListenAndServeTLS(routerCfg.TLSCertFile, routerCfg.TLSKeyFile)
		} else {
			err = httpSrv.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			log.Fatalf("server error: %v", err)
		}
	}()

	<-sig
	log.Println("shutting down...")
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	_ = httpSrv.Shutdown(shutdownCtx)
}

func loadSessionSecret(raw string) ([]byte, error) {
	if raw == "" {
		log.Printf("WARNING: OPENSCOPE_SESSION_SECRET not set; using a deterministic dev secret. NEVER use this in production.")
		// 32 bytes of dev-only material (deterministic so sessions survive restarts during dev).
		return []byte("openscope-dev--session-secret-32"), nil
	}
	// Try base64, then hex, then raw.
	if b, err := base64.StdEncoding.DecodeString(raw); err == nil && len(b) >= 32 {
		return b, nil
	}
	if b, err := decodeHex(raw); err == nil && len(b) >= 32 {
		return b, nil
	}
	return []byte(raw), nil
}

func decodeHex(s string) ([]byte, error) {
	out := make([]byte, len(s)/2)
	for i := 0; i < len(out); i++ {
		var hi, lo byte
		c1, c2 := s[i*2], s[i*2+1]
		hi = unhexByte(c1)
		lo = unhexByte(c2)
		out[i] = hi<<4 | lo
	}
	return out, nil
}

func unhexByte(c byte) byte {
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

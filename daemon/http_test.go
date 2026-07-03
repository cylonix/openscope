// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package daemon

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openscope/openscope/authtoken"
	"github.com/openscope/openscope/config"
	"github.com/openscope/openscope/executor"
	"github.com/openscope/openscope/ipc"
)

func testPaths(t *testing.T) config.Paths {
	t.Helper()
	home := t.TempDir()
	paths := config.Paths{
		ConfigDir:            filepath.Join(home, ".openscope"),
		AppsDir:              filepath.Join(home, ".openscope", "apps.d"),
		RunDir:               filepath.Join(home, ".openscope", "run"),
		StateDir:             filepath.Join(home, ".openscope", "state"),
		PoliciesFile:         filepath.Join(home, ".openscope", "policies.yaml"),
		AgentsFile:           filepath.Join(home, ".openscope", "agents.yaml"),
		AuditFile:            filepath.Join(home, ".openscope", "audit.jsonl"),
		EnabledAppsFile:      filepath.Join(home, ".openscope", "state", "enabled_apps.yaml"),
		SocketPath:           filepath.Join(home, ".openscope", "run", "openscoped.sock"),
		AdminDir:             filepath.Join(home, "admin"),
		ProtectedFoldersFile: filepath.Join(home, "admin", "protected_folders.yaml"),
		MailFiltersFile:      filepath.Join(home, "admin", "mail_filters.yaml"),
		AgentTokensFile:      filepath.Join(home, ".openscope", "agent_tokens.yaml"),
		TokenPepperFile:      filepath.Join(home, ".openscope", "token_pepper"),
	}
	if err := config.EnsureLayout(paths); err != nil {
		t.Fatalf("EnsureLayout: %v", err)
	}
	return paths
}

// newHTTPFixture builds an HTTPServer over a Service with a stub executor
// and one registered agent "demo" with a minted token.
func newHTTPFixture(t *testing.T, allowAnon bool) (*httptest.Server, string, config.Paths) {
	t.Helper()
	paths := testPaths(t)

	writeFile(t, paths.AgentsFile, "version: 1\nagents:\n  - demo\n")
	writeFile(t, paths.PoliciesFile, "version: 1\nrules:\n  - effect: allow\n    agent: demo\n    app: notes\n    action: read_note\n")

	service := NewService(paths)
	service.Executors["applescript"] = stubExecutor{
		result: executor.Result{Stdout: "{\"title\":\"Sprint Plan\"}"},
	}

	pepper, err := authtoken.LoadPepper("", paths.TokenPepperFile)
	if err != nil {
		t.Fatalf("LoadPepper: %v", err)
	}
	store := &authtoken.FileStore{Path: paths.AgentTokensFile, Pepper: pepper}
	token, err := store.Mint("demo", false)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	hs := &HTTPServer{
		Service:      service,
		Tokens:       store,
		AllowAnon:    allowAnon,
		MaxBodyBytes: 1 << 20,
		Limiter:      newRateLimiter(100, 100),
	}
	srv := httptest.NewTLSServer(hs.Handler())
	t.Cleanup(srv.Close)
	return srv, token, paths
}

func postAction(t *testing.T, srv *httptest.Server, token string, request ipc.Request) (*http.Response, ipc.Response) {
	t.Helper()
	payload, _ := json.Marshal(request)
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/v1/actions", bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	var decoded ipc.Response
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return resp, decoded
}

func auditLines(t *testing.T, paths config.Paths) []map[string]any {
	t.Helper()
	data, err := os.ReadFile(paths.AuditFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatal(err)
	}
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("bad audit line %q: %v", line, err)
		}
		out = append(out, m)
	}
	return out
}

func validRequest() ipc.Request {
	return ipc.Request{App: "notes", Action: "read_note", Params: map[string]string{"folder": "Work", "note": "Sprint Plan"}, Mode: "json"}
}

func TestHTTPMissingTokenRejected(t *testing.T) {
	srv, _, paths := newHTTPFixture(t, false)

	resp, decoded := postAction(t, srv, "", validRequest())
	if resp.StatusCode != http.StatusForbidden || decoded.ExitCode != ExitDenied {
		t.Fatalf("status=%d exit=%d, want 403/%d", resp.StatusCode, decoded.ExitCode, ExitDenied)
	}
	lines := auditLines(t, paths)
	if len(lines) != 1 || lines[0]["result"] != "missing_token" || lines[0]["transport"] != "http" {
		t.Errorf("audit = %v", lines)
	}
}

func TestHTTPBadTokenRejected(t *testing.T) {
	srv, _, paths := newHTTPFixture(t, false)

	resp, _ := postAction(t, srv, "osk_agent_AAAAAAAAAAAAAAAAAAAAAA", validRequest())
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	lines := auditLines(t, paths)
	if len(lines) != 1 || lines[0]["result"] != "invalid_token" {
		t.Errorf("audit = %v", lines)
	}
	// The audit row records the prefix only, never a full token.
	if prefix, _ := lines[0]["token_prefix"].(string); prefix != "osk_agent_AA" {
		t.Errorf("token_prefix = %q", prefix)
	}
}

func TestHTTPValidTokenFillsAgentIdentity(t *testing.T) {
	srv, token, paths := newHTTPFixture(t, false)

	// Agent field deliberately empty: the daemon must derive it from the token.
	resp, decoded := postAction(t, srv, token, validRequest())
	if resp.StatusCode != http.StatusOK || !decoded.OK {
		t.Fatalf("status=%d ok=%v err=%s", resp.StatusCode, decoded.OK, decoded.Error)
	}
	if decoded.Agent != "demo" {
		t.Errorf("agent = %q, want demo (derived from token)", decoded.Agent)
	}
	if resp.Header.Get("X-Request-Id") == "" {
		t.Error("missing X-Request-Id header")
	}
	lines := auditLines(t, paths)
	if len(lines) != 1 || lines[0]["agent"] != "demo" || lines[0]["result"] != "success" {
		t.Fatalf("audit = %v", lines)
	}
	if lines[0]["request_id"] == "" || lines[0]["transport"] != "http" || lines[0]["remote_addr"] == "" {
		t.Errorf("missing transport metadata: %v", lines[0])
	}
}

func TestHTTPAgentMismatchRejected(t *testing.T) {
	srv, token, paths := newHTTPFixture(t, false)

	request := validRequest()
	request.Agent = "someone-else"
	resp, decoded := postAction(t, srv, token, request)
	if resp.StatusCode != http.StatusForbidden || decoded.ExitCode != ExitDenied {
		t.Fatalf("status=%d exit=%d, want 403/%d", resp.StatusCode, decoded.ExitCode, ExitDenied)
	}
	lines := auditLines(t, paths)
	if len(lines) != 1 || lines[0]["result"] != "agent_token_mismatch" {
		t.Errorf("audit = %v", lines)
	}
}

func TestHTTPMatchingAgentAccepted(t *testing.T) {
	srv, token, _ := newHTTPFixture(t, false)

	request := validRequest()
	request.Agent = "demo" // explicitly set and matching the token
	resp, decoded := postAction(t, srv, token, request)
	if resp.StatusCode != http.StatusOK || !decoded.OK {
		t.Fatalf("status=%d ok=%v err=%s", resp.StatusCode, decoded.OK, decoded.Error)
	}
}

func TestHTTPAnonModeUsesRequestAgent(t *testing.T) {
	srv, _, _ := newHTTPFixture(t, true)

	request := validRequest()
	request.Agent = "demo"
	resp, decoded := postAction(t, srv, "", request)
	if resp.StatusCode != http.StatusOK || !decoded.OK {
		t.Fatalf("anon mode: status=%d ok=%v err=%s", resp.StatusCode, decoded.OK, decoded.Error)
	}
}

func TestHTTPRevokedTokenRejected(t *testing.T) {
	srv, token, paths := newHTTPFixture(t, false)

	pepper, _ := authtoken.LoadPepper("", paths.TokenPepperFile)
	store := &authtoken.FileStore{Path: paths.AgentTokensFile, Pepper: pepper}
	if _, err := store.Revoke("demo"); err != nil {
		t.Fatal(err)
	}
	resp, _ := postAction(t, srv, token, validRequest())
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("revoked token: status = %d, want 403", resp.StatusCode)
	}
}

func TestHTTPBodyTooLargeRejected(t *testing.T) {
	srv, token, _ := newHTTPFixture(t, false)

	request := validRequest()
	request.Params["note"] = strings.Repeat("x", 2<<20) // 2 MiB > 1 MiB cap
	resp, decoded := postAction(t, srv, token, request)
	if resp.StatusCode != http.StatusBadRequest || decoded.ExitCode != ExitInvalid {
		t.Fatalf("status=%d exit=%d, want 400/%d", resp.StatusCode, decoded.ExitCode, ExitInvalid)
	}
}

func TestHTTPRateLimit(t *testing.T) {
	srv, token, _ := newHTTPFixture(t, false)

	// A second server with a tight limiter (1/s, burst 2).
	hsSrv, tightToken, _ := func() (*httptest.Server, string, config.Paths) {
		paths := testPaths(t)
		writeFile(t, paths.AgentsFile, "version: 1\nagents:\n  - demo\n")
		writeFile(t, paths.PoliciesFile, "version: 1\nrules:\n  - effect: allow\n    agent: demo\n    app: notes\n    action: read_note\n")
		service := NewService(paths)
		service.Executors["applescript"] = stubExecutor{result: executor.Result{Stdout: "{}"}}
		pepper, _ := authtoken.LoadPepper("", paths.TokenPepperFile)
		store := &authtoken.FileStore{Path: paths.AgentTokensFile, Pepper: pepper}
		token, _ := store.Mint("demo", false)
		hs := &HTTPServer{Service: service, Tokens: store, MaxBodyBytes: 1 << 20, Limiter: newRateLimiter(1, 2)}
		s := httptest.NewTLSServer(hs.Handler())
		t.Cleanup(s.Close)
		return s, token, paths
	}()

	// Burst of 2 allowed, third must be limited.
	for i := range 2 {
		if resp, _ := postAction(t, hsSrv, tightToken, validRequest()); resp.StatusCode != http.StatusOK {
			t.Fatalf("request %d: status = %d, want 200", i, resp.StatusCode)
		}
	}
	resp, decoded := postAction(t, hsSrv, tightToken, validRequest())
	if resp.StatusCode != http.StatusTooManyRequests || decoded.ExitCode != ExitRateLimited {
		t.Fatalf("status=%d exit=%d, want 429/%d", resp.StatusCode, decoded.ExitCode, ExitRateLimited)
	}

	// The generous fixture server is unaffected.
	if resp, _ := postAction(t, srv, token, validRequest()); resp.StatusCode != http.StatusOK {
		t.Errorf("generous server rate-limited unexpectedly: %d", resp.StatusCode)
	}
}

func TestHTTPRateLimitPreAuth(t *testing.T) {
	// Invalid/unauthenticated requests must be throttled BEFORE the token-store
	// read and audit write, so a flood of bad tokens cannot force unbounded I/O.
	paths := testPaths(t)
	writeFile(t, paths.AgentsFile, "version: 1\nagents:\n  - demo\n")
	service := NewService(paths)
	pepper, _ := authtoken.LoadPepper("", paths.TokenPepperFile)
	store := &authtoken.FileStore{Path: paths.AgentTokensFile, Pepper: pepper}
	hs := &HTTPServer{Service: service, Tokens: store, MaxBodyBytes: 1 << 20, Limiter: newRateLimiter(1, 2)}
	s := httptest.NewTLSServer(hs.Handler())
	t.Cleanup(s.Close)

	// Burst 2: the first two bad-token attempts reach the auth check and are
	// denied; the third is shed by the pre-auth IP throttle with 429, not denied.
	for i := range 2 {
		resp, decoded := postAction(t, s, "osk_bogus_token", validRequest())
		if resp.StatusCode == http.StatusTooManyRequests {
			t.Fatalf("attempt %d throttled too early", i)
		}
		if decoded.ExitCode != ExitDenied {
			t.Fatalf("attempt %d: exit=%d, want denied", i, decoded.ExitCode)
		}
	}
	resp, decoded := postAction(t, s, "osk_bogus_token", validRequest())
	if resp.StatusCode != http.StatusTooManyRequests || decoded.ExitCode != ExitRateLimited {
		t.Fatalf("status=%d exit=%d, want 429/%d (pre-auth throttle)", resp.StatusCode, decoded.ExitCode, ExitRateLimited)
	}
}

func TestHTTPHealthzOpen(t *testing.T) {
	srv, _, _ := newHTTPFixture(t, false)
	resp, err := srv.Client().Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz status = %d", resp.StatusCode)
	}
}

func TestValidateHTTPConfig(t *testing.T) {
	cases := []struct {
		name  string
		paths config.Paths
		ok    bool
	}{
		{"no listener", config.Paths{}, true},
		{"loopback plaintext", config.Paths{HTTPListenAddr: "127.0.0.1:9999"}, true},
		{"localhost plaintext", config.Paths{HTTPListenAddr: "localhost:9999"}, true},
		{"public plaintext", config.Paths{HTTPListenAddr: "0.0.0.0:9999"}, false},
		{"all-interfaces shorthand", config.Paths{HTTPListenAddr: ":9999"}, false},
		{"public with TLS", config.Paths{HTTPListenAddr: "0.0.0.0:9999", HTTPTLSCertFile: "c", HTTPTLSKeyFile: "k"}, true},
		{"public plaintext, proxy ack", config.Paths{HTTPListenAddr: "0.0.0.0:9999", HTTPPlaintextOK: true}, true},
		{"cert without key", config.Paths{HTTPListenAddr: "127.0.0.1:9999", HTTPTLSCertFile: "c"}, false},
		{"anon on loopback", config.Paths{HTTPListenAddr: "127.0.0.1:9999", HTTPAllowAnon: true}, true},
		{"anon on public", config.Paths{HTTPListenAddr: "0.0.0.0:9999", HTTPAllowAnon: true, HTTPTLSCertFile: "c", HTTPTLSKeyFile: "k"}, false},
	}
	for _, tc := range cases {
		err := ValidateHTTPConfig(tc.paths)
		if (err == nil) != tc.ok {
			t.Errorf("%s: err = %v, want ok=%v", tc.name, err, tc.ok)
		}
	}
}

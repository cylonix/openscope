// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package daemon

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openscope/openscope/authtoken"
	"github.com/openscope/openscope/config"
	"github.com/openscope/openscope/executor"
	"github.com/openscope/openscope/ipc"
)

// newProxyFixture builds an HTTPServer with trusted-proxy support and the given
// policy. The acting agent "claude-code" and a proxy agent "sso-proxy" are both
// registered; user identity comes from the X-Forwarded-Email header.
func newProxyFixture(t *testing.T, trustProxy bool, policyYAML string) (*httptest.Server, config.Paths, *authtoken.FileStore) {
	t.Helper()
	paths := testPaths(t)
	writeFile(t, paths.AgentsFile, "version: 1\nagents:\n  - claude-code\n  - sso-proxy\n  - demo\n")
	writeFile(t, paths.PoliciesFile, policyYAML)

	service := NewService(paths)
	service.Executors["applescript"] = stubExecutor{result: executor.Result{Stdout: "{\"title\":\"Sprint Plan\"}"}}

	pepper, err := authtoken.LoadPepper("", paths.TokenPepperFile)
	if err != nil {
		t.Fatalf("LoadPepper: %v", err)
	}
	store := &authtoken.FileStore{Path: paths.AgentTokensFile, Pepper: pepper}

	hs := &HTTPServer{
		Service:           service,
		Tokens:            store,
		MaxBodyBytes:      1 << 20,
		Limiter:           newRateLimiter(100, 100),
		TrustProxy:        trustProxy,
		ProxyUserHeader:   "X-Forwarded-Email",
		ProxyGroupsHeader: "X-Forwarded-Groups",
	}
	srv := httptest.NewTLSServer(hs.Handler())
	t.Cleanup(srv.Close)
	return srv, paths, store
}

func postWithHeaders(t *testing.T, srv *httptest.Server, token string, headers map[string]string, request ipc.Request) (*http.Response, ipc.Response) {
	t.Helper()
	payload, _ := json.Marshal(request)
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/v1/actions", bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
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

func proxyRequest() ipc.Request {
	return ipc.Request{
		App:    "notes",
		Action: "read_note",
		Agent:  "claude-code", // the acting agent is advisory under proxy auth
		Params: map[string]string{"folder": "Work", "note": "Sprint Plan"},
		Mode:   "json",
	}
}

// userScopedPolicy allows one user with no agent selector.
const userScopedPolicy = "version: 1\nrules:\n  - effect: allow\n    user: alice@corp\n    app: notes\n    action: read_note\n"

func TestHTTPTrustedProxySetsVerifiedUser(t *testing.T) {
	srv, paths, store := newProxyFixture(t, true, userScopedPolicy)
	token, err := store.MintWith(authtoken.MintOptions{Agent: "sso-proxy", TrustedProxy: true})
	if err != nil {
		t.Fatalf("MintWith: %v", err)
	}

	resp, decoded := postWithHeaders(t, srv, token, map[string]string{"X-Forwarded-Email": "alice@corp"}, proxyRequest())
	if resp.StatusCode != http.StatusOK || !decoded.OK {
		t.Fatalf("status=%d ok=%v err=%s", resp.StatusCode, decoded.OK, decoded.Error)
	}
	lines := auditLines(t, paths)
	if len(lines) != 1 {
		t.Fatalf("audit lines = %v", lines)
	}
	got := lines[0]
	if got["user"] != "alice@corp" || got["auth_method"] != "proxy" || got["agent"] != "claude-code" {
		t.Fatalf("audit attribution = %v, want user=alice@corp auth_method=proxy agent=claude-code", got)
	}
	if got["result"] != "success" {
		t.Fatalf("result = %v, want success", got["result"])
	}
}

func TestHTTPTrustedProxyUserScopedPolicyDeniesOtherUser(t *testing.T) {
	srv, paths, store := newProxyFixture(t, true, userScopedPolicy)
	token, _ := store.MintWith(authtoken.MintOptions{Agent: "sso-proxy", TrustedProxy: true})

	resp, decoded := postWithHeaders(t, srv, token, map[string]string{"X-Forwarded-Email": "bob@corp"}, proxyRequest())
	if resp.StatusCode != http.StatusForbidden || decoded.ExitCode != ExitDenied {
		t.Fatalf("status=%d exit=%d, want 403/%d", resp.StatusCode, decoded.ExitCode, ExitDenied)
	}
	lines := auditLines(t, paths)
	if len(lines) != 1 || lines[0]["user"] != "bob@corp" || lines[0]["result"] != "denied" {
		t.Fatalf("audit = %v, want user=bob@corp result=denied", lines)
	}
}

func TestHTTPTrustedProxyMissingUserHeaderRejected(t *testing.T) {
	srv, paths, store := newProxyFixture(t, true, userScopedPolicy)
	token, _ := store.MintWith(authtoken.MintOptions{Agent: "sso-proxy", TrustedProxy: true})

	resp, decoded := postWithHeaders(t, srv, token, nil, proxyRequest())
	if resp.StatusCode != http.StatusForbidden || decoded.ExitCode != ExitDenied {
		t.Fatalf("status=%d exit=%d, want 403/%d", resp.StatusCode, decoded.ExitCode, ExitDenied)
	}
	lines := auditLines(t, paths)
	if len(lines) != 1 || lines[0]["result"] != "missing_proxy_user" {
		t.Fatalf("audit = %v, want result=missing_proxy_user", lines)
	}
}

func TestHTTPTrustedProxyHeaderOverridesBodyUser(t *testing.T) {
	// A client cannot escalate by putting a different user in the request body —
	// the verified header wins.
	srv, paths, store := newProxyFixture(t, true, userScopedPolicy)
	token, _ := store.MintWith(authtoken.MintOptions{Agent: "sso-proxy", TrustedProxy: true})

	req := proxyRequest()
	req.User = "admin@corp" // spoof attempt in the body
	resp, decoded := postWithHeaders(t, srv, token, map[string]string{"X-Forwarded-Email": "alice@corp"}, req)
	if resp.StatusCode != http.StatusOK || !decoded.OK {
		t.Fatalf("status=%d ok=%v err=%s", resp.StatusCode, decoded.OK, decoded.Error)
	}
	if lines := auditLines(t, paths); len(lines) != 1 || lines[0]["user"] != "alice@corp" {
		t.Fatalf("audit user = %v, want the header value alice@corp (body ignored)", lines)
	}
}

func TestHTTPNormalTokenIgnoresSpoofedUserHeader(t *testing.T) {
	// A normal (non-proxy) token must not gain a user identity from a forwarded
	// header: only trusted-proxy tokens are trusted to assert one.
	srv, paths, store := newProxyFixture(t, true, userScopedPolicy)
	token, err := store.Mint("demo", false) // plain agent token, no bound user
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	req := proxyRequest()
	req.Agent = "demo" // must match the plain token's agent
	resp, decoded := postWithHeaders(t, srv, token, map[string]string{"X-Forwarded-Email": "alice@corp"}, req)
	// The header is ignored → no user → the user-scoped allow does not match.
	if resp.StatusCode != http.StatusForbidden || decoded.ExitCode != ExitDenied {
		t.Fatalf("status=%d exit=%d, want 403/%d (spoofed header must be ignored)", resp.StatusCode, decoded.ExitCode, ExitDenied)
	}
	if lines := auditLines(t, paths); len(lines) != 1 || lines[0]["user"] != nil || lines[0]["auth_method"] != "token" {
		t.Fatalf("audit = %v, want no user and auth_method=token", lines)
	}
}

func TestHTTPPerUserTokenBindsUser(t *testing.T) {
	// The no-IdP path: a per-user token carries its subject, which scopes policy.
	srv, paths, store := newProxyFixture(t, true, userScopedPolicy)
	token, err := store.MintWith(authtoken.MintOptions{Agent: "demo", User: "alice@corp"})
	if err != nil {
		t.Fatalf("MintWith: %v", err)
	}

	req := proxyRequest()
	req.Agent = "demo"
	resp, decoded := postWithHeaders(t, srv, token, nil, req)
	if resp.StatusCode != http.StatusOK || !decoded.OK {
		t.Fatalf("status=%d ok=%v err=%s", resp.StatusCode, decoded.OK, decoded.Error)
	}
	if lines := auditLines(t, paths); len(lines) != 1 || lines[0]["user"] != "alice@corp" || lines[0]["auth_method"] != "token" {
		t.Fatalf("audit = %v, want user=alice@corp auth_method=token", lines)
	}
}

func TestHTTPProxyTokenWithoutTrustModeActsAsNormalToken(t *testing.T) {
	// With TrustProxy off, a trusted-proxy token is just a normal token bound to
	// its agent (sso-proxy) and the forwarded header is ignored — the proxy
	// capability requires the daemon's explicit opt-in.
	srv, _, store := newProxyFixture(t, false, userScopedPolicy)
	token, _ := store.MintWith(authtoken.MintOptions{Agent: "sso-proxy", TrustedProxy: true})

	// Body claims agent claude-code, but the token binds sso-proxy → mismatch.
	resp, decoded := postWithHeaders(t, srv, token, map[string]string{"X-Forwarded-Email": "alice@corp"}, proxyRequest())
	if resp.StatusCode != http.StatusForbidden || decoded.ExitCode != ExitDenied {
		t.Fatalf("status=%d exit=%d, want 403/%d (token agent mismatch)", resp.StatusCode, decoded.ExitCode, ExitDenied)
	}
}

func TestHTTPTrustedProxyGroupScopedPolicy(t *testing.T) {
	groupPolicy := "version: 1\nrules:\n  - effect: allow\n    groups: [sre]\n    app: notes\n    action: read_note\n"
	srv, paths, store := newProxyFixture(t, true, groupPolicy)
	token, _ := store.MintWith(authtoken.MintOptions{Agent: "sso-proxy", TrustedProxy: true})

	headers := map[string]string{"X-Forwarded-Email": "alice@corp", "X-Forwarded-Groups": "oncall, sre"}
	resp, decoded := postWithHeaders(t, srv, token, headers, proxyRequest())
	if resp.StatusCode != http.StatusOK || !decoded.OK {
		t.Fatalf("status=%d ok=%v err=%s", resp.StatusCode, decoded.OK, decoded.Error)
	}
	lines := auditLines(t, paths)
	if len(lines) != 1 {
		t.Fatalf("audit lines = %v", lines)
	}
	groups, _ := lines[0]["groups"].([]any)
	if len(groups) != 2 || groups[0] != "oncall" || groups[1] != "sre" {
		t.Fatalf("audit groups = %v, want [oncall sre]", lines[0]["groups"])
	}
}

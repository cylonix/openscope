// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package daemon

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/openscope/openscope/audit"
	"github.com/openscope/openscope/authtoken"
	"github.com/openscope/openscope/config"
	"github.com/openscope/openscope/ipc"
)

// HTTPServer is the daemon's network listener. Unlike the Unix socket
// (where filesystem permissions are the trust boundary), the HTTP listener
// authenticates every /v1/actions call with a Bearer agent token
// (osk_agent_*) and derives the agent identity FROM the token — the
// request's agent field is filled or checked against it, never trusted on
// its own.
//
// Anonymous mode (Paths.HTTPAllowAnon) preserves the legacy localhost
// bridge (Docker/NemoClaw): it is refused on non-loopback listen addresses
// by ValidateHTTPConfig.
type HTTPServer struct {
	Service Service
	Tokens  *authtoken.FileStore

	AllowAnon    bool
	MaxBodyBytes int64
	Limiter      *rateLimiter

	// SSO reverse-proxy trust. When TrustProxy is set, a request bearing a
	// trusted-proxy token may assert a verified user via ProxyUserHeader (and
	// groups via ProxyGroupsHeader). Header trust is gated on the token's
	// trusted_proxy capability — a normal token's user headers are ignored.
	TrustProxy        bool
	ProxyUserHeader   string
	ProxyGroupsHeader string
}

// NewHTTPServer builds the listener from Paths, loading the token pepper
// (auto-generating the pepper file on first use).
func NewHTTPServer(service Service, paths config.Paths) (*HTTPServer, error) {
	pepper, err := authtoken.LoadPepper(paths.AuthPepper, paths.TokenPepperFile)
	if err != nil {
		return nil, fmt.Errorf("load token pepper: %w", err)
	}
	return &HTTPServer{
		Service:           service,
		Tokens:            &authtoken.FileStore{Path: paths.AgentTokensFile, Pepper: pepper},
		AllowAnon:         paths.HTTPAllowAnon,
		MaxBodyBytes:      1 << 20, // 1 MiB — action requests are small JSON
		Limiter:           newRateLimiter(10, 30),
		TrustProxy:        paths.HTTPTrustProxy,
		ProxyUserHeader:   paths.HTTPProxyUserHeader,
		ProxyGroupsHeader: paths.HTTPProxyGroupsHeader,
	}, nil
}

// ValidateHTTPConfig enforces the startup safety rules for the network
// listener:
//
//   - plaintext on a non-loopback address requires OPENSCOPE_HTTP_PLAINTEXT_OK
//     (for reverse-proxy TLS termination) — never silently serve tokens in
//     cleartext
//   - anonymous mode (OPENSCOPE_HTTP_ALLOW_ANON) is loopback-only
func ValidateHTTPConfig(paths config.Paths) error {
	if paths.HTTPListenAddr == "" {
		return nil
	}
	loopback := listenAddrIsLoopback(paths.HTTPListenAddr)
	tlsConfigured := paths.HTTPTLSCertFile != "" && paths.HTTPTLSKeyFile != ""
	if (paths.HTTPTLSCertFile == "") != (paths.HTTPTLSKeyFile == "") {
		return fmt.Errorf("OPENSCOPE_HTTP_TLS_CERT and OPENSCOPE_HTTP_TLS_KEY must be set together")
	}
	if !loopback && !tlsConfigured && !paths.HTTPPlaintextOK {
		return fmt.Errorf("refusing to serve plaintext HTTP on non-loopback %q: set OPENSCOPE_HTTP_TLS_CERT/_KEY, or OPENSCOPE_HTTP_PLAINTEXT_OK=1 if TLS is terminated by a reverse proxy", paths.HTTPListenAddr)
	}
	if paths.HTTPAllowAnon && !loopback {
		return fmt.Errorf("OPENSCOPE_HTTP_ALLOW_ANON is loopback-only; %q is not a loopback address", paths.HTTPListenAddr)
	}
	return nil
}

func listenAddrIsLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	switch host {
	case "localhost", "":
		return host == "localhost" // ":8080" binds all interfaces — not loopback
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// ListenAndServeHTTP serves the daemon's HTTP bridge with auth, TLS (when
// configured), timeouts, and body limits. Kept as the package-level entry
// point so cmd/openscoped stays a thin wrapper.
func ListenAndServeHTTP(paths config.Paths, service Service) error {
	if err := ValidateHTTPConfig(paths); err != nil {
		return err
	}
	hs, err := NewHTTPServer(service, paths)
	if err != nil {
		return err
	}

	server := &http.Server{
		Addr:              paths.HTTPListenAddr,
		Handler:           hs.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	if paths.HTTPTLSCertFile != "" {
		server.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		return server.ListenAndServeTLS(paths.HTTPTLSCertFile, paths.HTTPTLSKeyFile)
	}
	return server.ListenAndServe()
}

// Handler exposes the mux for tests (httptest) and embedding.
func (hs *HTTPServer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":      true,
			"service": "openscoped",
		})
	})
	mux.HandleFunc("/v1/actions", hs.handleActions)
	return mux
}

func (hs *HTTPServer) handleActions(w http.ResponseWriter, r *http.Request) {
	requestID := newRequestID()
	w.Header().Set("X-Request-Id", requestID)

	if r.Method != http.MethodPost {
		writeHTTPResponse(w, errorResponse(ExitInvalid, "method not allowed"))
		return
	}

	meta := RequestMeta{
		RequestID:  requestID,
		Transport:  "http",
		RemoteAddr: r.RemoteAddr,
	}

	// --- Authenticate -----------------------------------------------------
	// Normal token: the agent (and any bound user) comes FROM the token.
	// Trusted-proxy token: the agent stays advisory (request body) and the
	// verified user comes from the proxy-forwarded header.
	agentID := ""
	var verifiedUser string
	var verifiedGroups []string
	authHeader := r.Header.Get("Authorization")
	switch {
	case authHeader != "":
		token, ok := authtoken.ParseBearer(authHeader)
		if !ok {
			hs.auditAuthFailure(meta, "", "invalid_token", "malformed Authorization header")
			writeHTTPResponse(w, errorResponse(ExitDenied, "invalid or malformed bearer token"))
			return
		}
		meta.TokenPrefix = token[:authtoken.PrefixLen]
		res, err := hs.Tokens.ResolveFull(token)
		if err != nil {
			hs.auditAuthFailure(meta, "", "invalid_token", "token did not resolve to an agent")
			writeHTTPResponse(w, errorResponse(ExitDenied, "invalid or revoked token"))
			return
		}
		if res.TrustedProxy && hs.TrustProxy {
			// SSO proxy: trust the verified-user header it forwarded. The proxy
			// authenticated the human against the customer's IdP; this token is
			// the trust anchor, so the daemon never validates an IdP JWT itself.
			meta.AuthMethod = "proxy"
			verifiedUser = strings.TrimSpace(r.Header.Get(hs.ProxyUserHeader))
			verifiedGroups = parseProxyGroups(r.Header.Get(hs.ProxyGroupsHeader))
			if verifiedUser == "" {
				hs.auditAuthFailure(meta, "", "missing_proxy_user", "trusted-proxy request carried no verified user header")
				writeHTTPResponse(w, errorResponse(ExitDenied, "trusted-proxy request missing verified user identity"))
				return
			}
		} else {
			// Normal bearer token: identity is the token's agent plus any user
			// subject bound at mint time. A forwarded user header is ignored.
			agentID = res.Agent
			verifiedUser = res.User
			meta.AuthMethod = "token"
		}
	case hs.AllowAnon:
		// Legacy localhost bridge: the request's own agent/user fields are
		// used, exactly like the Unix socket path.
		meta.AuthMethod = "anon"
	default:
		hs.auditAuthFailure(meta, "", "missing_token", "no Authorization header")
		w.Header().Set("WWW-Authenticate", `Bearer realm="openscoped"`)
		writeHTTPResponse(w, errorResponse(ExitDenied, "missing bearer token (mint one with: openscope agent token mint <agent_id>)"))
		return
	}

	// --- Rate limit (per token, else per remote IP) ----------------------
	limiterKey := meta.TokenPrefix
	if limiterKey == "" {
		limiterKey = remoteIP(r.RemoteAddr)
	}
	if hs.Limiter != nil && !hs.Limiter.allow(limiterKey) {
		hs.auditAuthFailure(meta, agentID, "rate_limited", "request rate exceeded")
		writeHTTPResponse(w, errorResponse(ExitRateLimited, "rate limit exceeded; retry later"))
		return
	}

	// --- Decode (bounded) -------------------------------------------------
	maxBytes := hs.MaxBodyBytes
	if maxBytes <= 0 {
		maxBytes = 1 << 20
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
	var request ipc.Request
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		writeHTTPResponse(w, errorResponse(ExitInvalid, fmt.Sprintf("decode request: %v", err)))
		return
	}

	// --- Bind agent identity ---------------------------------------------
	if agentID != "" {
		switch request.Agent {
		case "", agentID:
			request.Agent = agentID
		default:
			hs.auditAuthFailure(meta, agentID, "agent_token_mismatch",
				fmt.Sprintf("request agent %q does not match token agent %q", request.Agent, agentID))
			writeHTTPResponse(w, errorResponse(ExitDenied, "request agent does not match token"))
			return
		}
	}

	// --- Bind user identity ----------------------------------------------
	// For token and proxy auth the user/groups are server-authoritative —
	// overwrite anything the client put in the body so it can never assert an
	// identity off the wire. The anon bridge keeps the body's advisory values
	// (loopback-only, like the Unix socket).
	if meta.AuthMethod != "anon" {
		request.User = verifiedUser
		request.Groups = verifiedGroups
	}

	response := hs.Service.HandleWithMeta(request, meta)
	writeHTTPResponse(w, response)
}

func (hs *HTTPServer) auditAuthFailure(meta RequestMeta, agentID, result, reason string) {
	event := audit.Event{
		Timestamp: time.Now().UTC(),
		Agent:     agentID,
		App:       "daemon",
		Action:    "/v1/actions",
		Decision:  "deny",
		Result:    result,
		Reason:    reason,
	}
	event.RequestID = meta.RequestID
	event.Transport = meta.Transport
	event.RemoteAddr = meta.RemoteAddr
	event.TokenPrefix = meta.TokenPrefix
	_ = audit.Append(hs.Service.Paths.AuditFile, event)
}

// errorResponse builds a uniform error ipc.Response.
func errorResponse(exitCode int, msg string) ipc.Response {
	return ipc.Response{OK: false, Error: msg, ExitCode: exitCode}
}

func writeHTTPResponse(w http.ResponseWriter, response ipc.Response) {
	w.Header().Set("Content-Type", "application/json")
	if !response.OK {
		w.WriteHeader(httpStatusForExitCode(response.ExitCode))
	}
	_ = json.NewEncoder(w).Encode(response)
}

func newRequestID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "rid-rand-unavailable"
	}
	return hex.EncodeToString(b[:])
}

// parseProxyGroups splits a proxy-forwarded groups header into a clean list.
// oauth2-proxy and similar proxies send groups comma-separated (e.g.
// "sre,oncall"); empty entries and surrounding whitespace are dropped.
func parseProxyGroups(header string) []string {
	if strings.TrimSpace(header) == "" {
		return nil
	}
	var groups []string
	for _, g := range strings.Split(header, ",") {
		if g = strings.TrimSpace(g); g != "" {
			groups = append(groups, g)
		}
	}
	return groups
}

func remoteIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return host
}

func httpStatusForExitCode(exitCode int) int {
	switch exitCode {
	case ExitOK:
		return http.StatusOK
	case ExitInvalid:
		return http.StatusBadRequest
	case ExitDenied:
		return http.StatusForbidden
	case ExitNotFound:
		return http.StatusNotFound
	case ExitExecutorError:
		return http.StatusBadGateway
	case ExitRateLimited:
		return http.StatusTooManyRequests
	default:
		return http.StatusInternalServerError
	}
}

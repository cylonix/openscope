// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package daemon

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/openscope/openscope/agent"
	"github.com/openscope/openscope/audit"
	"github.com/openscope/openscope/capabilities"
	"github.com/openscope/openscope/config"
	"github.com/openscope/openscope/cpclient"
	"github.com/openscope/openscope/ipc"
	"github.com/openscope/openscope/passport"
	"github.com/openscope/openscope/reflector"
)

const defaultReflectorTTL = 30 * time.Minute

// isLocalOnlyVerb reports whether a request targets a built-in management or
// diagnostic verb that short-circuits before the attenuation gate, and so must
// be refused over a reflected session.
func isLocalOnlyVerb(request ipc.Request) bool {
	if request.App == "reflector" {
		return true
	}
	if request.App == "ssh" && request.Action == "inspect_bypass" {
		return true
	}
	return false
}

// NewReflectorManager builds the daemon's reflector manager from config, or
// returns (nil, nil) when reflector is not configured (OPENSCOPE_REFLECTOR_URL
// unset). It loads/creates the daemon identity, reuses the deploy token from the
// existing control-plane enrollment as the relay credential (no second
// enrollment), and wires reflected requests back through the normal chokepoint.
func NewReflectorManager(paths config.Paths) (*reflector.Manager, error) {
	if paths.ReflectorURL == "" {
		return nil, nil
	}
	identity, err := reflector.LoadOrCreateIdentity(paths.ReflectorIdentityFile)
	if err != nil {
		return nil, err
	}
	token := os.Getenv("OPENSCOPE_REFLECTOR_TOKEN")
	if token == "" {
		if e, lerr := cpclient.LoadEnrollment(filepath.Join(paths.ConfigDir, "controlplane.yaml")); lerr == nil {
			token = e.DeploymentToken
		}
	}
	transport := reflector.NewHTTPMailbox(paths.ReflectorURL, token)

	// Reflected requests run through an independent, fully-wired Service (same
	// paths + executors); it never needs Reflector itself, which avoids a
	// construction cycle.
	dispatchSvc := NewService(paths)
	dispatch := func(sess *reflector.Session, req ipc.Request) ipc.Response {
		return dispatchSvc.reflectorDispatch(sess, req)
	}
	return reflector.NewManager(transport, identity, paths.ReflectorURL, dispatch, reflector.Options{}), nil
}

// reflectorDispatch is the heart of the delegation model: it OVERWRITES the
// wire-claimed identity with the session's issuer (so policy.Evaluate runs under
// the issuer, never the external agent) and attaches the passport scope as a
// deny-only attenuation. Mirrors http.go's discipline of server-derived identity.
func (s Service) reflectorDispatch(sess *reflector.Session, req ipc.Request) ipc.Response {
	req.Agent = sess.Issuer.Agent
	req.User = sess.Issuer.User
	req.Groups = sess.Issuer.Groups
	scope := sess.Scope()
	return s.HandleWithMeta(req, RequestMeta{
		RequestID:     newRequestID(),
		Transport:     "reflector",
		AuthMethod:    "reflector",
		SessionID:     sess.ID,
		ExternalAgent: sess.External,
		Attenuation:   &scope,
	})
}

// handleReflectorControl serves the `reflector` control verb (open/extend/close/
// list), invoked over the trusted local socket by `openscope share`.
func (s Service) handleReflectorControl(request ipc.Request) ipc.Response {
	if s.Reflector == nil {
		return ipc.Response{OK: false, App: "reflector", Action: request.Action, Agent: request.Agent,
			Error: "reflector is not enabled on this daemon (set OPENSCOPE_REFLECTOR_URL)", ExitCode: ExitConfigError}
	}
	switch request.Action {
	case "open":
		return s.reflectorOpen(request)
	case "extend":
		return s.reflectorExtend(request)
	case "close":
		id := request.Params["id"]
		if id != "" && s.Reflector.Close(id) {
			return ipc.Response{OK: true, App: "reflector", Action: "close", Agent: request.Agent, Data: map[string]any{"id": id, "closed": true}}
		}
		return ipc.Response{OK: false, App: "reflector", Action: "close", Agent: request.Agent, Error: "no such session", ExitCode: ExitNotFound}
	case "list":
		return ipc.Response{OK: true, App: "reflector", Action: "list", Agent: request.Agent, Data: s.Reflector.List()}
	default:
		return ipc.Response{OK: false, App: "reflector", Action: request.Action, Agent: request.Agent,
			Error: fmt.Sprintf("unknown reflector action %q", request.Action), ExitCode: ExitNotFound}
	}
}

func (s Service) reflectorOpen(request ipc.Request) ipc.Response {
	issuer := request.Agent
	requested, errResp := s.parseAndVerifyScope(request)
	if errResp != nil {
		return *errResp
	}

	ttl := defaultReflectorTTL
	if v := request.Params["ttl"]; v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			ttl = d
		}
	}
	var recipient []byte
	if v := request.Params["recipient_pub"]; v != "" {
		dec, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			return ipc.Response{OK: false, App: "reflector", Action: "open", Agent: issuer, Error: "bad recipient_pub", ExitCode: ExitInvalid}
		}
		recipient = dec
	}

	p := passport.Passport{
		Issuer:     passport.Principal{Agent: issuer, User: request.User, Groups: request.Groups},
		External:   request.Params["to"],
		RelayURL:   s.Paths.ReflectorURL,
		Sanctioned: requested,
		Recipient:  recipient,
	}
	handle, fragment, err := s.Reflector.Open(p, passport.NewScope(requested), ttl)
	if err != nil {
		return ipc.Response{OK: false, App: "reflector", Action: "open", Agent: issuer, Error: err.Error(), ExitCode: ExitExecutorError}
	}
	h, _ := passport.DecodeHandle(handle)

	s.meta.SessionID = h.ID
	s.meta.ExternalAgent = p.External
	s.recordAudit(audit.Event{
		Timestamp: time.Now().UTC(),
		Agent:     issuer,
		App:       "reflector",
		Action:    "open",
		Decision:  "allow",
		Result:    "success",
	})

	data := map[string]any{
		"id":          h.ID,
		"handle":      handle,
		"fingerprint": h.DaemonFingerprint,
		"valid_until": h.ValidUntil.Format(time.RFC3339),
		"sanctioned":  requested,
	}
	if len(fragment) > 0 {
		data["bearer_secret"] = base64.StdEncoding.EncodeToString(fragment)
	}
	return ipc.Response{OK: true, App: "reflector", Action: "open", Agent: issuer, Data: data}
}

func (s Service) reflectorExtend(request ipc.Request) ipc.Response {
	id := request.Params["id"]
	if id == "" {
		return ipc.Response{OK: false, App: "reflector", Action: "extend", Agent: request.Agent, Error: "id is required", ExitCode: ExitInvalid}
	}
	requested, errResp := s.parseAndVerifyScope(request)
	if errResp != nil {
		return *errResp
	}
	if !s.Reflector.Extend(id, passport.NewScope(requested)) {
		return ipc.Response{OK: false, App: "reflector", Action: "extend", Agent: request.Agent, Error: "no such session", ExitCode: ExitNotFound}
	}
	return ipc.Response{OK: true, App: "reflector", Action: "extend", Agent: request.Agent, Data: map[string]any{"id": id, "sanctioned": requested}}
}

// parseAndVerifyScope decodes the requested scope and enforces the two
// preconditions every share/extend shares: the issuer is registered, and the
// requested scope is a SUBSET of the issuer's live surface. The subset check is
// authoritative here (the CLI's identical pre-check is only for fast feedback).
// Returns the parsed scope, or a non-nil error response to return verbatim.
func (s Service) parseAndVerifyScope(request ipc.Request) ([]capabilities.Capability, *ipc.Response) {
	issuer := request.Agent
	registered, err := agent.IsRegistered(s.Paths, issuer)
	if err != nil {
		return nil, &ipc.Response{OK: false, App: "reflector", Action: request.Action, Agent: issuer, Error: fmt.Sprintf("load agents: %v", err), ExitCode: ExitConfigError}
	}
	if !registered {
		return nil, &ipc.Response{OK: false, App: "reflector", Action: request.Action, Agent: issuer, Error: fmt.Sprintf("issuer %q is not registered", issuer), ExitCode: ExitDenied}
	}

	var requested []capabilities.Capability
	if raw := request.Params["scope"]; raw != "" {
		if err := json.Unmarshal([]byte(raw), &requested); err != nil {
			return nil, &ipc.Response{OK: false, App: "reflector", Action: request.Action, Agent: issuer, Error: "malformed scope", ExitCode: ExitInvalid}
		}
	}
	if len(requested) == 0 {
		return nil, &ipc.Response{OK: false, App: "reflector", Action: request.Action, Agent: issuer, Error: "scope is required (use --verb)", ExitCode: ExitInvalid}
	}

	surface, err := capabilities.BuildFromPaths(s.Paths, issuer)
	if err != nil {
		return nil, &ipc.Response{OK: false, App: "reflector", Action: request.Action, Agent: issuer, Error: fmt.Sprintf("build issuer surface: %v", err), ExitCode: ExitConfigError}
	}
	if ok, why := passport.Subset(requested, surface.Capabilities); !ok {
		s.meta.SessionID = ""
		s.recordAudit(audit.Event{
			Timestamp: time.Now().UTC(),
			Agent:     issuer,
			App:       "reflector",
			Action:    request.Action,
			Decision:  "deny",
			Result:    "out_of_issuer_scope",
			Reason:    why,
		})
		return nil, &ipc.Response{OK: false, App: "reflector", Action: request.Action, Agent: issuer,
			Error:    why + " — the issuer cannot delegate what it lacks; expand its scope via `openscope plan` / `sudo openscope apply` first",
			ExitCode: ExitDenied}
	}
	return requested, nil
}

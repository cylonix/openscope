// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/openscope/openscope/capabilities"
	"github.com/openscope/openscope/config"
	"github.com/openscope/openscope/daemon"
	"github.com/openscope/openscope/ipc"
	"github.com/openscope/openscope/output"
)

// runShare drives `openscope share` — issuing, listing, extending, and revoking
// cross-org delegation sessions. The issuing developer delegates a SUBSET of
// their own scope; the daemon executes within the issuer's scope and tears the
// session down at TTL.
func runShare(paths config.Paths, args []string) int {
	if len(args) == 0 {
		output.WriteErrorf("usage: openscope share <open|list|extend|revoke>")
		return daemon.ExitInvalid
	}
	switch args[0] {
	case "open":
		return runShareOpen(paths, args[1:])
	case "list":
		return runShareList(paths, args[1:])
	case "extend":
		return runShareExtend(paths, args[1:])
	case "revoke", "close":
		return runShareRevoke(paths, args[1:])
	default:
		output.WriteErrorf("unknown share subcommand %q", args[0])
		return daemon.ExitInvalid
	}
}

// shareFlags is the parsed form of `share open`/`extend` args. Unlike
// parseFlags, --verb may repeat.
type shareFlags struct {
	agent  string
	verbs  []string
	to     string
	ttl    string
	id     string
	bearer bool
	json   bool
}

func parseShareFlags(args []string) (shareFlags, error) {
	var f shareFlags
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--agent":
			f.agent, i = next(args, i)
		case "--verb":
			var v string
			v, i = next(args, i)
			if v != "" {
				f.verbs = append(f.verbs, v)
			}
		case "--to":
			f.to, i = next(args, i)
		case "--ttl":
			f.ttl, i = next(args, i)
		case "--id":
			f.id, i = next(args, i)
		case "--bearer":
			f.bearer = true
		case "--json":
			f.json = true
		default:
			return f, fmt.Errorf("unexpected argument %q", args[i])
		}
	}
	return f, nil
}

func next(args []string, i int) (string, int) {
	if i+1 >= len(args) || strings.HasPrefix(args[i+1], "--") {
		return "", i
	}
	return args[i+1], i + 1
}

func runShareOpen(paths config.Paths, args []string) int {
	f, err := parseShareFlags(args)
	if err != nil {
		output.WriteErrorf("%v", err)
		return daemon.ExitInvalid
	}
	if f.agent == "" || len(f.verbs) == 0 {
		output.WriteErrorf("usage: openscope share open --agent <issuer> --verb app.action[:k=v,...] [--verb ...] (--to <alias> | --bearer) [--ttl 30m]")
		return daemon.ExitInvalid
	}

	requested, code := buildRequestedScope(paths, f.agent, f.verbs)
	if code != daemon.ExitOK {
		return code
	}
	scopeJSON, err := json.Marshal(requested)
	if err != nil {
		output.WriteErrorf("encode scope: %v", err)
		return daemon.ExitExecutorError
	}

	params := map[string]string{"scope": string(scopeJSON)}
	if f.ttl != "" {
		params["ttl"] = f.ttl
	}
	if f.to != "" {
		params["to"] = f.to
	}
	if !f.bearer {
		if f.to == "" {
			output.WriteErrorf("a recipient is required: pass --to <alias> (see `openscope contact`), or --bearer to issue an unbound handle")
			return daemon.ExitInvalid
		}
		cf, err := loadContacts(paths.ContactsFile)
		if err != nil {
			output.WriteErrorf("load contacts: %v", err)
			return daemon.ExitConfigError
		}
		pub, ok := cf.lookup(f.to)
		if !ok {
			output.WriteErrorf("no contact %q — add the recipient's key (`openscope contact add %s <pubkey>`), or use --bearer", f.to, f.to)
			return daemon.ExitNotFound
		}
		params["recipient_pub"] = pub
	}

	resp, err := ipc.Call(paths, ipc.Request{App: "reflector", Action: "open", Agent: f.agent, Params: params})
	if err != nil {
		output.WriteErrorf("daemon unavailable: %v", err)
		return daemon.ExitIPCError
	}
	if !resp.OK {
		output.WriteErrorf("%s", resp.Error)
		return resp.ExitCode
	}
	if f.json {
		return writeJSON(output.Response{OK: true, App: resp.App, Action: resp.Action, Agent: resp.Agent, Data: resp.Data})
	}
	printShareOpen(f, resp.Data)
	return daemon.ExitOK
}

func printShareOpen(f shareFlags, data any) {
	m, _ := data.(map[string]any)
	str := func(k string) string { s, _ := m[k].(string); return s }

	fmt.Println("Delegation session opened.")
	fmt.Println()
	fmt.Printf("  id:          %s\n", str("id"))
	fmt.Printf("  valid until: %s\n", str("valid_until"))
	fmt.Printf("  run-as:      %s  (the issuer; the recipient acts within this scope)\n", f.agent)
	if f.to != "" {
		fmt.Printf("  to:          %s\n", f.to)
	}
	fmt.Println()
	fmt.Println("Daemon fingerprint — confirm this with the recipient over a separate channel:")
	fmt.Printf("  %s\n", str("fingerprint"))
	fmt.Println()
	fmt.Println("Passport handle — give this to the recipient:")
	fmt.Printf("  %s\n", str("handle"))
	if secret := str("bearer_secret"); secret != "" {
		fmt.Println()
		fmt.Println("Bearer secret (no recipient key was bound — anyone with BOTH values can connect;")
		fmt.Println("prefer --to <alias> for cross-org. Convey out of band):")
		fmt.Printf("  %s\n", secret)
		fmt.Println()
		fmt.Println("Recipient runs:  openscope-reflect-client --passport <handle> --secret <bearer-secret>")
	} else {
		fmt.Println()
		fmt.Println("Recipient runs:  openscope-reflect-client --passport <handle>")
	}
}

// buildRequestedScope derives the requested capabilities from the issuer's live
// surface, narrowing by the per-verb k=v pins. Deriving (rather than building
// from scratch) makes the result narrow-by-construction; the daemon's Subset
// check is the authoritative guard.
func buildRequestedScope(paths config.Paths, issuer string, verbs []string) ([]capabilities.Capability, int) {
	surface, err := capabilities.BuildFromPaths(paths, issuer)
	if err != nil {
		output.WriteErrorf("build issuer surface: %v", err)
		return nil, daemon.ExitConfigError
	}
	var requested []capabilities.Capability
	for _, spec := range verbs {
		app, action, pins, err := parseVerbSpec(spec)
		if err != nil {
			output.WriteErrorf("%v", err)
			return nil, daemon.ExitInvalid
		}
		c, err := deriveCapability(surface.Capabilities, app, action, pins)
		if err != nil {
			output.WriteErrorf("%v — the issuer cannot delegate what it lacks; check `openscope capabilities --agent %s`", err, issuer)
			return nil, daemon.ExitDenied
		}
		requested = append(requested, c)
	}
	return requested, daemon.ExitOK
}

// parseVerbSpec parses "app.action[:k=v,k=v]".
func parseVerbSpec(spec string) (app, action string, pins map[string]string, err error) {
	head := spec
	rest := ""
	if i := strings.IndexByte(spec, ':'); i >= 0 {
		head, rest = spec[:i], spec[i+1:]
	}
	dot := strings.IndexByte(head, '.')
	if dot <= 0 || dot == len(head)-1 {
		return "", "", nil, fmt.Errorf("verb %q must be app.action[:k=v,...]", spec)
	}
	app, action = head[:dot], head[dot+1:]
	pins = map[string]string{}
	if rest != "" {
		for _, kv := range strings.Split(rest, ",") {
			eq := strings.IndexByte(kv, '=')
			if eq <= 0 {
				return "", "", nil, fmt.Errorf("verb %q: param %q must be k=v", spec, kv)
			}
			pins[strings.TrimSpace(kv[:eq])] = strings.TrimSpace(kv[eq+1:])
		}
	}
	return app, action, pins, nil
}

// deriveCapability clones the matching issuer capability and pins the named
// params. Params not named keep the issuer's constraint (free or allow-list).
func deriveCapability(surface []capabilities.Capability, app, action string, pins map[string]string) (capabilities.Capability, error) {
	for _, c := range surface {
		if c.App != app || c.Action != action {
			continue
		}
		out := capabilities.Capability{App: c.App, Action: c.Action, Description: c.Description}
		seen := map[string]bool{}
		for _, p := range c.Params {
			np := p // copy
			key := p.PolicyKey
			if key == "" {
				key = p.Name
			}
			v, ok := pins[p.Name]
			if !ok {
				v, ok = pins[key]
			}
			if ok {
				np.Pinned = true
				np.Fixed = v
				np.AllowedValues = nil
				np.Hint = ""
				seen[p.Name] = true
				seen[key] = true
			}
			out.Params = append(out.Params, np)
		}
		for k := range pins {
			if !seen[k] {
				return capabilities.Capability{}, fmt.Errorf("verb %s.%s has no parameter %q", app, action, k)
			}
		}
		return out, nil
	}
	return capabilities.Capability{}, fmt.Errorf("verb %s.%s is not in the issuer's surface", app, action)
}

func runShareList(paths config.Paths, args []string) int {
	f, _ := parseShareFlags(args)
	agent := f.agent
	if agent == "" {
		agent = "operator" // list is read-only; any registered agent works, but the daemon needs one
	}
	resp, err := ipc.Call(paths, ipc.Request{App: "reflector", Action: "list", Agent: agent})
	if err != nil {
		output.WriteErrorf("daemon unavailable: %v", err)
		return daemon.ExitIPCError
	}
	if !resp.OK {
		output.WriteErrorf("%s", resp.Error)
		return resp.ExitCode
	}
	return writeJSON(output.Response{OK: true, App: resp.App, Action: resp.Action, Agent: resp.Agent, Data: resp.Data})
}

func runShareExtend(paths config.Paths, args []string) int {
	f, err := parseShareFlags(args)
	if err != nil {
		output.WriteErrorf("%v", err)
		return daemon.ExitInvalid
	}
	if f.agent == "" || f.id == "" || len(f.verbs) == 0 {
		output.WriteErrorf("usage: openscope share extend --agent <issuer> --id <osp_...> --verb app.action[:k=v,...]")
		return daemon.ExitInvalid
	}
	requested, code := buildRequestedScope(paths, f.agent, f.verbs)
	if code != daemon.ExitOK {
		return code
	}
	scopeJSON, _ := json.Marshal(requested)
	resp, err := ipc.Call(paths, ipc.Request{App: "reflector", Action: "extend", Agent: f.agent,
		Params: map[string]string{"id": f.id, "scope": string(scopeJSON)}})
	if err != nil {
		output.WriteErrorf("daemon unavailable: %v", err)
		return daemon.ExitIPCError
	}
	if !resp.OK {
		output.WriteErrorf("%s", resp.Error)
		return resp.ExitCode
	}
	fmt.Printf("session %s scope extended\n", f.id)
	return daemon.ExitOK
}

func runShareRevoke(paths config.Paths, args []string) int {
	f, err := parseShareFlags(args)
	if err != nil {
		output.WriteErrorf("%v", err)
		return daemon.ExitInvalid
	}
	if f.id == "" {
		output.WriteErrorf("usage: openscope share revoke --id <osp_...> [--agent <id>]")
		return daemon.ExitInvalid
	}
	agent := f.agent
	if agent == "" {
		agent = "operator"
	}
	resp, err := ipc.Call(paths, ipc.Request{App: "reflector", Action: "close", Agent: agent, Params: map[string]string{"id": f.id}})
	if err != nil {
		output.WriteErrorf("daemon unavailable: %v", err)
		return daemon.ExitIPCError
	}
	if !resp.OK {
		output.WriteErrorf("%s", resp.Error)
		return resp.ExitCode
	}
	fmt.Printf("session %s revoked\n", f.id)
	return daemon.ExitOK
}

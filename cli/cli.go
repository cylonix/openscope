// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/openscope/openscope/admin"
	"github.com/openscope/openscope/agent"
	"github.com/openscope/openscope/appdef"
	"github.com/openscope/openscope/authtoken"
	"github.com/openscope/openscope/buildinfo"
	"github.com/openscope/openscope/config"
	"github.com/openscope/openscope/cpclient"
	"github.com/openscope/openscope/daemon"
	"github.com/openscope/openscope/doctor"
	"github.com/openscope/openscope/executor/sshexec"
	"github.com/openscope/openscope/executor/systemexec"
	"github.com/openscope/openscope/ipc"
	"github.com/openscope/openscope/output"
	"github.com/openscope/openscope/policy"
	"github.com/openscope/openscope/resources"
	"github.com/openscope/openscope/status"
)

func Run(args []string) int {
	// Version is answered before config resolution so `openscope --version`
	// works even on a half-installed or misconfigured machine — it's the first
	// thing you reach for when figuring out which build is on disk.
	if len(args) > 0 {
		switch args[0] {
		case "version", "--version", "-V":
			return runVersion(args[1:])
		}
	}

	paths, err := config.DefaultPaths()
	if err != nil {
		output.WriteErrorf("config error: %v", err)
		return daemon.ExitConfigError
	}
	if err := config.EnsureLayout(paths); err != nil {
		output.WriteErrorf("config error: %v", err)
		return daemon.ExitConfigError
	}

	if len(args) == 0 {
		printUsage()
		return daemon.ExitInvalid
	}

	if args[0] == "notes" && len(args) > 1 && args[1] == "blacklist" {
		return runNotesBlacklist(paths, args[2:])
	}
	if args[0] == "mail" && len(args) > 1 && args[1] == "domains" {
		return runMailDomains(paths, args[2:])
	}
	if args[0] == "http" && len(args) > 1 && args[1] == "profiles" {
		return runHTTPProfiles(paths, args[2:])
	}
	if args[0] == "ssh" && len(args) > 1 && args[1] == "targets" {
		return runSSHTargets(paths, args[2:])
	}
	if args[0] == "ssh" && len(args) > 1 && args[1] == "check-bypass" {
		return runSSHCheckBypass(paths, args[2:])
	}
	if args[0] == "system" && len(args) > 1 && args[1] == "commands" {
		return runSystemCommands(paths, args[2:])
	}
	if args[0] == "system" && len(args) > 1 && args[1] == "sudoers" {
		return runSystemSudoers(paths)
	}

	switch args[0] {
	case "init":
		return runInit(paths, args[1:])
	case "app":
		return runApp(paths, args[1:])
	case "policy":
		return runPolicy(paths, args[1:])
	case "agent":
		return runAgent(paths, args[1:])
	case "status":
		return runStatus(paths)
	case "doctor":
		return runDoctor(paths, args[1:])
	case "enroll":
		return runEnroll(paths, args[1:])
	case "plan":
		return runPlan(paths, args[1:])
	case "apply":
		return runApply(paths, args[1:])
	default:
		return runProtectedAction(paths, args)
	}
}

func runApp(paths config.Paths, args []string) int {
	if len(args) == 0 {
		output.WriteErrorf("usage: openscope app <list|show|validate|enable|disable|activate|deactivate>")
		return daemon.ExitInvalid
	}

	switch args[0] {
	case "list":
		loaded, err := loadVisibleDefinitions(paths)
		if err != nil {
			output.WriteErrorf("load app definitions: %v", err)
			return daemon.ExitConfigError
		}

		names := appNames(loaded)
		sort.Strings(names)

		apps := make([]map[string]any, 0, len(names))
		for _, name := range names {
			entry := loaded[name]
			apps = append(apps, map[string]any{
				"name":         name,
				"displayName":  entry.Definition.App.DisplayName,
				"securityMode": entry.Definition.App.SecurityMode,
				"enabled":      entry.Enabled,
				"bundled":      entry.Definition.Bundled,
				"source":       entry.Definition.Source,
			})
		}
		return writeJSON(map[string]any{"apps": apps})
	case "show":
		if len(args) < 2 {
			output.WriteErrorf("usage: openscope app show <app>")
			return daemon.ExitInvalid
		}
		loaded, err := loadVisibleDefinitions(paths)
		if err != nil {
			output.WriteErrorf("load app definitions: %v", err)
			return daemon.ExitConfigError
		}
		entry, ok := loaded[args[1]]
		if !ok {
			output.WriteErrorf("app %q not found", args[1])
			return daemon.ExitNotFound
		}
		return writeJSON(map[string]any{
			"enabled":      entry.Enabled,
			"bundled":      entry.Definition.Bundled,
			"securityMode": entry.Definition.App.SecurityMode,
			"app":          entry.Definition,
		})
	case "validate":
		if len(args) == 2 {
			def, err := appdef.LoadFile(args[1])
			if err != nil {
				output.WriteErrorf("validate app definition: %v", err)
				return daemon.ExitConfigError
			}
			return writeJSON(map[string]any{"ok": true, "app": def.App.Name, "source": def.Source})
		}
		_, err := loadVisibleDefinitions(paths)
		if err != nil {
			output.WriteErrorf("validate app definitions: %v", err)
			return daemon.ExitConfigError
		}
		return writeJSON(map[string]any{"ok": true})
	case "enable":
		if len(args) < 2 {
			output.WriteErrorf("usage: openscope app enable <app>")
			return daemon.ExitInvalid
		}
		return setAppEnabled(paths, args[1], true)
	case "disable":
		if len(args) < 2 {
			output.WriteErrorf("usage: openscope app disable <app>")
			return daemon.ExitInvalid
		}
		return setAppEnabled(paths, args[1], false)
	case "activate":
		return runAppActivation(paths, true, args[1:])
	case "deactivate":
		return runAppActivation(paths, false, args[1:])
	default:
		output.WriteErrorf("unknown app command %q", args[0])
		return daemon.ExitInvalid
	}
}

func runInit(paths config.Paths, args []string) int {
	force := false
	if len(args) > 0 {
		if len(args) == 1 && args[0] == "--force" {
			force = true
		} else {
			output.WriteErrorf("usage: openscope init [--force]")
			return daemon.ExitInvalid
		}
	}

	if !force {
		if fileExists(paths.AgentsFile) || fileExists(paths.PoliciesFile) {
			output.WriteErrorf("config already exists; re-run with --force to overwrite agents.yaml and policies.yaml")
			return daemon.ExitDenied
		}
	}

	registry := agent.Registry{
		Version: 1,
		Agents:  []string{"openclaw"},
	}
	if err := agent.Save(paths.AgentsFile, registry); err != nil {
		output.WriteErrorf("write default agents: %v", err)
		return daemon.ExitConfigError
	}

	pf := policy.File{
		Version: 1,
		Rules: []policy.Rule{
			{Effect: "allow", Agent: "openclaw", App: "notes", Action: "list_notes"},
			{Effect: "allow", Agent: "openclaw", App: "notes", Action: "read_note"},
			{Effect: "allow", Agent: "openclaw", App: "mail", Action: "list_messages", Constraints: map[string]string{"mailbox": "Inbox"}},
			{Effect: "allow", Agent: "openclaw", App: "mail", Action: "read_message", Constraints: map[string]string{"mailbox": "Inbox"}},
		},
	}
	if err := policy.SaveDefault(paths, pf); err != nil {
		output.WriteErrorf("write default policy: %v", err)
		return daemon.ExitConfigError
	}

	return writeJSON(map[string]any{
		"ok":          true,
		"initialized": true,
		"force":       force,
		"agents_file": paths.AgentsFile,
		"policy_file": paths.PoliciesFile,
		"agents":      registry.Agents,
	})
}

func runPolicy(paths config.Paths, args []string) int {
	if len(args) == 0 {
		output.WriteErrorf("usage: openscope policy <list|show|validate|allow|deny>")
		return daemon.ExitInvalid
	}

	switch args[0] {
	case "list":
		pf, err := policy.LoadDefault(paths)
		if err != nil {
			output.WriteErrorf("load policy: %v", err)
			return daemon.ExitConfigError
		}
		return writeJSON(pf)
	case "show":
		if len(args) < 3 || args[1] != "--agent" {
			output.WriteErrorf("usage: openscope policy show --agent <agent_id>")
			return daemon.ExitInvalid
		}
		pf, err := policy.LoadDefault(paths)
		if err != nil {
			output.WriteErrorf("load policy: %v", err)
			return daemon.ExitConfigError
		}
		var rules []policy.Rule
		for _, rule := range pf.Rules {
			if rule.Agent == args[2] {
				rules = append(rules, rule)
			}
		}
		return writeJSON(map[string]any{"agent": args[2], "rules": rules})
	case "validate":
		_, err := policy.LoadDefault(paths)
		if err != nil {
			output.WriteErrorf("validate policy: %v", err)
			return daemon.ExitConfigError
		}
		return writeJSON(map[string]any{"ok": true})
	case "allow", "deny":
		return runPolicyAddRule(paths, args[0], args[1:])
	default:
		output.WriteErrorf("unknown policy command %q", args[0])
		return daemon.ExitInvalid
	}
}

func runPolicyAddRule(paths config.Paths, effect string, args []string) int {
	if err := requireRootForMutation("policy changes"); err != nil {
		output.WriteErrorf("%v", err)
		return daemon.ExitDenied
	}

	flags, err := parseFlags(args)
	if err != nil {
		output.WriteErrorf("parse flags: %v", err)
		return daemon.ExitInvalid
	}

	agentID := flags["agent"]
	app := flags["app"]
	action := flags["action"]

	if agentID == "" || app == "" || action == "" {
		output.WriteErrorf("usage: openscope policy %s --agent <id> --app <app> --action <action> [--<param> <value> ...]", effect)
		return daemon.ExitInvalid
	}

	delete(flags, "agent")
	delete(flags, "app")
	delete(flags, "action")

	var constraints map[string]string
	if len(flags) > 0 {
		constraints = flags
	}

	rule := policy.Rule{
		Effect:      effect,
		Agent:       agentID,
		App:         app,
		Action:      action,
		Constraints: constraints,
	}

	_, added, err := policy.AddRule(paths, rule)
	if err != nil {
		output.WriteErrorf("add policy rule: %v", err)
		return daemon.ExitConfigError
	}

	return writeJSON(map[string]any{
		"ok":    true,
		"added": added,
		"rule":  rule,
	})
}

func runNotesBlacklist(paths config.Paths, args []string) int {
	if len(args) == 0 {
		output.WriteErrorf("usage: openscope notes blacklist <list|add|remove> [keyword]")
		return daemon.ExitInvalid
	}

	switch args[0] {
	case "list":
		protected, err := admin.LoadProtectedFoldersOrDefault(paths)
		if err != nil {
			output.WriteErrorf("load protected folder blacklist: %v", err)
			return daemon.ExitConfigError
		}
		return writeJSON(map[string]any{
			"keywords": protected.Keywords,
			"source":   paths.ProtectedFoldersFile,
		})
	case "add":
		if err := requireRootForMutation("protected folder blacklist changes"); err != nil {
			output.WriteErrorf("%v", err)
			return daemon.ExitDenied
		}
		if len(args) < 2 {
			output.WriteErrorf("usage: openscope notes blacklist add <keyword>")
			return daemon.ExitInvalid
		}
		protected, added, err := admin.AddProtectedFolderKeyword(paths, args[1])
		if err != nil {
			output.WriteErrorf("add protected folder keyword: %v", err)
			return daemon.ExitConfigError
		}
		return writeJSON(map[string]any{
			"ok":       true,
			"added":    added,
			"keywords": protected.Keywords,
			"source":   paths.ProtectedFoldersFile,
		})
	case "remove":
		if err := requireRootForMutation("protected folder blacklist changes"); err != nil {
			output.WriteErrorf("%v", err)
			return daemon.ExitDenied
		}
		if len(args) < 2 {
			output.WriteErrorf("usage: openscope notes blacklist remove <keyword>")
			return daemon.ExitInvalid
		}
		protected, removed, err := admin.RemoveProtectedFolderKeyword(paths, args[1])
		if err != nil {
			output.WriteErrorf("remove protected folder keyword: %v", err)
			return daemon.ExitConfigError
		}
		return writeJSON(map[string]any{
			"ok":       true,
			"removed":  removed,
			"keywords": protected.Keywords,
			"source":   paths.ProtectedFoldersFile,
		})
	default:
		output.WriteErrorf("unknown notes blacklist command %q", args[0])
		return daemon.ExitInvalid
	}
}

func runMailDomains(paths config.Paths, args []string) int {
	if len(args) == 0 {
		output.WriteErrorf("usage: openscope mail domains <list|add|remove> [domain]")
		return daemon.ExitInvalid
	}

	switch args[0] {
	case "list":
		filters, err := admin.LoadMailFiltersOrDefault(paths)
		if err != nil {
			output.WriteErrorf("load mail filters: %v", err)
			return daemon.ExitConfigError
		}
		return writeJSON(map[string]any{
			"allowed_sender_domains": filters.AllowedSenderDomains,
			"source":                 paths.MailFiltersFile,
		})
	case "add":
		if err := requireRootForMutation("mail sender domain changes"); err != nil {
			output.WriteErrorf("%v", err)
			return daemon.ExitDenied
		}
		if len(args) < 2 {
			output.WriteErrorf("usage: openscope mail domains add <domain>")
			return daemon.ExitInvalid
		}
		filters, added, err := admin.AddAllowedSenderDomain(paths, args[1])
		if err != nil {
			output.WriteErrorf("add mail sender domain: %v", err)
			return daemon.ExitConfigError
		}
		return writeJSON(map[string]any{
			"ok":                     true,
			"added":                  added,
			"allowed_sender_domains": filters.AllowedSenderDomains,
			"source":                 paths.MailFiltersFile,
		})
	case "remove":
		if err := requireRootForMutation("mail sender domain changes"); err != nil {
			output.WriteErrorf("%v", err)
			return daemon.ExitDenied
		}
		if len(args) < 2 {
			output.WriteErrorf("usage: openscope mail domains remove <domain>")
			return daemon.ExitInvalid
		}
		filters, removed, err := admin.RemoveAllowedSenderDomain(paths, args[1])
		if err != nil {
			output.WriteErrorf("remove mail sender domain: %v", err)
			return daemon.ExitConfigError
		}
		return writeJSON(map[string]any{
			"ok":                     true,
			"removed":                removed,
			"allowed_sender_domains": filters.AllowedSenderDomains,
			"source":                 paths.MailFiltersFile,
		})
	default:
		output.WriteErrorf("unknown mail domains command %q", args[0])
		return daemon.ExitInvalid
	}
}

func runSSHTargets(paths config.Paths, args []string) int {
	if len(args) == 0 {
		output.WriteErrorf("usage: openscope ssh targets <list|add|remove>")
		return daemon.ExitInvalid
	}

	switch args[0] {
	case "list":
		targets, err := admin.LoadSSHTargetsOrDefault(paths)
		if err != nil {
			output.WriteErrorf("load ssh targets: %v", err)
			return daemon.ExitConfigError
		}
		return writeJSON(map[string]any{
			"targets": targets.Targets,
			"source":  paths.SSHTargetsFile,
		})
	case "add":
		if err := requireRootForMutation("ssh target changes"); err != nil {
			output.WriteErrorf("%v", err)
			return daemon.ExitDenied
		}
		flags, err := parseFlags(args[1:])
		if err != nil {
			output.WriteErrorf("parse flags: %v", err)
			return daemon.ExitInvalid
		}
		port := 22
		if rawPort := strings.TrimSpace(flags["port"]); rawPort != "" {
			parsed, err := strconv.Atoi(rawPort)
			if err != nil {
				output.WriteErrorf("parse flags: port must be an integer")
				return daemon.ExitInvalid
			}
			port = parsed
		}
		target := admin.SSHTarget{
			Alias:               flags["alias"],
			Host:                flags["host"],
			User:                flags["user"],
			Port:                port,
			IdentityFile:        flags["identity-file"],
			ProxyJump:           flags["proxy-jump"],
			AllowedServices:     parseCSV(flags["services"]),
			AllowedPaths:        parseCSV(flags["paths"]),
			AllowedPathPrefixes: parseCSV(flags["path-prefixes"]),
		}
		targets, added, err := admin.AddSSHTarget(paths, target)
		if err != nil {
			output.WriteErrorf("add ssh target: %v", err)
			return daemon.ExitConfigError
		}
		return writeJSON(map[string]any{
			"ok":     true,
			"added":  added,
			"target": target,
			"count":  len(targets.Targets),
			"source": paths.SSHTargetsFile,
		})
	case "remove":
		if err := requireRootForMutation("ssh target changes"); err != nil {
			output.WriteErrorf("%v", err)
			return daemon.ExitDenied
		}
		if len(args) < 2 {
			output.WriteErrorf("usage: openscope ssh targets remove <alias>")
			return daemon.ExitInvalid
		}
		targets, removed, err := admin.RemoveSSHTarget(paths, args[1])
		if err != nil {
			output.WriteErrorf("remove ssh target: %v", err)
			return daemon.ExitConfigError
		}
		return writeJSON(map[string]any{
			"ok":      true,
			"removed": removed,
			"alias":   args[1],
			"count":   len(targets.Targets),
			"source":  paths.SSHTargetsFile,
		})
	default:
		output.WriteErrorf("unknown ssh targets command %q", args[0])
		return daemon.ExitInvalid
	}
}

// runSSHCheckBypass probes whether the invoking user's own ~/.ssh keys can
// authenticate to the configured SSH targets. An agent-readable key that
// reaches a brokered host bypasses the broker entirely (the agent just sshes
// directly), so even a perfectly root-owned broker key is moot. It makes real
// outbound ssh connections — running only the harmless remote command `true` —
// and is therefore opt-in: it runs only when invoked explicitly, never as part
// of plan/doctor. Exit code 3 (denied) if any key reaches a host.
func runSSHCheckBypass(paths config.Paths, args []string) int {
	flags, err := parseFlags(args)
	if err != nil {
		output.WriteErrorf("%v", err)
		return daemon.ExitInvalid
	}
	targets, err := admin.LoadSSHTargetsOrDefault(paths)
	if err != nil {
		output.WriteErrorf("load ssh targets: %v", err)
		return daemon.ExitConfigError
	}
	only := strings.TrimSpace(flags["target"])
	keys := sshexec.DiscoverUserKeys(paths.HomeDir)

	var results []sshexec.BypassResult
	probed := 0
	for _, t := range targets.Targets {
		if only != "" && t.Alias != only {
			continue
		}
		probed++
		results = append(results, sshexec.ProbeBypass(t, keys, nil)...)
	}

	bypassed := 0
	for _, r := range results {
		if r.Outcome == sshexec.BypassFound {
			bypassed++
		}
	}

	if flags["json"] == "true" {
		if code := writeJSON(map[string]any{
			"checked_targets": probed,
			"user_keys":       keys,
			"results":         results,
			"bypass_found":    bypassed,
		}); code != daemon.ExitOK {
			return code
		}
	} else {
		printBypassReport(keys, results, bypassed, probed)
	}
	if bypassed > 0 {
		return daemon.ExitDenied
	}
	return daemon.ExitOK
}

func printBypassReport(keys []string, results []sshexec.BypassResult, bypassed, probed int) {
	fmt.Println("OpenScope ssh bypass probe (outbound — ran `true` on each reachable host)")
	fmt.Printf("  ~/.ssh keys discovered: %d   targets probed: %d\n", len(keys), probed)
	if len(keys) == 0 {
		fmt.Println("  no private keys in ~/.ssh — nothing to probe")
		return
	}
	if len(results) == 0 {
		fmt.Println("  no targets matched")
		return
	}
	fmt.Println()
	for _, r := range results {
		mark := "inconclusive"
		switch r.Outcome {
		case sshexec.BypassFound:
			mark = "BYPASS"
		case sshexec.BypassClear:
			mark = "clear"
		}
		line := fmt.Sprintf("  [%-12s] %s (%s) via %s", mark, r.Target, r.Host, filepath.Base(r.Key))
		if r.Detail != "" {
			line += " — " + r.Detail
		}
		fmt.Println(line)
	}
	fmt.Println()
	if bypassed > 0 {
		fmt.Printf("ERROR: %d user-key/host pair(s) authenticate directly — the broker is bypassable.\n", bypassed)
		fmt.Println("Remove that key from the host's authorized_keys (or stop brokering the host); brokered access must use a root-owned key only.")
	} else {
		fmt.Println("OK: no ~/.ssh key authenticated to a brokered host.")
	}
}

func runHTTPProfiles(paths config.Paths, args []string) int {
	if len(args) == 0 {
		output.WriteErrorf("usage: openscope http profiles <list|add|remove>")
		return daemon.ExitInvalid
	}

	switch args[0] {
	case "list":
		profiles, err := admin.LoadHTTPProfilesOrDefault(paths)
		if err != nil {
			output.WriteErrorf("load http profiles: %v", err)
			return daemon.ExitConfigError
		}
		return writeJSON(map[string]any{
			"profiles": profiles.Profiles,
			"source":   paths.HTTPProfilesFile,
		})
	case "add":
		if err := requireRootForMutation("http profile changes"); err != nil {
			output.WriteErrorf("%v", err)
			return daemon.ExitDenied
		}
		flags, err := parseFlags(args[1:])
		if err != nil {
			output.WriteErrorf("parse flags: %v", err)
			return daemon.ExitInvalid
		}
		timeout := 30
		if rawTimeout := strings.TrimSpace(flags["timeout"]); rawTimeout != "" {
			parsed, err := strconv.Atoi(rawTimeout)
			if err != nil {
				output.WriteErrorf("parse flags: timeout must be an integer")
				return daemon.ExitInvalid
			}
			timeout = parsed
		}
		profile := admin.HTTPProfile{
			Name:           flags["name"],
			BaseURL:        flags["base-url"],
			Headers:        parseHeaderCSV(flags["headers"]),
			TimeoutSeconds: timeout,
		}
		profiles, added, err := admin.AddHTTPProfile(paths, profile)
		if err != nil {
			output.WriteErrorf("add http profile: %v", err)
			return daemon.ExitConfigError
		}
		return writeJSON(map[string]any{
			"ok":      true,
			"added":   added,
			"profile": profile,
			"count":   len(profiles.Profiles),
			"source":  paths.HTTPProfilesFile,
		})
	case "remove":
		if err := requireRootForMutation("http profile changes"); err != nil {
			output.WriteErrorf("%v", err)
			return daemon.ExitDenied
		}
		if len(args) < 2 {
			output.WriteErrorf("usage: openscope http profiles remove <name>")
			return daemon.ExitInvalid
		}
		profiles, removed, err := admin.RemoveHTTPProfile(paths, args[1])
		if err != nil {
			output.WriteErrorf("remove http profile: %v", err)
			return daemon.ExitConfigError
		}
		return writeJSON(map[string]any{
			"ok":      true,
			"removed": removed,
			"name":    args[1],
			"count":   len(profiles.Profiles),
			"source":  paths.HTTPProfilesFile,
		})
	default:
		output.WriteErrorf("unknown http profiles command %q", args[0])
		return daemon.ExitInvalid
	}
}

func requireRootForMutation(scope string) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("%s require sudo so local agents cannot silently widen access", scope)
	}
	return nil
}

func runAgent(paths config.Paths, args []string) int {
	if len(args) == 0 {
		output.WriteErrorf("usage: openscope agent <register|list|skills>")
		return daemon.ExitInvalid
	}

	switch args[0] {
	case "register":
		if len(args) < 2 {
			output.WriteErrorf("usage: openscope agent register <agent_id>")
			return daemon.ExitInvalid
		}
		registry, created, err := agent.Register(paths, args[1])
		if err != nil {
			output.WriteErrorf("register agent: %v", err)
			return daemon.ExitConfigError
		}
		return writeJSON(map[string]any{
			"ok":      true,
			"created": created,
			"agent":   args[1],
			"agents":  registry.Agents,
		})
	case "list":
		registry, err := agent.LoadDefaultOrEmpty(paths)
		if err != nil {
			output.WriteErrorf("load agents: %v", err)
			return daemon.ExitConfigError
		}
		return writeJSON(registry)
	case "skills":
		return runAgentSkills(paths, args[1:])
	case "token":
		return runAgentToken(paths, args[1:])
	default:
		output.WriteErrorf("unknown agent command %q", args[0])
		return daemon.ExitInvalid
	}
}

// runAgentToken manages the network-broker token store
// (<config>/agent_tokens.yaml). Tokens authenticate agents on the daemon's
// HTTP listener; the daemon derives the agent identity from the token.
func runAgentToken(paths config.Paths, args []string) int {
	if len(args) == 0 {
		output.WriteErrorf("usage: openscope agent token <mint|list|revoke>")
		return daemon.ExitInvalid
	}

	pepper, err := authtoken.LoadPepper(paths.AuthPepper, paths.TokenPepperFile)
	if err != nil {
		output.WriteErrorf("load token pepper: %v", err)
		return daemon.ExitConfigError
	}
	store := &authtoken.FileStore{Path: paths.AgentTokensFile, Pepper: pepper}

	switch args[0] {
	case "mint":
		rest := args[1:]
		rotate := false
		if len(rest) > 0 && rest[0] == "--rotate" {
			rotate = true
			rest = rest[1:]
		}
		if len(rest) != 1 {
			output.WriteErrorf("usage: openscope agent token mint [--rotate] <agent_id>")
			return daemon.ExitInvalid
		}
		agentID := rest[0]
		// Minting implies the agent may act — register it like `agent register`.
		if _, _, err := agent.Register(paths, agentID); err != nil {
			output.WriteErrorf("register agent: %v", err)
			return daemon.ExitConfigError
		}
		token, err := store.Mint(agentID, rotate)
		if err != nil {
			output.WriteErrorf("mint token: %v", err)
			return daemon.ExitConfigError
		}
		return writeJSON(map[string]any{
			"ok":    true,
			"agent": agentID,
			// Shown exactly once — only the HMAC hash is stored.
			"token": token,
			"note":  "store this token now; it cannot be recovered later",
		})
	case "list":
		rows, err := store.List()
		if err != nil {
			output.WriteErrorf("list tokens: %v", err)
			return daemon.ExitConfigError
		}
		type tokenInfo struct {
			Agent     string `json:"agent"`
			Prefix    string `json:"prefix"`
			CreatedAt string `json:"created_at"`
			RevokedAt string `json:"revoked_at,omitempty"`
		}
		out := make([]tokenInfo, 0, len(rows))
		for _, row := range rows {
			info := tokenInfo{Agent: row.Agent, Prefix: row.Prefix, CreatedAt: row.CreatedAt.Format(time.RFC3339)}
			if row.RevokedAt != nil {
				info.RevokedAt = row.RevokedAt.Format(time.RFC3339)
			}
			out = append(out, info)
		}
		return writeJSON(map[string]any{"tokens": out})
	case "revoke":
		if len(args) != 2 {
			output.WriteErrorf("usage: openscope agent token revoke <agent_id|token_prefix>")
			return daemon.ExitInvalid
		}
		n, err := store.Revoke(args[1])
		if err != nil {
			output.WriteErrorf("revoke token: %v", err)
			return daemon.ExitConfigError
		}
		if n == 0 {
			output.WriteErrorf("no active token matches %q", args[1])
			return daemon.ExitNotFound
		}
		return writeJSON(map[string]any{"ok": true, "revoked": n})
	default:
		output.WriteErrorf("unknown agent token command %q", args[0])
		return daemon.ExitInvalid
	}
}

// runEnroll registers this deployment with the vendor control plane and
// persists the deployment token to <ConfigDir>/controlplane.yaml. The
// control plane is strictly optional — nothing requires enrollment.
func runEnroll(paths config.Paths, args []string) int {
	flags := map[string]string{}
	for i := 0; i+1 < len(args); i += 2 {
		if !strings.HasPrefix(args[i], "--") {
			output.WriteErrorf("usage: openscope enroll --control-plane <url> --code <enroll_code> [--name <deployment_name>] [--kind broker|router]")
			return daemon.ExitInvalid
		}
		flags[strings.TrimPrefix(args[i], "--")] = args[i+1]
	}
	url, code := flags["control-plane"], flags["code"]
	if url == "" || code == "" {
		output.WriteErrorf("usage: openscope enroll --control-plane <url> --code <enroll_code> [--name <deployment_name>] [--kind broker|router]")
		return daemon.ExitInvalid
	}
	name := flags["name"]
	if name == "" {
		if host, err := os.Hostname(); err == nil {
			name = host
		}
	}
	kind := flags["kind"]
	if kind == "" {
		kind = "broker"
	}

	result, err := cpclient.Enroll(url, code, name, kind, "dev")
	if err != nil {
		output.WriteErrorf("enroll: %v", err)
		return daemon.ExitExecutorError
	}
	enrollFile := filepath.Join(paths.ConfigDir, "controlplane.yaml")
	if err := cpclient.SaveEnrollment(enrollFile, cpclient.Enrollment{
		ControlPlaneURL: url,
		DeploymentID:    result.DeploymentID,
		DeploymentToken: result.DeploymentToken,
	}); err != nil {
		output.WriteErrorf("save enrollment: %v", err)
		return daemon.ExitConfigError
	}
	return writeJSON(map[string]any{
		"ok":            true,
		"deployment_id": result.DeploymentID,
		"saved_to":      enrollFile,
		"note":          "restart openscoped to start reporting usage metadata",
	})
}

func runAgentSkills(paths config.Paths, args []string) int {
	if len(args) < 2 || args[0] != "--agent" {
		output.WriteErrorf("usage: openscope agent skills --agent <agent_id>")
		return daemon.ExitInvalid
	}
	agentID := args[1]

	loaded, err := loadVisibleDefinitions(paths)
	if err != nil {
		output.WriteErrorf("load app definitions: %v", err)
		return daemon.ExitConfigError
	}

	pf, err := policy.LoadDefault(paths)
	if err != nil {
		output.WriteErrorf("load policy: %v", err)
		return daemon.ExitConfigError
	}

	sshTargets, _ := admin.LoadSSHTargetsOrDefault(paths)
	httpProfiles, _ := admin.LoadHTTPProfilesOrDefault(paths)
	systemCmds, _ := admin.LoadSystemCommandsOrDefault(paths)

	type skillEntry struct {
		App         string             `json:"app"`
		Action      string             `json:"action"`
		Description string             `json:"description"`
		Parameters  []appdef.Parameter `json:"parameters,omitempty"`
		Constraints map[string]string  `json:"constraints,omitempty"`
		Context     map[string]any     `json:"context,omitempty"`
	}

	var skills []skillEntry
	for _, rule := range pf.Rules {
		if rule.Effect != "allow" || rule.Agent != agentID {
			continue
		}
		entry, ok := loaded[rule.App]
		if !ok || !entry.Enabled {
			continue
		}
		action, ok := entry.Definition.Actions[rule.Action]
		if !ok {
			continue
		}

		skill := skillEntry{
			App:         rule.App,
			Action:      rule.Action,
			Description: action.Description,
			Parameters:  action.Parameters,
			Constraints: rule.Constraints,
		}

		if entry.Definition.App.Executor == "ssh" {
			skill.Context = buildSSHContext(sshTargets, rule.Constraints)
		}
		if entry.Definition.App.Executor == "http" {
			skill.Context = buildHTTPContext(httpProfiles, rule.Constraints)
		}
		if entry.Definition.App.Executor == "system" {
			skill.Context = buildSystemContext(systemCmds, rule.Constraints)
		}

		skills = append(skills, skill)
	}

	return writeJSON(map[string]any{
		"agent":  agentID,
		"skills": skills,
	})
}

func buildSSHContext(targets admin.SSHTargets, constraints map[string]string) map[string]any {
	ctx := map[string]any{}

	targetAlias := constraints["target"]
	if targetAlias != "" {
		if t, ok := admin.FindSSHTarget(targets, targetAlias); ok {
			ctx["target"] = map[string]any{
				"alias":                 t.Alias,
				"host":                  t.Host,
				"user":                  t.User,
				"allowed_services":      t.AllowedServices,
				"allowed_paths":         t.AllowedPaths,
				"allowed_path_prefixes": t.AllowedPathPrefixes,
			}
		}
		return ctx
	}

	// No target constraint — show all available targets
	if len(targets.Targets) > 0 {
		available := make([]map[string]any, 0, len(targets.Targets))
		for _, t := range targets.Targets {
			available = append(available, map[string]any{
				"alias":                 t.Alias,
				"host":                  t.Host,
				"user":                  t.User,
				"allowed_services":      t.AllowedServices,
				"allowed_paths":         t.AllowedPaths,
				"allowed_path_prefixes": t.AllowedPathPrefixes,
			})
		}
		ctx["available_targets"] = available
	}
	return ctx
}

func buildHTTPContext(profiles admin.HTTPProfiles, constraints map[string]string) map[string]any {
	ctx := map[string]any{}
	profileName := constraints["profile"]
	if profileName != "" {
		for _, p := range profiles.Profiles {
			if p.Name == profileName {
				ctx["profile"] = map[string]any{
					"name":     p.Name,
					"base_url": p.BaseURL,
				}
				break
			}
		}
		return ctx
	}
	if len(profiles.Profiles) > 0 {
		available := make([]map[string]any, 0, len(profiles.Profiles))
		for _, p := range profiles.Profiles {
			available = append(available, map[string]any{
				"name":     p.Name,
				"base_url": p.BaseURL,
			})
		}
		ctx["available_profiles"] = available
	}
	return ctx
}

func runStatus(paths config.Paths) int {
	return writeJSON(status.Snapshot(paths))
}

func runVersion(args []string) int {
	info := buildinfo.Get()
	for _, a := range args {
		if a == "--json" {
			return writeJSON(info)
		}
	}
	fmt.Println("openscope " + buildinfo.String())
	return daemon.ExitOK
}

func runDoctor(paths config.Paths, args []string) int {
	report := doctor.Run(paths)
	color := useColor()
	for _, a := range args {
		switch a {
		case "--json":
			return writeJSON(report)
		case "--no-color":
			color = false
		case "--color":
			color = true
		}
	}
	fmt.Print(report.Text(color))
	if !report.OK {
		return daemon.ExitConfigError
	}
	return daemon.ExitOK
}

// useColor reports whether to emit ANSI color on stdout: it must be a terminal,
// NO_COLOR (https://no-color.org) must be unset, and TERM must not be "dumb".
// Piped or redirected output (incl. `| cat`) gets plain text automatically.
func useColor() bool {
	if os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		return false
	}
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

func runProtectedAction(paths config.Paths, args []string) int {
	if len(args) < 2 {
		output.WriteErrorf("usage: openscope <app> <action> --agent <agent_id> [flags]")
		return daemon.ExitInvalid
	}

	params, err := parseFlags(args[2:])
	if err != nil {
		output.WriteErrorf("parse flags: %v", err)
		return daemon.ExitInvalid
	}

	agentID := params["agent"]
	if agentID == "" {
		output.WriteErrorf("missing required flag --agent")
		return daemon.ExitInvalid
	}

	mode := "json"
	if params["body-only"] == "true" {
		mode = "body-only"
		delete(params, "body-only")
	}
	delete(params, "agent")

	response, err := ipc.Call(paths, ipc.Request{
		App:    args[0],
		Action: args[1],
		Agent:  agentID,
		Params: params,
		Mode:   mode,
	})
	if err != nil {
		output.WriteErrorf("daemon unavailable: %v", err)
		return daemon.ExitIPCError
	}

	if !response.OK {
		output.WriteErrorf("%s", response.Error)
		return response.ExitCode
	}

	if mode == "body-only" {
		if body, ok := response.Data.(string); ok {
			_, _ = fmt.Fprint(os.Stdout, body)
			return daemon.ExitOK
		}
	}

	return writeJSON(output.Response{
		OK:     true,
		App:    response.App,
		Action: response.Action,
		Agent:  response.Agent,
		Data:   response.Data,
	})
}

func loadVisibleDefinitions(paths config.Paths) (map[string]loadedApp, error) {
	defs, err := loadAllDefinitions(paths)
	if err != nil {
		return nil, err
	}
	enabled, err := appdef.LoadEnabledFileOrEmpty(paths.EnabledAppsFile)
	if err != nil {
		return nil, err
	}
	return applyEnabledState(defs, enabled), nil
}

func loadAllDefinitions(paths config.Paths) (map[string]appdef.Definition, error) {
	defs := map[string]appdef.Definition{}

	bundled, err := loadBundledDefinitions()
	if err != nil {
		return nil, err
	}
	for _, def := range bundled {
		defs[def.App.Name] = def
	}

	userDefs, err := appdef.LoadDir(paths.AppsDir)
	if err != nil {
		return nil, err
	}
	for _, def := range userDefs {
		defs[def.App.Name] = def
	}

	return defs, nil
}

func loadBundledDefinitions() ([]appdef.Definition, error) {
	entries, err := resources.FS.ReadDir("bundled/apps")
	if err != nil {
		return nil, fmt.Errorf("read bundled app definitions: %w", err)
	}

	defs := make([]appdef.Definition, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		path := "bundled/apps/" + entry.Name()
		data, err := resources.FS.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read bundled app definition %s: %w", path, err)
		}
		def, err := appdef.Parse(data, path)
		if err != nil {
			return nil, err
		}
		def.Bundled = true
		def.ManifestPath = path
		defs = append(defs, def)
	}

	return defs, nil
}

func setAppEnabled(paths config.Paths, appName string, enabled bool) int {
	defs, err := loadAllDefinitions(paths)
	if err != nil {
		output.WriteErrorf("load app definitions: %v", err)
		return daemon.ExitConfigError
	}

	def, ok := defs[appName]
	if !ok {
		output.WriteErrorf("app %q not found", appName)
		return daemon.ExitNotFound
	}
	if def.Bundled {
		output.WriteErrorf("bundled app %q is always enabled", appName)
		return daemon.ExitInvalid
	}

	state, err := appdef.LoadEnabledFileOrEmpty(paths.EnabledAppsFile)
	if err != nil {
		output.WriteErrorf("load enabled apps: %v", err)
		return daemon.ExitConfigError
	}

	state.Apps = updateAppEnabledList(state.Apps, appName, enabled)
	if err := appdef.SaveEnabledFile(paths.EnabledAppsFile, state); err != nil {
		output.WriteErrorf("save enabled apps: %v", err)
		return daemon.ExitConfigError
	}

	return writeJSON(map[string]any{
		"ok":      true,
		"app":     appName,
		"enabled": enabled,
	})
}

func runAppActivation(paths config.Paths, activate bool, args []string) int {
	if err := requireRootForMutation("bundled passthrough app activation"); err != nil {
		output.WriteErrorf("%v", err)
		return daemon.ExitDenied
	}

	if len(args) < 3 || args[0] != "--agent" {
		verb := "activate"
		if !activate {
			verb = "deactivate"
		}
		output.WriteErrorf("usage: openscope app %s --agent <agent_id> <app> [app...]", verb)
		return daemon.ExitInvalid
	}

	agentID := args[1]
	appNames := args[2:]
	if agentID == "" || len(appNames) == 0 {
		output.WriteErrorf("usage: openscope app activate --agent <agent_id> <app> [app...]")
		return daemon.ExitInvalid
	}

	defs, err := loadAllDefinitions(paths)
	if err != nil {
		output.WriteErrorf("load app definitions: %v", err)
		return daemon.ExitConfigError
	}

	processed, exitCode, err := applyBundledPassthroughActivation(paths, defs, agentID, appNames, activate)
	if err != nil {
		output.WriteErrorf("%v", err)
		return exitCode
	}

	return writeJSON(map[string]any{
		"ok":      true,
		"agent":   agentID,
		"results": processed,
	})
}

func applyBundledPassthroughActivation(paths config.Paths, defs map[string]appdef.Definition, agentID string, appNames []string, activate bool) ([]map[string]any, int, error) {
	processed := make([]map[string]any, 0, len(appNames))
	for _, appName := range appNames {
		def, ok := defs[appName]
		if !ok {
			return nil, daemon.ExitNotFound, fmt.Errorf("app %q not found", appName)
		}
		if !def.Bundled {
			return nil, daemon.ExitInvalid, fmt.Errorf("app %q is not a bundled app", appName)
		}
		if def.App.SecurityMode != "passthrough" {
			return nil, daemon.ExitInvalid, fmt.Errorf("app %q is not a passthrough app", appName)
		}

		if activate {
			added := 0
			actionNames := sortedActionNames(def.Actions)
			for _, actionName := range actionNames {
				_, created, err := policy.AddRule(paths, policy.Rule{
					Effect: "allow",
					Agent:  agentID,
					App:    appName,
					Action: actionName,
				})
				if err != nil {
					return nil, daemon.ExitConfigError, fmt.Errorf("activate app %q: %v", appName, err)
				}
				if created {
					added++
				}
			}
			processed = append(processed, map[string]any{
				"app":         appName,
				"activated":   true,
				"rules_added": added,
			})
			continue
		}

		actionNames := make(map[string]struct{}, len(def.Actions))
		for actionName := range def.Actions {
			actionNames[actionName] = struct{}{}
		}
		_, removed, err := policy.RemoveRules(paths, func(rule policy.Rule) bool {
			if rule.Effect != "allow" || rule.Agent != agentID || rule.App != appName {
				return false
			}
			if _, ok := actionNames[rule.Action]; !ok {
				return false
			}
			return len(rule.Constraints) == 0
		})
		if err != nil {
			return nil, daemon.ExitConfigError, fmt.Errorf("deactivate app %q: %v", appName, err)
		}
		processed = append(processed, map[string]any{
			"app":           appName,
			"activated":     false,
			"rules_removed": removed,
		})
	}
	return processed, daemon.ExitOK, nil
}

func sortedActionNames(actions map[string]appdef.Action) []string {
	names := make([]string, 0, len(actions))
	for name := range actions {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func updateAppEnabledList(apps []string, appName string, enabled bool) []string {
	filtered := make([]string, 0, len(apps))
	for _, existing := range apps {
		if existing != appName {
			filtered = append(filtered, existing)
		}
	}
	if enabled {
		filtered = append(filtered, appName)
	}
	sort.Strings(filtered)
	return filtered
}

func parseFlags(args []string) (map[string]string, error) {
	params := map[string]string{}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if !strings.HasPrefix(arg, "--") {
			return nil, fmt.Errorf("unexpected argument %q", arg)
		}
		name := strings.TrimPrefix(arg, "--")
		if name == "" {
			return nil, fmt.Errorf("invalid flag %q", arg)
		}
		if i+1 >= len(args) || strings.HasPrefix(args[i+1], "--") {
			params[name] = "true"
			continue
		}
		params[name] = args[i+1]
		i++
	}
	return params, nil
}

func writeJSON(v any) int {
	if err := output.WriteJSON(v); err != nil {
		output.WriteErrorf("write json: %v", err)
		return daemon.ExitExecutorError
	}
	return daemon.ExitOK
}

func runSystemCommands(paths config.Paths, args []string) int {
	if len(args) == 0 {
		output.WriteErrorf("usage: openscope system commands <list|add-manager|remove-manager|add-package|remove-package|add-service|remove-service|add-app|remove-app|add-build-prefix|remove-build-prefix>")
		return daemon.ExitInvalid
	}

	switch args[0] {
	case "list":
		cmds, err := admin.LoadSystemCommandsOrDefault(paths)
		if err != nil {
			output.WriteErrorf("load system commands: %v", err)
			return daemon.ExitConfigError
		}
		return writeJSON(map[string]any{
			"config": cmds,
			"source": paths.SystemCommandsFile,
		})
	case "add-manager":
		if err := requireRootForMutation("system command changes"); err != nil {
			output.WriteErrorf("%v", err)
			return daemon.ExitDenied
		}
		flags, err := parseFlags(args[1:])
		if err != nil {
			output.WriteErrorf("parse flags: %v", err)
			return daemon.ExitInvalid
		}
		mgr := admin.ManagerConfig{
			Name:   flags["name"],
			Binary: flags["binary"],
			Sudo:   flags["sudo"] == "true",
		}
		cmds, added, err := admin.AddManager(paths, mgr)
		if err != nil {
			output.WriteErrorf("add manager: %v", err)
			return daemon.ExitConfigError
		}
		return writeJSON(map[string]any{
			"ok":      true,
			"added":   added,
			"manager": mgr,
			"count":   len(cmds.Packages.Managers),
			"source":  paths.SystemCommandsFile,
		})
	case "remove-manager":
		if err := requireRootForMutation("system command changes"); err != nil {
			output.WriteErrorf("%v", err)
			return daemon.ExitDenied
		}
		if len(args) < 2 {
			output.WriteErrorf("usage: openscope system commands remove-manager <name>")
			return daemon.ExitInvalid
		}
		cmds, removed, err := admin.RemoveManager(paths, args[1])
		if err != nil {
			output.WriteErrorf("remove manager: %v", err)
			return daemon.ExitConfigError
		}
		return writeJSON(map[string]any{
			"ok":      true,
			"removed": removed,
			"name":    args[1],
			"count":   len(cmds.Packages.Managers),
			"source":  paths.SystemCommandsFile,
		})
	case "add-package":
		if err := requireRootForMutation("system command changes"); err != nil {
			output.WriteErrorf("%v", err)
			return daemon.ExitDenied
		}
		if len(args) < 2 {
			output.WriteErrorf("usage: openscope system commands add-package <name>")
			return daemon.ExitInvalid
		}
		cmds, added, err := admin.AddAllowedPackage(paths, args[1])
		if err != nil {
			output.WriteErrorf("add package: %v", err)
			return daemon.ExitConfigError
		}
		return writeJSON(map[string]any{
			"ok":      true,
			"added":   added,
			"package": args[1],
			"count":   len(cmds.Packages.Allowed),
			"source":  paths.SystemCommandsFile,
		})
	case "remove-package":
		if err := requireRootForMutation("system command changes"); err != nil {
			output.WriteErrorf("%v", err)
			return daemon.ExitDenied
		}
		if len(args) < 2 {
			output.WriteErrorf("usage: openscope system commands remove-package <name>")
			return daemon.ExitInvalid
		}
		cmds, removed, err := admin.RemoveAllowedPackage(paths, args[1])
		if err != nil {
			output.WriteErrorf("remove package: %v", err)
			return daemon.ExitConfigError
		}
		return writeJSON(map[string]any{
			"ok":      true,
			"removed": removed,
			"package": args[1],
			"count":   len(cmds.Packages.Allowed),
			"source":  paths.SystemCommandsFile,
		})
	case "add-service":
		if err := requireRootForMutation("system command changes"); err != nil {
			output.WriteErrorf("%v", err)
			return daemon.ExitDenied
		}
		if len(args) < 2 {
			output.WriteErrorf("usage: openscope system commands add-service <name>")
			return daemon.ExitInvalid
		}
		cmds, added, err := admin.AddAllowedService(paths, args[1])
		if err != nil {
			output.WriteErrorf("add service: %v", err)
			return daemon.ExitConfigError
		}
		return writeJSON(map[string]any{
			"ok":      true,
			"added":   added,
			"service": args[1],
			"count":   len(cmds.Services.Allowed),
			"source":  paths.SystemCommandsFile,
		})
	case "remove-service":
		if err := requireRootForMutation("system command changes"); err != nil {
			output.WriteErrorf("%v", err)
			return daemon.ExitDenied
		}
		if len(args) < 2 {
			output.WriteErrorf("usage: openscope system commands remove-service <name>")
			return daemon.ExitInvalid
		}
		cmds, removed, err := admin.RemoveAllowedService(paths, args[1])
		if err != nil {
			output.WriteErrorf("remove service: %v", err)
			return daemon.ExitConfigError
		}
		return writeJSON(map[string]any{
			"ok":      true,
			"removed": removed,
			"service": args[1],
			"count":   len(cmds.Services.Allowed),
			"source":  paths.SystemCommandsFile,
		})
	case "add-app":
		if err := requireRootForMutation("system command changes"); err != nil {
			output.WriteErrorf("%v", err)
			return daemon.ExitDenied
		}
		if len(args) < 2 {
			output.WriteErrorf("usage: openscope system commands add-app <name>")
			return daemon.ExitInvalid
		}
		cmds, added, err := admin.AddAllowedApp(paths, args[1])
		if err != nil {
			output.WriteErrorf("add app: %v", err)
			return daemon.ExitConfigError
		}
		return writeJSON(map[string]any{
			"ok":     true,
			"added":  added,
			"app":    args[1],
			"count":  len(cmds.Apps.AllowedNames),
			"source": paths.SystemCommandsFile,
		})
	case "remove-app":
		if err := requireRootForMutation("system command changes"); err != nil {
			output.WriteErrorf("%v", err)
			return daemon.ExitDenied
		}
		if len(args) < 2 {
			output.WriteErrorf("usage: openscope system commands remove-app <name>")
			return daemon.ExitInvalid
		}
		cmds, removed, err := admin.RemoveAllowedApp(paths, args[1])
		if err != nil {
			output.WriteErrorf("remove app: %v", err)
			return daemon.ExitConfigError
		}
		return writeJSON(map[string]any{
			"ok":      true,
			"removed": removed,
			"app":     args[1],
			"count":   len(cmds.Apps.AllowedNames),
			"source":  paths.SystemCommandsFile,
		})
	case "add-build-prefix":
		if err := requireRootForMutation("system command changes"); err != nil {
			output.WriteErrorf("%v", err)
			return daemon.ExitDenied
		}
		if len(args) < 2 {
			output.WriteErrorf("usage: openscope system commands add-build-prefix <path>")
			return daemon.ExitInvalid
		}
		cmds, added, err := admin.AddBuildPrefix(paths, args[1])
		if err != nil {
			output.WriteErrorf("add build prefix: %v", err)
			return daemon.ExitConfigError
		}
		return writeJSON(map[string]any{
			"ok":     true,
			"added":  added,
			"prefix": args[1],
			"count":  len(cmds.Builds.AllowedProjectPrefixes),
			"source": paths.SystemCommandsFile,
		})
	case "remove-build-prefix":
		if err := requireRootForMutation("system command changes"); err != nil {
			output.WriteErrorf("%v", err)
			return daemon.ExitDenied
		}
		if len(args) < 2 {
			output.WriteErrorf("usage: openscope system commands remove-build-prefix <path>")
			return daemon.ExitInvalid
		}
		cmds, removed, err := admin.RemoveBuildPrefix(paths, args[1])
		if err != nil {
			output.WriteErrorf("remove build prefix: %v", err)
			return daemon.ExitConfigError
		}
		return writeJSON(map[string]any{
			"ok":      true,
			"removed": removed,
			"prefix":  args[1],
			"count":   len(cmds.Builds.AllowedProjectPrefixes),
			"source":  paths.SystemCommandsFile,
		})
	default:
		output.WriteErrorf("unknown system commands subcommand %q", args[0])
		return daemon.ExitInvalid
	}
}

func runSystemSudoers(paths config.Paths) int {
	cmds, err := admin.LoadSystemCommandsOrDefault(paths)
	if err != nil {
		output.WriteErrorf("load system commands: %v", err)
		return daemon.ExitConfigError
	}

	username := "root"
	if u, err := user.Current(); err == nil {
		username = u.Username
	}

	fmt.Print(systemexec.GenerateSudoers(cmds, username))
	return daemon.ExitOK
}

func buildSystemContext(cmds admin.SystemCommands, constraints map[string]string) map[string]any {
	ctx := map[string]any{}

	managerName := constraints["manager"]
	if managerName != "" {
		if mgr, ok := admin.FindManager(cmds, managerName); ok {
			ctx["manager"] = map[string]any{
				"name":   mgr.Name,
				"binary": mgr.Binary,
				"sudo":   mgr.Sudo,
			}
		}
	} else if len(cmds.Packages.Managers) > 0 {
		available := make([]map[string]any, 0, len(cmds.Packages.Managers))
		for _, mgr := range cmds.Packages.Managers {
			available = append(available, map[string]any{
				"name":   mgr.Name,
				"binary": mgr.Binary,
				"sudo":   mgr.Sudo,
			})
		}
		ctx["available_managers"] = available
	}

	if len(cmds.Packages.Allowed) > 0 {
		ctx["allowed_packages"] = cmds.Packages.Allowed
	}
	if len(cmds.Services.Allowed) > 0 {
		ctx["allowed_services"] = cmds.Services.Allowed
	}
	if len(cmds.Processes.AllowedNames) > 0 {
		ctx["allowed_processes"] = cmds.Processes.AllowedNames
	}
	if len(cmds.Processes.AllowedSignals) > 0 {
		ctx["allowed_signals"] = cmds.Processes.AllowedSignals
	}
	if len(cmds.Ports.Allowed) > 0 {
		ctx["allowed_ports"] = cmds.Ports.Allowed
	}
	if len(cmds.Apps.AllowedNames) > 0 {
		ctx["allowed_apps"] = cmds.Apps.AllowedNames
	}
	if len(cmds.Apps.AllowedInstallDirs) > 0 {
		ctx["allowed_install_dirs"] = cmds.Apps.AllowedInstallDirs
	}
	if len(cmds.Builds.AllowedProjectPrefixes) > 0 {
		ctx["allowed_build_prefixes"] = cmds.Builds.AllowedProjectPrefixes
	}
	if cmds.Services.AllowLaunchctl {
		ctx["launchctl_enabled"] = true
	}

	return ctx
}

func printUsage() {
	w := os.Stderr
	_, _ = fmt.Fprintln(w, "OpenScope — scoped access broker for AI agents")
	_, _ = fmt.Fprintln(w, "")
	_, _ = fmt.Fprintln(w, "Usage:")
	_, _ = fmt.Fprintln(w, "  openscope <app> <action> --agent <id> [--<param> <value> ...]")
	_, _ = fmt.Fprintln(w, "")
	_, _ = fmt.Fprintln(w, "Setup:")
	_, _ = fmt.Fprintln(w, "  init [--force]                    Initialize default config (~/.openscope/)")
	_, _ = fmt.Fprintln(w, "  version                           Show the installed version (--json for fields)")
	_, _ = fmt.Fprintln(w, "  status                            Show daemon and config status")
	_, _ = fmt.Fprintln(w, "  doctor [--json] [--no-color]      Run diagnostics (colored table by default; --json for scripts)")
	_, _ = fmt.Fprintln(w, "  plan --file <proposal.yaml>       Review a privilege proposal: consequences,")
	_, _ = fmt.Fprintln(w, "                                    lint findings, and bounds verdict (no sudo)")
	_, _ = fmt.Fprintln(w, "      [--json | --html [path]] [--no-open]   Machine output, or an HTML report")
	_, _ = fmt.Fprintln(w, "      [--skip-bypass-check]             Skip the live ~/.ssh→target bypass probe (offline/CI)")
	_, _ = fmt.Fprintln(w, "  apply --file <proposal.yaml>      Apply a reviewed proposal after confirmation (sudo);")
	_, _ = fmt.Fprintln(w, "                                    re-runs plan + verifies no ~/.ssh key can reach new")
	_, _ = fmt.Fprintln(w, "                                    SSH targets ([--skip-bypass-check] to override)")
	_, _ = fmt.Fprintln(w, "")
	_, _ = fmt.Fprintln(w, "Agents:")
	_, _ = fmt.Fprintln(w, "  agent register <id>               Register an agent")
	_, _ = fmt.Fprintln(w, "  agent list                        List registered agents")
	_, _ = fmt.Fprintln(w, "  agent skills --agent <id>         Show all provisioned actions for an agent")
	_, _ = fmt.Fprintln(w, "  agent token mint [--rotate] <id>  Mint a network-broker token (shown once)")
	_, _ = fmt.Fprintln(w, "  agent token list                  List token prefixes and status")
	_, _ = fmt.Fprintln(w, "  agent token revoke <id|prefix>    Revoke an agent token")
	_, _ = fmt.Fprintln(w, "")
	_, _ = fmt.Fprintln(w, "Control plane (optional):")
	_, _ = fmt.Fprintln(w, "  enroll --control-plane <url> --code <code>   Register this deployment")
	_, _ = fmt.Fprintln(w, "")
	_, _ = fmt.Fprintln(w, "Apps:")
	_, _ = fmt.Fprintln(w, "  app list                          List available apps and enabled status")
	_, _ = fmt.Fprintln(w, "  app show <app>                    Show app definition with actions")
	_, _ = fmt.Fprintln(w, "  app validate [file]               Validate app definitions")
	_, _ = fmt.Fprintln(w, "  app enable <app>                  Enable a user-defined app")
	_, _ = fmt.Fprintln(w, "  app disable <app>                 Disable a user-defined app")
	_, _ = fmt.Fprintln(w, "  app activate --agent <id> <app>   Allow agent access to all actions (sudo)")
	_, _ = fmt.Fprintln(w, "  app deactivate --agent <id> <app> Revoke agent access to all actions (sudo)")
	_, _ = fmt.Fprintln(w, "")
	_, _ = fmt.Fprintln(w, "Policy:")
	_, _ = fmt.Fprintln(w, "  policy list                       List all policy rules")
	_, _ = fmt.Fprintln(w, "  policy show --agent <id>          Show rules for an agent")
	_, _ = fmt.Fprintln(w, "  policy validate                   Validate the policy file")
	_, _ = fmt.Fprintln(w, "  policy allow --agent <id> --app <app> --action <action> [--<key> <val>]")
	_, _ = fmt.Fprintln(w, "                                    Add an allow rule (sudo)")
	_, _ = fmt.Fprintln(w, "  policy deny  --agent <id> --app <app> --action <action> [--<key> <val>]")
	_, _ = fmt.Fprintln(w, "                                    Add a deny rule (sudo)")
	_, _ = fmt.Fprintln(w, "")
	_, _ = fmt.Fprintln(w, "SSH targets:")
	_, _ = fmt.Fprintln(w, "  ssh targets list                  List configured SSH targets")
	_, _ = fmt.Fprintln(w, "  ssh targets add --alias <name> --host <host> --user <user>")
	_, _ = fmt.Fprintln(w, "      [--port <n>] [--identity-file <path>] [--proxy-jump <host>]")
	_, _ = fmt.Fprintln(w, "      [--services <a,b>] [--paths <a,b>] [--path-prefixes <a,b>]")
	_, _ = fmt.Fprintln(w, "                                    Add an SSH target (sudo)")
	_, _ = fmt.Fprintln(w, "  ssh targets remove <alias>        Remove an SSH target (sudo)")
	_, _ = fmt.Fprintln(w, "  ssh check-bypass [--target <alias>] [--json]")
	_, _ = fmt.Fprintln(w, "                                    Probe whether your ~/.ssh keys can reach")
	_, _ = fmt.Fprintln(w, "                                    brokered hosts directly (opt-in, outbound ssh)")
	_, _ = fmt.Fprintln(w, "")
	_, _ = fmt.Fprintln(w, "HTTP profiles:")
	_, _ = fmt.Fprintln(w, "  http profiles list                List configured HTTP profiles")
	_, _ = fmt.Fprintln(w, "  http profiles add --name <name> --base-url <url>")
	_, _ = fmt.Fprintln(w, "      [--headers <k=v,k=v>] [--timeout <sec>]")
	_, _ = fmt.Fprintln(w, "                                    Add an HTTP profile (sudo)")
	_, _ = fmt.Fprintln(w, "  http profiles remove <name>       Remove an HTTP profile (sudo)")
	_, _ = fmt.Fprintln(w, "")
	_, _ = fmt.Fprintln(w, "System commands:")
	_, _ = fmt.Fprintln(w, "  system commands list               List system commands config")
	_, _ = fmt.Fprintln(w, "  system commands add-manager --name <name> --binary <path> [--sudo]")
	_, _ = fmt.Fprintln(w, "                                    Add a package manager (sudo)")
	_, _ = fmt.Fprintln(w, "  system commands remove-manager <name>")
	_, _ = fmt.Fprintln(w, "                                    Remove a package manager (sudo)")
	_, _ = fmt.Fprintln(w, "  system commands add-package <name> Add an allowed package (sudo)")
	_, _ = fmt.Fprintln(w, "  system commands remove-package <name>")
	_, _ = fmt.Fprintln(w, "                                    Remove an allowed package (sudo)")
	_, _ = fmt.Fprintln(w, "  system commands add-service <name> Add an allowed service (sudo)")
	_, _ = fmt.Fprintln(w, "  system commands remove-service <name>")
	_, _ = fmt.Fprintln(w, "                                    Remove an allowed service (sudo)")
	_, _ = fmt.Fprintln(w, "  system commands add-app <name>    Add an allowed app name (sudo)")
	_, _ = fmt.Fprintln(w, "  system commands remove-app <name> Remove an allowed app name (sudo)")
	_, _ = fmt.Fprintln(w, "  system commands add-build-prefix <path>")
	_, _ = fmt.Fprintln(w, "                                    Add an allowed build project path prefix (sudo)")
	_, _ = fmt.Fprintln(w, "  system commands remove-build-prefix <path>")
	_, _ = fmt.Fprintln(w, "                                    Remove an allowed build project prefix (sudo)")
	_, _ = fmt.Fprintln(w, "  system sudoers                    Print sudoers entries for sudo-enabled managers")
	_, _ = fmt.Fprintln(w, "")
	_, _ = fmt.Fprintln(w, "Admin filters:")
	_, _ = fmt.Fprintln(w, "  notes blacklist list              List protected folder keywords")
	_, _ = fmt.Fprintln(w, "  notes blacklist add <keyword>     Add a protected folder keyword (sudo)")
	_, _ = fmt.Fprintln(w, "  notes blacklist remove <keyword>  Remove a protected folder keyword (sudo)")
	_, _ = fmt.Fprintln(w, "  mail domains list                 List allowed sender domains")
	_, _ = fmt.Fprintln(w, "  mail domains add <domain>         Add an allowed sender domain (sudo)")
	_, _ = fmt.Fprintln(w, "  mail domains remove <domain>      Remove an allowed sender domain (sudo)")
}

func parseCSV(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	values := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			values = append(values, part)
		}
	}
	return values
}

func parseHeaderCSV(raw string) map[string]string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	headers := map[string]string{}
	for _, part := range strings.Split(raw, ",") {
		key, value, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key == "" || value == "" {
			continue
		}
		headers[key] = value
	}
	if len(headers) == 0 {
		return nil
	}
	return headers
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

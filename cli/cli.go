// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/openscope/openscope/admin"
	"github.com/openscope/openscope/agent"
	"github.com/openscope/openscope/appdef"
	"github.com/openscope/openscope/config"
	"github.com/openscope/openscope/daemon"
	"github.com/openscope/openscope/doctor"
	"github.com/openscope/openscope/ipc"
	"github.com/openscope/openscope/output"
	"github.com/openscope/openscope/policy"
	"github.com/openscope/openscope/resources"
	"github.com/openscope/openscope/status"
)

func Run(args []string) int {
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
		return runDoctor(paths)
	default:
		return runProtectedAction(paths, args)
	}
}

func runApp(paths config.Paths, args []string) int {
	if len(args) == 0 {
		output.WriteErrorf("usage: openscope app <list|show|validate|enable|disable>")
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

func requireRootForMutation(scope string) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("%s require sudo so local agents cannot silently widen access", scope)
	}
	return nil
}

func runAgent(paths config.Paths, args []string) int {
	if len(args) == 0 {
		output.WriteErrorf("usage: openscope agent <register|list>")
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
	default:
		output.WriteErrorf("unknown agent command %q", args[0])
		return daemon.ExitInvalid
	}
}

func runStatus(paths config.Paths) int {
	return writeJSON(status.Snapshot(paths))
}

func runDoctor(paths config.Paths) int {
	return writeJSON(doctor.Run(paths))
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

func printUsage() {
	_, _ = fmt.Fprintln(os.Stderr, "usage: openscope <app> <action> [flags]")
	_, _ = fmt.Fprintln(os.Stderr, "       openscope init [--force]")
	_, _ = fmt.Fprintln(os.Stderr, "       openscope mail domains <list|add|remove> [domain]")
	_, _ = fmt.Fprintln(os.Stderr, "       openscope app <list|show|validate|enable|disable|activate|deactivate>")
	_, _ = fmt.Fprintln(os.Stderr, "       openscope policy <list|show|validate|allow|deny>")
	_, _ = fmt.Fprintln(os.Stderr, "       openscope agent <register|list>")
	_, _ = fmt.Fprintln(os.Stderr, "       openscope status")
	_, _ = fmt.Fprintln(os.Stderr, "       openscope doctor")
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package daemon

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/openscope/openscope/admin"
	"github.com/openscope/openscope/agent"
	"github.com/openscope/openscope/appdef"
	"github.com/openscope/openscope/audit"
	"github.com/openscope/openscope/config"
	"github.com/openscope/openscope/executor"
	appleexec "github.com/openscope/openscope/executor/applescript"
	"github.com/openscope/openscope/ipc"
	"github.com/openscope/openscope/output"
	"github.com/openscope/openscope/policy"
	"github.com/openscope/openscope/resources"
)

const (
	ExitOK            = 0
	ExitInvalid       = 2
	ExitDenied        = 3
	ExitNotFound      = 4
	ExitExecutorError = 5
	ExitConfigError   = 6
	ExitIPCError      = 7
)

type loadedApp struct {
	Definition appdef.Definition
	Enabled    bool
}

type Service struct {
	Paths     config.Paths
	Executors map[string]executor.Runner
}

func NewService(paths config.Paths) Service {
	return Service{
		Paths: paths,
		Executors: map[string]executor.Runner{
			"applescript": appleexec.Executor{},
		},
	}
}

func (s Service) Handle(request ipc.Request) ipc.Response {
	if request.App == "" || request.Action == "" || request.Agent == "" {
		return ipc.Response{OK: false, Error: "app, action, and agent are required", ExitCode: ExitInvalid}
	}

	loaded, err := s.loadVisibleDefinitions()
	if err != nil {
		return ipc.Response{OK: false, Error: fmt.Sprintf("load app definitions: %v", err), ExitCode: ExitConfigError}
	}

	entry, err := requireEnabledApp(loaded, request.App)
	if err != nil {
		return ipc.Response{OK: false, App: request.App, Action: request.Action, Agent: request.Agent, Error: err.Error(), ExitCode: ExitNotFound}
	}

	action, ok := entry.Definition.Action(request.Action)
	if !ok {
		return ipc.Response{OK: false, App: request.App, Action: request.Action, Agent: request.Agent, Error: fmt.Sprintf("unknown action %q for app %q", request.Action, request.App), ExitCode: ExitNotFound}
	}

	required := missingRequired(action.Parameters, request.Params)
	if len(required) > 0 {
		return ipc.Response{OK: false, App: request.App, Action: request.Action, Agent: request.Agent, Error: fmt.Sprintf("missing required flags: %s", strings.Join(required, ", ")), ExitCode: ExitInvalid}
	}

	registered, err := agent.IsRegistered(s.Paths, request.Agent)
	if err != nil {
		return ipc.Response{OK: false, Error: fmt.Sprintf("load agents: %v", err), ExitCode: ExitConfigError}
	}
	if !registered {
		s.recordAudit(audit.Event{
			Timestamp: time.Now().UTC(),
			Agent:     request.Agent,
			App:       entry.Definition.App.Name,
			Action:    request.Action,
			Params:    action.PolicyContext(request.Params),
			Decision:  "deny",
			Result:    "unregistered_agent",
			Reason:    "agent is not registered",
		})
		return ipc.Response{OK: false, App: request.App, Action: request.Action, Agent: request.Agent, Error: fmt.Sprintf("agent %q is not registered", request.Agent), ExitCode: ExitDenied}
	}

	actionContext := entry.Definition.PolicyContext(request.Action, request.Params)
	protected, err := admin.LoadProtectedFoldersOrDefault(s.Paths)
	if err != nil {
		return ipc.Response{OK: false, Error: fmt.Sprintf("load protected folder blacklist: %v", err), ExitCode: ExitConfigError}
	}
	if entry.Definition.App.Name == "notes" {
		if keyword, blocked := admin.MatchProtectedFolder(protected, actionContext["folder"]); blocked {
			reason := fmt.Sprintf("folder is protected by admin blacklist keyword %q", keyword)
			s.recordAudit(audit.Event{
				Timestamp: time.Now().UTC(),
				Agent:     request.Agent,
				App:       entry.Definition.App.Name,
				Action:    request.Action,
				Params:    actionContext,
				Decision:  "deny",
				Result:    "admin_blacklist",
				Reason:    reason,
			})
			return ipc.Response{OK: false, App: request.App, Action: request.Action, Agent: request.Agent, Error: reason, ExitCode: ExitDenied}
		}
	}
	if entry.Definition.App.Name == "mail" {
		if keyword, blocked := admin.MatchProtectedFolder(protected, actionContext["mailbox"]); blocked {
			reason := fmt.Sprintf("mailbox is protected by admin blacklist keyword %q", keyword)
			s.recordAudit(audit.Event{
				Timestamp: time.Now().UTC(),
				Agent:     request.Agent,
				App:       entry.Definition.App.Name,
				Action:    request.Action,
				Params:    actionContext,
				Decision:  "deny",
				Result:    "admin_blacklist",
				Reason:    reason,
			})
			return ipc.Response{OK: false, App: request.App, Action: request.Action, Agent: request.Agent, Error: reason, ExitCode: ExitDenied}
		}
	}

	pf, err := policy.LoadDefaultOrEmpty(s.Paths)
	if err != nil {
		return ipc.Response{OK: false, Error: fmt.Sprintf("load policy: %v", err), ExitCode: ExitConfigError}
	}

	decision := policy.Evaluate(pf, entry.Definition, request.Action, request.Agent, request.Params)
	if !decision.Allowed {
		s.recordAudit(audit.Event{
			Timestamp: time.Now().UTC(),
			Agent:     request.Agent,
			App:       entry.Definition.App.Name,
			Action:    request.Action,
			Params:    actionContext,
			Decision:  "deny",
			Result:    "denied",
			Reason:    decision.Reason,
		})
		return ipc.Response{OK: false, App: request.App, Action: request.Action, Agent: request.Agent, Error: decision.Reason, ExitCode: ExitDenied}
	}

	execRunner := s.executorFor(entry.Definition)
	result, err := execRunner.Run(entry.Definition, request.Action, request.Params)
	if err != nil {
		s.recordAudit(audit.Event{
			Timestamp: time.Now().UTC(),
			Agent:     request.Agent,
			App:       entry.Definition.App.Name,
			Action:    request.Action,
			Params:    actionContext,
			Decision:  "allow",
			Result:    "executor_error",
			Reason:    err.Error(),
		})
		return ipc.Response{OK: false, App: request.App, Action: request.Action, Agent: request.Agent, Error: fmt.Sprintf("execute action: %v", err), ExitCode: ExitExecutorError}
	}

	if result.ExitCode != 0 {
		message := strings.TrimSpace(result.Stderr)
		if message == "" {
			message = fmt.Sprintf("executor failed for %s %s", entry.Definition.App.Name, request.Action)
		}
		s.recordAudit(audit.Event{
			Timestamp: time.Now().UTC(),
			Agent:     request.Agent,
			App:       entry.Definition.App.Name,
			Action:    request.Action,
			Params:    actionContext,
			Decision:  "allow",
			Result:    "executor_failure",
			Reason:    message,
		})
		return ipc.Response{OK: false, App: request.App, Action: request.Action, Agent: request.Agent, Error: message, ExitCode: ExitExecutorError}
	}

	filteredOutput, filterErr := s.applyAdminFilters(entry.Definition.App.Name, request.Action, request.Mode, result.Stdout)
	if filterErr != nil {
		s.recordAudit(audit.Event{
			Timestamp: time.Now().UTC(),
			Agent:     request.Agent,
			App:       entry.Definition.App.Name,
			Action:    request.Action,
			Params:    actionContext,
			Decision:  "allow",
			Result:    "admin_filter_error",
			Reason:    filterErr.Error(),
		})
		return ipc.Response{OK: false, App: request.App, Action: request.Action, Agent: request.Agent, Error: filterErr.Error(), ExitCode: ExitConfigError}
	}

	s.recordAudit(audit.Event{
		Timestamp: time.Now().UTC(),
		Agent:     request.Agent,
		App:       entry.Definition.App.Name,
		Action:    request.Action,
		Params:    actionContext,
		Decision:  "allow",
		Result:    "success",
		Reason:    decision.Reason,
	})

	return ipc.Response{
		OK:       true,
		App:      request.App,
		Action:   request.Action,
		Agent:    request.Agent,
		Data:     filteredOutput,
		ExitCode: ExitOK,
	}
}

func (s Service) loadVisibleDefinitions() (map[string]loadedApp, error) {
	defs, err := loadAllDefinitions(s.Paths)
	if err != nil {
		return nil, err
	}
	enabled, err := appdef.LoadEnabledFileOrEmpty(s.Paths.EnabledAppsFile)
	if err != nil {
		return nil, err
	}

	loaded := make(map[string]loadedApp, len(defs))
	for name, def := range defs {
		loaded[name] = loadedApp{
			Definition: def,
			Enabled:    def.Bundled || contains(enabled.Apps, name),
		}
	}
	return loaded, nil
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

	sort.Slice(defs, func(i, j int) bool {
		return defs[i].App.Name < defs[j].App.Name
	})
	return defs, nil
}

func (s Service) recordAudit(event audit.Event) {
	_ = audit.Append(s.Paths.AuditFile, event)
}

func (s Service) executorFor(def appdef.Definition) executor.Runner {
	if runner, ok := s.Executors[def.App.Executor]; ok {
		return runner
	}
	return appleexec.Executor{}
}

func normalizeOutput(defMode, requestMode, stdout string) any {
	if requestMode == "body-only" {
		return stdout
	}
	if defMode == "json" {
		var decoded any
		if err := output.UnmarshalJSON([]byte(strings.TrimSpace(stdout)), &decoded); err == nil {
			return decoded
		}
	}
	return map[string]any{"raw": stdout}
}

func (s Service) applyAdminFilters(appName, actionName, requestMode, stdout string) (any, error) {
	decoded := normalizeOutput("json", requestMode, stdout)
	if requestMode == "body-only" || appName != "mail" {
		return decoded, nil
	}

	filters, err := admin.LoadMailFiltersOrDefault(s.Paths)
	if err != nil {
		return nil, fmt.Errorf("load mail filters: %w", err)
	}
	if len(filters.AllowedSenderDomains) == 0 {
		return decoded, nil
	}

	switch actionName {
	case "list_messages":
		items, ok := decoded.([]any)
		if !ok {
			return nil, fmt.Errorf("mail list_messages returned unexpected shape")
		}
		filtered := make([]any, 0, len(items))
		for _, item := range items {
			message, ok := item.(map[string]any)
			if !ok {
				continue
			}
			sender, _ := message["sender"].(string)
			if admin.SenderAllowed(filters, sender) {
				filtered = append(filtered, message)
			}
		}
		return filtered, nil
	case "read_message":
		message, ok := decoded.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("mail read_message returned unexpected shape")
		}
		sender, _ := message["sender"].(string)
		if !admin.SenderAllowed(filters, sender) {
			return nil, fmt.Errorf("sender domain is not allowed by admin mail filters")
		}
		return message, nil
	default:
		return decoded, nil
	}
}

func requireEnabledApp(defs map[string]loadedApp, name string) (loadedApp, error) {
	def, ok := defs[name]
	if !ok {
		return loadedApp{}, fmt.Errorf("unknown app %q", name)
	}
	if !def.Enabled {
		return loadedApp{}, fmt.Errorf("app %q is installed but not enabled", name)
	}
	return def, nil
}

func missingRequired(parameters []appdef.Parameter, values map[string]string) []string {
	var missing []string
	for _, parameter := range parameters {
		if parameter.Required && strings.TrimSpace(values[parameter.Name]) == "" {
			missing = append(missing, "--"+parameter.Name)
		}
	}
	return missing
}

func contains(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}

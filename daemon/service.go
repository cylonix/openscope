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
	"github.com/openscope/openscope/cpclient"
	"github.com/openscope/openscope/executor"
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
	ExitRateLimited   = 8
)

type loadedApp struct {
	Definition appdef.Definition
	Enabled    bool
}

type Service struct {
	Paths     config.Paths
	Executors map[string]executor.Runner

	// Usage, when set, receives one metadata-only event per audited
	// decision (the control-plane metering hook). It must be non-blocking;
	// cpclient.Client.Record satisfies that. Never receives params/bodies.
	Usage func(cpclient.UsageEvent)

	// meta carries per-request transport context (set by HandleWithMeta on
	// the value copy; Service is used by value so this never races).
	meta RequestMeta
}

// RequestMeta is transport context recorded on audit events. Empty for
// local Unix-socket requests.
type RequestMeta struct {
	RequestID   string
	Transport   string // "unix" | "http"
	RemoteAddr  string
	TokenPrefix string
}

func NewService(paths config.Paths) Service {
	return Service{
		Paths:     paths,
		Executors: defaultExecutors(paths),
	}
}

// HandleWithMeta runs Handle with transport context attached to every audit
// event the request produces.
func (s Service) HandleWithMeta(request ipc.Request, meta RequestMeta) ipc.Response {
	s.meta = meta
	return s.Handle(request)
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
			// RootApplied apps came through `sudo openscope apply` (human-reviewed,
			// root-owned) — enabled without a separate opt-in, like bundled apps.
			Enabled: def.Bundled || def.RootApplied || contains(enabled.Apps, name),
		}
	}
	return loaded, nil
}

func loadAllDefinitions(paths config.Paths) (map[string]appdef.Definition, error) {
	bundled, err := loadBundledDefinitions()
	if err != nil {
		return nil, err
	}
	// Pinned precedence: bundled (trusted) → apps.d (user) → root applied
	// registry (authoritative). In SystemMode a privilege boundary exists, so
	// command-template verbs from the user-writable apps.d are dropped — an
	// approved command must come from a trusted, agent-unwritable source.
	return appdef.AssembleDefinitions(bundled, paths.AppsDir, paths.AppDefinitionsFile, config.SystemMode())
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
	event.RequestID = s.meta.RequestID
	event.Transport = s.meta.Transport
	event.RemoteAddr = s.meta.RemoteAddr
	event.TokenPrefix = s.meta.TokenPrefix
	_ = audit.Append(s.Paths.AuditFile, event)

	// Control-plane metering: the audit event minus params (metadata only).
	if s.Usage != nil {
		s.Usage(cpclient.UsageEvent{
			Timestamp: event.Timestamp,
			RequestID: event.RequestID,
			Kind:      "action",
			App:       event.App,
			Action:    event.Action,
			Decision:  event.Decision,
			Result:    event.Result,
		})
	}
}

// executorFor returns the runner for the app's declared executor, or an
// error runner when the executor is unknown or unavailable on this
// platform (e.g. applescript on a Linux broker). It must never silently
// fall back to a different executor.
func (s Service) executorFor(def appdef.Definition) executor.Runner {
	if runner, ok := s.Executors[def.App.Executor]; ok {
		return runner
	}
	return unavailableExecutor{name: def.App.Executor}
}

type unavailableExecutor struct{ name string }

func (u unavailableExecutor) Run(appdef.Definition, string, map[string]string) (executor.Result, error) {
	return executor.Result{}, fmt.Errorf("executor %q is not available on this platform", u.name)
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

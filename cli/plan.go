// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/openscope/openscope/admin"
	"github.com/openscope/openscope/appdef"
	"github.com/openscope/openscope/audit"
	"github.com/openscope/openscope/config"
	"github.com/openscope/openscope/daemon"
	"github.com/openscope/openscope/executor/sshexec"
	"github.com/openscope/openscope/ipc"
	"github.com/openscope/openscope/output"
	"github.com/openscope/openscope/policy"
	"github.com/openscope/openscope/proposal"
)

// parallelPathRunner is the ssh runner the LOCAL fallback read uses (apply-as-root,
// when the daemon is unreachable); nil selects the default os/exec runner. Tests
// override it to avoid real network.
var parallelPathRunner sshexec.CommandRunner

// brokerKeyReadable reports whether the broker's root-owned identity file can be read
// in this process — true at apply (root), false at plan (the invoking user). Used only
// to decide whether the LOCAL fallback read is possible when the daemon is unreachable.
// Overridable in tests.
var brokerKeyReadable = func(path string) bool {
	if path == "" {
		return false
	}
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	_ = f.Close()
	return true
}

// inspectBypassViaDaemon asks the daemon (root, holds the broker key) to read the
// target's authorized_keys and compare against keys' fingerprints, returning the
// verdicts (per key; a broker-key rejection is one target-level result with Key
// empty). The authorized_keys content never leaves the daemon. reached=false
// means the daemon is unreachable, so the caller can fall back to a local read or
// defer. Overridable in tests.
var inspectBypassViaDaemon = func(paths config.Paths, agentID string, target admin.SSHTarget, keys []sshexec.UserKey) (results []sshexec.BypassResult, reached bool) {
	tj, err := json.Marshal(target)
	if err != nil {
		return nil, false
	}
	kj, err := json.Marshal(keys)
	if err != nil {
		return nil, false
	}
	resp, err := ipc.Call(paths, ipc.Request{
		App:    "ssh",
		Action: "inspect_bypass",
		Agent:  agentID,
		Params: map[string]string{"target": string(tj), "keys": string(kj)},
	})
	if err != nil {
		return nil, false // daemon unreachable
	}
	if resp.ExitCode == daemon.ExitNotFound {
		return nil, false // older daemon without the inspect_bypass built-in → defer/fallback
	}
	if !resp.OK {
		// reached but rejected (custody gate, bad target) → inconclusive, fail closed.
		out := make([]sshexec.BypassResult, 0, len(keys))
		for _, k := range keys {
			out = append(out, sshexec.BypassResult{Target: target.Alias, Host: target.Host, Key: k.Path, Outcome: sshexec.BypassUnknown, Detail: resp.Error})
		}
		return out, true
	}
	// resp.Data round-trips through JSON (any); re-decode into typed results.
	b, _ := json.Marshal(resp.Data)
	_ = json.Unmarshal(b, &results)
	return results, true
}

// localOperator labels who ran the inspection in the daemon's audit (best-effort).
func localOperator() string {
	if u := os.Getenv("SUDO_USER"); u != "" {
		return u
	}
	if u, err := user.Current(); err == nil && u.Username != "" {
		return u.Username
	}
	return "operator"
}

// runLiveBypass verifies — without ever attempting a failed auth — that none of the
// invoking user's ~/.ssh keys can reach the proposal's new SSH targets directly (which
// would bypass the broker). It asks the daemon (root, holds the broker key) to read
// each target's authorized_keys and compare against the user's key fingerprints, then
// folds the verdict into the plan via ApplyBypassResults: a present key, a target that
// rejects the broker key, or an inconclusive read → blocking SSH-BYPASS (fail closed),
// all-absent → SSH-NO-BYPASS pass. No sudo needed. If the daemon is unreachable it
// falls back to a local read where the broker key is readable (apply-as-root), else
// defers (the static SSH-PARALLEL-PATH finding stands). No-op without new targets or
// ~/.ssh keys. --skip-bypass-check skips it.
func runLiveBypass(paths config.Paths, plan *proposal.Plan) {
	p := plan.Proposal
	if len(p.SSHTargets.Add) == 0 {
		return
	}
	keyPaths := sshexec.DiscoverUserKeys(paths.HomeDir)
	if len(keyPaths) == 0 {
		return // no ~/.ssh keys → no parallel path possible; nothing to verify
	}
	keys := sshexec.LocalUserKeys(keyPaths)
	agentID := localOperator()
	var bypass, brokerRejected, unknown, deferred []sshexec.BypassResult
	inspected := 0
	for _, t := range p.SSHTargets.Add {
		target := admin.NormalizeSSHTarget(t)
		results, reached := inspectBypassViaDaemon(paths, agentID, target, keys)
		if !reached && brokerKeyReadable(target.IdentityFile) {
			results, reached = sshexec.InspectBypass(target, keys, parallelPathRunner), true
		}
		if !reached {
			// Not inspected (daemon down and broker key unreadable here). Held
			// separately: an all-deferred run defers gracefully below, but a
			// PARTIALLY inspected run must fold these in as unknown so the pass
			// verdict can't silently cover a target that was never checked.
			deferred = append(deferred, sshexec.BypassResult{
				Target: target.Alias, Host: target.Host, Outcome: sshexec.BypassUnknown,
				Detail: "not inspected — daemon unreachable and the broker key is not readable here",
			})
			continue
		}
		inspected++
		for _, r := range results {
			switch r.Outcome {
			case sshexec.BypassFound:
				bypass = append(bypass, r)
			case sshexec.BypassBrokerKeyRejected:
				brokerRejected = append(brokerRejected, r)
			case sshexec.BypassClear:
				// conclusively rejected — the one outcome that may pass
			default:
				// BypassUnknown and any outcome this CLI doesn't know (a newer
				// daemon) — fail closed: an unrecognized verdict is not a pass.
				unknown = append(unknown, r)
			}
		}
	}
	if inspected == 0 {
		fmt.Fprintln(os.Stderr, "==> Parallel-path check deferred (daemon unreachable and the broker key is root-only); the static SSH-PARALLEL-PATH finding stands")
		return
	}
	unknown = append(unknown, deferred...)
	fmt.Fprintf(os.Stderr, "==> Parallel-path check: inspected %d target(s) via the daemon (broker-key read, no auth attempt), compared %d ~/.ssh key(s)\n",
		inspected, len(keys))
	plan.ApplyBypassResults(bypass, brokerRejected, unknown)
}

func boundsPath(paths config.Paths) string {
	return filepath.Join(paths.AdminDir, "bounds.yaml")
}

func loadDefsForPlan(paths config.Paths) (map[string]appdef.Definition, error) {
	loaded, err := loadVisibleDefinitions(paths)
	if err != nil {
		return nil, err
	}
	defs := make(map[string]appdef.Definition, len(loaded))
	for name, app := range loaded {
		defs[name] = app.Definition
	}
	return defs, nil
}

func machineInfo(paths config.Paths) proposal.MachineInfo {
	username := "user"
	if u, err := user.Current(); err == nil && u.Username != "" {
		username = u.Username
	}
	if sudo := os.Getenv("SUDO_USER"); sudo != "" {
		username = sudo
	}
	host, _ := os.Hostname()
	_, statErr := os.Stat(paths.SocketPath)
	return proposal.MachineInfo{
		User:          username,
		Host:          host,
		OS:            runtime.GOOS,
		DaemonRunning: statErr == nil,
		HomeDir:       paths.HomeDir,
	}
}

func buildPlanFor(paths config.Paths, file string) (proposal.Plan, proposal.LiveState, error) {
	p, err := proposal.Load(file)
	if err != nil {
		return proposal.Plan{}, proposal.LiveState{}, err
	}
	live, err := proposal.LoadLiveState(paths)
	if err != nil {
		return proposal.Plan{}, proposal.LiveState{}, err
	}
	defs, err := loadDefsForPlan(paths)
	if err != nil {
		return proposal.Plan{}, proposal.LiveState{}, err
	}
	bounds, fromFile, err := proposal.LoadBounds(boundsPath(paths))
	if err != nil {
		return proposal.Plan{}, proposal.LiveState{}, err
	}
	src := "default (no bounds.yaml — opinionated defaults)"
	if fromFile {
		src = boundsPath(paths)
	}
	return proposal.BuildPlan(p, live, defs, bounds, src, machineInfo(paths)), live, nil
}

func runPlan(paths config.Paths, args []string) int {
	flags, err := parseFlags(args)
	if err != nil {
		output.WriteErrorf("%v", err)
		return daemon.ExitInvalid
	}
	file := flags["file"]
	if file == "" {
		output.WriteErrorf("usage: openscope plan --file <proposal.yaml> [--json | --html [path]] [--no-open] [--skip-bypass-check]")
		return daemon.ExitInvalid
	}

	plan, _, err := buildPlanFor(paths, file)
	if err != nil {
		output.WriteErrorf("plan: %v", err)
		return daemon.ExitConfigError
	}

	// Verify the parallel path live BY DEFAULT (the one thing plan can't settle
	// statically): probe the proposed targets with the user's ~/.ssh keys and
	// fold the verdict in, so the report below DETECTS a bypass rather than
	// merely warning about a potential one. --skip-bypass-check stays offline for
	// CI / unreachable hosts (the SSH-PARALLEL-PATH warning remains).
	if flags["skip-bypass-check"] != "true" {
		runLiveBypass(paths, &plan)
	}

	switch {
	case flags["json"] == "true":
		if code := writeJSON(plan.JSON()); code != daemon.ExitOK {
			return code
		}
	case flags["html"] != "":
		path, err := writeHTMLReport(plan, flags["html"])
		if err != nil {
			output.WriteErrorf("plan: write html: %v", err)
			return daemon.ExitConfigError
		}
		fmt.Printf("wrote HTML report: %s\n", path)
		if flags["no-open"] != "true" {
			if err := openInBrowser(path); err != nil {
				output.WriteErrorf("could not launch browser (%v); open it manually: file://%s", err, path)
			}
		}
	default:
		fmt.Print(proposal.RenderText(plan))
	}

	if plan.Blocked {
		return daemon.ExitDenied
	}
	return daemon.ExitOK
}

// writeHTMLReport renders the plan to HTML. flag is "true" (bare --html → a
// temp file) or an explicit output path.
func writeHTMLReport(plan proposal.Plan, flag string) (string, error) {
	htmlDoc := proposal.RenderHTML(plan)
	if flag == "true" {
		f, err := os.CreateTemp("", "openscope-plan-*.html")
		if err != nil {
			return "", err
		}
		defer f.Close()
		if _, err := f.WriteString(htmlDoc); err != nil {
			return "", err
		}
		return f.Name(), nil
	}
	if err := os.WriteFile(flag, []byte(htmlDoc), 0o644); err != nil {
		return "", err
	}
	return flag, nil
}

// openInBrowser opens path in the default browser (best-effort, non-blocking).
func openInBrowser(path string) error {
	var name string
	var args []string
	switch runtime.GOOS {
	case "darwin":
		name, args = "open", []string{path}
	case "windows":
		name, args = "cmd", []string{"/c", "start", "", path}
	default:
		name, args = "xdg-open", []string{path}
	}
	return exec.Command(name, args...).Start()
}

func runApply(paths config.Paths, args []string) int {
	flags, err := parseFlags(args)
	if err != nil {
		output.WriteErrorf("%v", err)
		return daemon.ExitInvalid
	}
	file := flags["file"]
	if file == "" {
		output.WriteErrorf("usage: sudo openscope apply --file <proposal.yaml> [--expect-hash <sha>] [--yes] [--skip-bypass-check]")
		return daemon.ExitInvalid
	}
	if err := requireRootForMutation("proposal apply"); err != nil {
		output.WriteErrorf("%v", err)
		return daemon.ExitDenied
	}

	plan, live, err := buildPlanFor(paths, file)
	if err != nil {
		output.WriteErrorf("apply: %v", err)
		return daemon.ExitConfigError
	}
	p := plan.Proposal

	if want := flags["expect-hash"]; want != "" {
		if len(want) < 8 {
			output.WriteErrorf("--expect-hash %q is too short; use at least 8 hex chars (or the full sha256)", want)
			return daemon.ExitInvalid
		}
		if !strings.HasPrefix(p.SHA256, want) {
			output.WriteErrorf("proposal hash %s does not match --expect-hash %s; refusing", p.SHA256, want)
			return daemon.ExitDenied
		}
	}

	// Verify the parallel path live before granting access (the moment it
	// matters): a brokered SSH target is only a real boundary if the agent can't
	// already reach the host with one of its own ~/.ssh keys. Custody of the
	// broker's root-owned key (checked statically) is necessary but NOT
	// sufficient. The verdict folds into the plan as a blocking SSH-BYPASS
	// finding, so the plan.Blocked gate below refuses it — fail closed.
	if flags["skip-bypass-check"] == "true" {
		output.WriteErrorf("WARNING: --skip-bypass-check — NOT verifying that your ~/.ssh keys are unable to reach the new target(s); the broker boundary is unproven")
	} else {
		runLiveBypass(paths, &plan)
	}

	// apply runs the SAME plan as `openscope plan` and refuses unless it passes —
	// there is no flag to apply an un-planned or blocked proposal. Re-rendering
	// the full report from the file we actually read also makes apply
	// self-contained and any plan→apply tampering visible here.
	fmt.Println("==> Preflight: planning the proposal (identical gate to `openscope plan`)…")
	fmt.Print(proposal.RenderText(plan))

	if plan.Blocked {
		output.WriteErrorf("apply refused: plan is BLOCKED by %d bounds violation(s) — resolve the proposal (see the fixes above) or widen %s as root",
			len(plan.Blocking), boundsPath(paths))
		return daemon.ExitDenied
	}

	// High findings require typed acknowledgment; --yes cannot cover them.
	if len(plan.Acknowledge) > 0 {
		if flags["yes"] == "true" {
			output.WriteErrorf("apply refused: --yes cannot bypass %d high finding(s); confirm interactively", len(plan.Acknowledge))
			return daemon.ExitDenied
		}
		if err := confirmAcknowledgements(plan.Acknowledge); err != nil {
			output.WriteErrorf("apply aborted: %v", err)
			return daemon.ExitDenied
		}
	}

	if err := applyProposal(paths, p, live.System); err != nil {
		output.WriteErrorf("apply: %v", err)
		return daemon.ExitExecutorError
	}

	if err := writeAttestation(paths, p); err != nil {
		output.WriteErrorf("apply: write attestation: %v", err)
		return daemon.ExitConfigError
	}

	return writeJSON(map[string]any{
		"ok":           true,
		"applied":      true,
		"proposal":     p.Metadata.Name,
		"proposal_sha": p.SHA256,
		"ssh_targets":  len(p.SSHTargets.Add),
		"verbs":        len(p.Apps.Add),
		"policy_rules": len(p.Policy.Add),
		"acknowledged": len(plan.Acknowledge),
	})
}

// confirmAcknowledgements prompts (on /dev/tty, never stdin) for each high
// finding; the operator must type the flagged resource to proceed.
func confirmAcknowledgements(findings []proposal.Finding) error {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("no interactive terminal for confirmation: %w", err)
	}
	defer tty.Close()
	reader := bufio.NewReader(tty)
	for i, f := range findings {
		// Echo the EXACT string to type — "the resource name" alone left people
		// hunting for which token on the header line they had to enter.
		fmt.Fprintf(tty, "\n[%d/%d] HIGH %s — %s\n  %s\n  To confirm, type exactly:  %s\n  (blank aborts) > ",
			i+1, len(findings), f.RuleID, f.Resource, f.Summary, f.Resource)
		line, _ := reader.ReadString('\n')
		if strings.TrimSpace(line) != strings.TrimSpace(f.Resource) {
			return fmt.Errorf("confirmation for %q did not match", f.Resource)
		}
	}
	return nil
}

// applyProposal writes the proposal through the existing validated admin code
// paths. It is transactional: the four mutated files are snapshotted up front
// and restored on any error, so a mid-sequence failure never leaves a
// partially-applied, inconsistent config. Factored out (no euid check) so tests
// can exercise it with temp paths. liveSystem is the same snapshot the plan/
// bounds gate evaluated, so the effective config written matches what was
// reviewed (no TOCTOU against a second live read).
func applyProposal(paths config.Paths, p proposal.Proposal, liveSystem admin.SystemCommands) error {
	snap := snapshotFiles(paths.SSHTargetsFile, paths.SystemCommandsFile, paths.PoliciesFile, paths.AppDefinitionsFile)

	if err := applyMutations(paths, p, liveSystem); err != nil {
		restoreFiles(snap)
		return fmt.Errorf("%w (no changes applied — config restored)", err)
	}

	// Policy now lives root-owned in the admin dir; drop any legacy user-owned
	// copy so there is a single, agent-unwritable source of truth.
	migratePolicyLocation(paths)

	// Order matters: create the files first, THEN hand them back to the
	// invoking user, so root-created files aren't left unreadable by the daemon.
	auditApply(paths, p)
	chownTreeToInvoker(paths)
	return nil
}

// migratePolicyLocation removes the legacy user-owned policies.yaml once policy
// has been written to its root-owned admin-dir location. apply runs as root, so
// the unlink succeeds regardless of the legacy file's owner. Only runs after a
// successful apply (the new file exists), so a failed apply never strands the
// install without a policy.
func migratePolicyLocation(paths config.Paths) {
	if paths.LegacyPoliciesFile == "" || paths.LegacyPoliciesFile == paths.PoliciesFile {
		return
	}
	if _, err := os.Stat(paths.PoliciesFile); err != nil {
		return // new location not written — leave the legacy file in place
	}
	if _, err := os.Stat(paths.LegacyPoliciesFile); err == nil {
		_ = os.Remove(paths.LegacyPoliciesFile)
	}
}

func applyMutations(paths config.Paths, p proposal.Proposal, liveSystem admin.SystemCommands) error {
	for _, alias := range p.SSHTargets.Remove {
		if _, _, err := admin.RemoveSSHTarget(paths, alias); err != nil {
			return fmt.Errorf("remove ssh target %q: %w", alias, err)
		}
	}
	for _, t := range p.SSHTargets.Add {
		_, added, err := admin.AddSSHTarget(paths, t)
		if err != nil {
			return fmt.Errorf("add ssh target %q: %w", t.Alias, err)
		}
		if !added {
			// AddSSHTarget keeps the live target on alias collision. Compare a
			// NORMALIZED proposed target against the stored one so unsorted /
			// whitespaced lists don't trigger a spurious conflict.
			norm := admin.NormalizeSSHTarget(t)
			if existing, ok := admin.FindSSHTarget(mustLoadTargets(paths), t.Alias); ok && !sshTargetEqual(existing, norm) {
				return fmt.Errorf("ssh target %q already exists with different settings; remove it first or use a replace", t.Alias)
			}
		}
	}

	for _, alias := range p.SSMTargets.Remove {
		if _, _, err := admin.RemoveSSMTarget(paths, alias); err != nil {
			return fmt.Errorf("remove ssm target %q: %w", alias, err)
		}
	}
	for _, t := range p.SSMTargets.Add {
		if _, _, err := admin.AddSSMTarget(paths, t); err != nil {
			return fmt.Errorf("add ssm target %q: %w", t.Alias, err)
		}
	}

	eff := p.EffectiveSystem(liveSystem)
	if err := admin.SaveDefaultSystemCommands(paths, eff); err != nil {
		return fmt.Errorf("write system commands: %w", err)
	}

	// Verb definitions land in the root-owned registry BEFORE the policy rules,
	// so a freshly-granted rule already has the verb it points at.
	if err := applyAppDefinitions(paths, p); err != nil {
		return err
	}

	for _, r := range p.Policy.Remove {
		if _, _, err := policy.RemoveRules(paths, func(x policy.Rule) bool { return ruleEqual(x, r) }); err != nil {
			return fmt.Errorf("remove policy rule: %w", err)
		}
	}
	for _, r := range p.Policy.Add {
		if _, _, err := policy.AddRule(paths, r); err != nil {
			return fmt.Errorf("add policy rule: %w", err)
		}
	}
	return nil
}

// applyAppDefinitions folds the proposal's verb deltas into the root-owned
// applied-verb registry: removals first, then adds (action-level merge). It then
// re-assembles the full namespace to prove the daemon will be able to load it
// with the new registry — a failure here rolls back the whole apply, so a
// corrupt registry can never be committed.
func applyAppDefinitions(paths config.Paths, p proposal.Proposal) error {
	if len(p.Apps.Add) == 0 && len(p.Apps.Remove) == 0 {
		return nil
	}
	list, err := appdef.LoadAppliedFile(paths.AppDefinitionsFile)
	if err != nil {
		return fmt.Errorf("load applied app definitions: %w", err)
	}
	for _, r := range p.Apps.Remove {
		list = appdef.RemoveDefinitionAction(list, r.App, r.Action)
	}
	for _, d := range p.Apps.Add {
		list, err = appdef.MergeDefinitionList(list, d)
		if err != nil {
			return fmt.Errorf("merge verb %q: %w", d.App.Name, err)
		}
	}
	if err := appdef.SaveAppliedFile(paths.AppDefinitionsFile, list); err != nil {
		return fmt.Errorf("write applied app definitions: %w", err)
	}
	if _, err := loadAllDefinitions(paths); err != nil {
		return fmt.Errorf("applied app definitions would not load: %w", err)
	}
	return nil
}

func mustLoadTargets(paths config.Paths) admin.SSHTargets {
	t, _ := admin.LoadSSHTargetsOrDefault(paths)
	return t
}

func sshTargetEqual(a, b admin.SSHTarget) bool {
	return a.Host == b.Host && a.User == b.User && a.Port == b.Port &&
		a.IdentityFile == b.IdentityFile && a.ProxyJump == b.ProxyJump &&
		strings.Join(a.AllowedServices, ",") == strings.Join(b.AllowedServices, ",") &&
		strings.Join(a.AllowedPaths, ",") == strings.Join(b.AllowedPaths, ",") &&
		strings.Join(a.AllowedPathPrefixes, ",") == strings.Join(b.AllowedPathPrefixes, ",") &&
		strings.Join(a.AllowedUploadSources, ",") == strings.Join(b.AllowedUploadSources, ",")
}

type fileSnapshot struct {
	path    string
	data    []byte
	existed bool
	mode    os.FileMode
}

func snapshotFiles(pathList ...string) []fileSnapshot {
	snaps := make([]fileSnapshot, 0, len(pathList))
	for _, path := range pathList {
		s := fileSnapshot{path: path}
		if info, err := os.Stat(path); err == nil {
			s.existed = true
			s.mode = info.Mode().Perm()
			s.data, _ = os.ReadFile(path)
		}
		snaps = append(snaps, s)
	}
	return snaps
}

func restoreFiles(snaps []fileSnapshot) {
	for _, s := range snaps {
		if s.existed {
			_ = os.WriteFile(s.path, s.data, s.mode)
		} else {
			_ = os.Remove(s.path)
		}
	}
}

func ruleEqual(a, b policy.Rule) bool {
	if a.Effect != b.Effect || a.Agent != b.Agent || a.App != b.App || a.Action != b.Action {
		return false
	}
	if len(a.Constraints) != len(b.Constraints) {
		return false
	}
	for k, v := range a.Constraints {
		if b.Constraints[k] != v {
			return false
		}
	}
	return true
}

func auditApply(paths config.Paths, p proposal.Proposal) {
	now := time.Now().UTC()
	authoredBy := p.Metadata.AuthoredBy.Tool
	for _, t := range p.SSHTargets.Add {
		_ = audit.Append(paths.AuditFile, audit.Event{
			Timestamp: now, Agent: authoredBy, App: "admin", Action: "apply.ssh_target",
			Params:   map[string]string{"alias": t.Alias, "host": t.Host, "user": t.User},
			Decision: "allow", Result: "admin_apply",
			ProposalSHA256: p.SHA256, ProposalName: p.Metadata.Name, AuthoredBy: authoredBy,
		})
	}
	for _, d := range p.Apps.Add {
		for action := range d.Actions {
			_ = audit.Append(paths.AuditFile, audit.Event{
				Timestamp: now, Agent: authoredBy, App: "admin", Action: "apply.verb",
				Params:   map[string]string{"app": d.App.Name, "action": action, "command": d.Actions[action].Command},
				Decision: "allow", Result: "admin_apply",
				ProposalSHA256: p.SHA256, ProposalName: p.Metadata.Name, AuthoredBy: authoredBy,
			})
		}
	}
	_ = audit.Append(paths.AuditFile, audit.Event{
		Timestamp: now, Agent: authoredBy, App: "admin", Action: "apply",
		Decision: "allow", Result: "admin_apply",
		Reason:         fmt.Sprintf("%d ssh targets, %d verbs, %d policy rules", len(p.SSHTargets.Add), len(p.Apps.Add), len(p.Policy.Add)),
		ProposalSHA256: p.SHA256, ProposalName: p.Metadata.Name, AuthoredBy: authoredBy,
	})
}

// writeAttestation records, in the root-owned admin dir, the sha256 of the
// user-writable policy/agents files as applied — tamper-evidence the daemon
// and doctor can compare against later (the policy section is otherwise only
// CLI-gated, not root-gated).
func writeAttestation(paths config.Paths, p proposal.Proposal) error {
	lines := []string{
		"# OpenScope applied-state attestation — do not edit by hand",
		"proposal_sha256: " + p.SHA256,
		"proposal_name: " + p.Metadata.Name,
		"policies_sha256: " + fileSHA(paths.PoliciesFile),
		"agents_sha256: " + fileSHA(paths.AgentsFile),
		"ssh_targets_sha256: " + fileSHA(paths.SSHTargetsFile),
		"system_commands_sha256: " + fileSHA(paths.SystemCommandsFile),
		"app_definitions_sha256: " + fileSHA(paths.AppDefinitionsFile),
	}
	body := strings.Join(lines, "\n") + "\n"
	if err := os.MkdirAll(paths.AdminDir, 0o755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(paths.AdminDir, "applied_state.yaml"), []byte(body), 0o644)
}

func fileSHA(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// chownTreeToInvoker hands the user-owned config dir and its files back to the
// invoking (sudo) user. Running `apply` as root can create ~/.openscope and
// files under it (audit.jsonl, policies.yaml) root-owned; without this the
// user-level daemon could no longer read or append to them. The admin-dir
// files (ssh_targets/system_commands) are intentionally left root-owned.
func chownTreeToInvoker(paths config.Paths) {
	if os.Geteuid() != 0 {
		return
	}
	sudoUser := os.Getenv("SUDO_USER")
	if sudoUser == "" {
		return
	}
	u, err := user.Lookup(sudoUser)
	if err != nil {
		return
	}
	var uid, gid int
	fmt.Sscanf(u.Uid, "%d", &uid)
	fmt.Sscanf(u.Gid, "%d", &gid)
	// PoliciesFile is intentionally absent: policy lives root-owned in the admin
	// dir so a same-uid agent cannot edit or replace the rules that confine it.
	chownTargets := []string{
		paths.ConfigDir, paths.RunDir, paths.StateDir, paths.AppsDir, paths.AgentsFile,
	}
	// In a root-daemon install the audit log is root-owned in the admin dir (the
	// agent can read but not erase it); only the per-user deployment hands it
	// back to the invoking user so the non-root daemon can append.
	if !config.SystemMode() {
		chownTargets = append(chownTargets, paths.AuditFile)
	}
	for _, path := range chownTargets {
		if path != "" {
			_ = os.Chown(path, uid, gid)
		}
	}
}

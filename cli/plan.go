// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package cli

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
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
	"github.com/openscope/openscope/output"
	"github.com/openscope/openscope/policy"
	"github.com/openscope/openscope/proposal"
)

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
		output.WriteErrorf("usage: openscope plan --file <proposal.yaml> [--json | --html [path]] [--no-open]")
		return daemon.ExitInvalid
	}

	plan, _, err := buildPlanFor(paths, file)
	if err != nil {
		output.WriteErrorf("plan: %v", err)
		return daemon.ExitConfigError
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
		output.WriteErrorf("usage: sudo openscope apply --file <proposal.yaml> [--expect-hash <sha>] [--yes]")
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

	// Re-render the full report from the file we actually read, so apply is
	// self-contained and any plan→apply tampering is visible here.
	fmt.Print(proposal.RenderText(plan))

	if plan.Blocked {
		output.WriteErrorf("apply refused: %d bounds violation(s) — resolve the proposal or edit %s as root",
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
		fmt.Fprintf(tty, "\n[%d/%d] HIGH %s — %s\n  %s\n  Type the resource name above to confirm (blank aborts): ",
			i+1, len(findings), f.RuleID, f.Resource, f.Summary)
		line, _ := reader.ReadString('\n')
		if strings.TrimSpace(line) != strings.TrimSpace(f.Resource) {
			return fmt.Errorf("confirmation for %q did not match", f.Resource)
		}
	}
	return nil
}

// applyProposal writes the proposal through the existing validated admin code
// paths. It is transactional: the three mutated files are snapshotted up front
// and restored on any error, so a mid-sequence failure never leaves a
// partially-applied, inconsistent config. Factored out (no euid check) so tests
// can exercise it with temp paths. liveSystem is the same snapshot the plan/
// bounds gate evaluated, so the effective config written matches what was
// reviewed (no TOCTOU against a second live read).
func applyProposal(paths config.Paths, p proposal.Proposal, liveSystem admin.SystemCommands) error {
	snap := snapshotFiles(paths.SSHTargetsFile, paths.SystemCommandsFile, paths.PoliciesFile)

	if err := applyMutations(paths, p, liveSystem); err != nil {
		restoreFiles(snap)
		return fmt.Errorf("%w (no changes applied — config restored)", err)
	}

	// Order matters: create the files first, THEN hand them back to the
	// invoking user, so root-created files aren't left unreadable by the daemon.
	auditApply(paths, p)
	chownTreeToInvoker(paths)
	return nil
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

	eff := p.EffectiveSystem(liveSystem)
	if err := admin.SaveDefaultSystemCommands(paths, eff); err != nil {
		return fmt.Errorf("write system commands: %w", err)
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

func mustLoadTargets(paths config.Paths) admin.SSHTargets {
	t, _ := admin.LoadSSHTargetsOrDefault(paths)
	return t
}

func sshTargetEqual(a, b admin.SSHTarget) bool {
	return a.Host == b.Host && a.User == b.User && a.Port == b.Port &&
		a.IdentityFile == b.IdentityFile && a.ProxyJump == b.ProxyJump &&
		strings.Join(a.AllowedServices, ",") == strings.Join(b.AllowedServices, ",") &&
		strings.Join(a.AllowedPaths, ",") == strings.Join(b.AllowedPaths, ",") &&
		strings.Join(a.AllowedPathPrefixes, ",") == strings.Join(b.AllowedPathPrefixes, ",")
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
	_ = audit.Append(paths.AuditFile, audit.Event{
		Timestamp: now, Agent: authoredBy, App: "admin", Action: "apply",
		Decision: "allow", Result: "admin_apply",
		Reason:         fmt.Sprintf("%d ssh targets, %d policy rules", len(p.SSHTargets.Add), len(p.Policy.Add)),
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
	for _, path := range []string{
		paths.ConfigDir, paths.RunDir, paths.StateDir, paths.AppsDir,
		paths.PoliciesFile, paths.AgentsFile, paths.AuditFile,
	} {
		if path != "" {
			_ = os.Chown(path, uid, gid)
		}
	}
}

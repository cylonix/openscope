// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package doctor

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/openscope/openscope/admin"
	"github.com/openscope/openscope/buildinfo"
	"github.com/openscope/openscope/config"
	"github.com/openscope/openscope/executor/sshexec"
	"github.com/openscope/openscope/privsep"
)

type Report struct {
	OK                   bool               `json:"ok"`
	Build                buildinfo.Info     `json:"build"`
	ConfigDir            string             `json:"config_dir,omitempty"`
	Socket               string             `json:"socket,omitempty"`
	ConfigDirExists      bool               `json:"config_dir_exists"`
	DaemonRunning        bool               `json:"daemon_running"`
	AsapplePath          string             `json:"asapple_path,omitempty"`
	AsappleSigned        bool               `json:"asapple_signed"`
	NotesAccess          NotesCheck         `json:"notes_access"`
	SSHTargetsConfig     ConfigCheck        `json:"ssh_targets_config"`
	SSHKeyProtection     KeyProtectionCheck `json:"ssh_key_protection"`
	HTTPProfilesConfig   ConfigCheck        `json:"http_profiles_config"`
	SystemCommandsConfig ConfigCheck        `json:"system_commands_config"`
	PrivilegeSeparation  PrivilegeCheck     `json:"privilege_separation"`
	Hints                []string           `json:"hints,omitempty"`
}

// PrivilegeCheck reports whether the broker is privilege-separated from a local
// same-uid agent. It only fails when local privileged brokering (ssh keys /
// system commands) is configured on a non-root broker — see
// docs/macos-privileged-helper.md.
type PrivilegeCheck struct {
	Checked   bool   `json:"checked"`
	OK        bool   `json:"ok"`
	Separated bool   `json:"separated"`
	Root      bool   `json:"root"`
	EUID      int    `json:"euid"`
	Reason    string `json:"reason,omitempty"`
}

type KeyProtectionCheck struct {
	Checked  bool            `json:"checked"`
	OK       bool            `json:"ok"`
	Warnings []SSHKeyWarning `json:"warnings,omitempty"`
}

type SSHKeyWarning struct {
	Target  string `json:"target"`
	Level   string `json:"level"`
	Code    string `json:"code,omitempty"`
	Message string `json:"message"`
}

type NotesCheck struct {
	Checked bool   `json:"checked"`
	OK      bool   `json:"ok"`
	Error   string `json:"error,omitempty"`
}

type ConfigCheck struct {
	Checked bool   `json:"checked"`
	Present bool   `json:"present"`
	OK      bool   `json:"ok"`
	Count   int    `json:"count,omitempty"`
	Error   string `json:"error,omitempty"`
	Source  string `json:"source,omitempty"`
}

func Run(paths config.Paths) Report {
	report := Report{
		Build:     buildinfo.Get(),
		ConfigDir: paths.ConfigDir,
		Socket:    paths.SocketPath,
	}
	var hints []string

	// Config dir
	if _, err := os.Stat(paths.ConfigDir); err == nil {
		report.ConfigDirExists = true
	} else {
		hints = append(hints, "config directory missing — run: openscope status")
	}

	// Daemon reachability
	report.DaemonRunning = checkBroker(paths)
	if !report.DaemonRunning {
		if strings.TrimSpace(paths.HTTPURL) != "" {
			hints = append(hints, "broker not reachable over HTTP — verify OPENSCOPE_HTTP_URL and that openscoped is listening on OPENSCOPE_HTTP_LISTEN")
		} else {
			hints = append(hints, "daemon not running — restart: "+daemonRestartHint())
		}
	}

	// Apple-automation checks only apply where the applescript executor
	// exists; a Linux broker brokers ssh/http/system actions only.
	appleChecks := runtime.GOOS == "darwin"
	if appleChecks {
		// asapple binary
		asapplePath := findAsapple()
		report.AsapplePath = asapplePath
		if asapplePath == "" {
			hints = append(hints, "asapple not found — rebuild the OpenScope.app bundle")
		} else {
			report.AsappleSigned = checkSigned(asapplePath)
			if !report.AsappleSigned {
				hints = append(hints, "asapple is not code-signed — rebuild the OpenScope.app bundle from Xcode")
			}
		}

		// Notes Automation permission — probe with a minimal AppleScript
		report.NotesAccess = checkNotesAccess(asapplePath)
		if !report.NotesAccess.OK {
			hints = append(hints, "Notes access denied — run: tccutil reset AppleEvents com.ezblock.openscope && open /Applications/OpenScope.app")
			hints = append(hints, "then re-run any Notes action to trigger the macOS approval prompt")
		}
	}

	report.SSHTargetsConfig = checkSSHTargetsConfig(paths)
	if !report.SSHTargetsConfig.OK {
		hints = append(hints, "ssh targets config is invalid — fix "+paths.SSHTargetsFile+" or remove the broken file")
	}

	report.SSHKeyProtection = checkSSHKeyProtection(paths)
	if !report.SSHKeyProtection.OK {
		hints = append(hints, "SSH identity files are not adequately protected from unprivileged processes — move keys to a root-owned directory (e.g. /var/openscope/ssh/) with mode 0600 owned by root")
	}

	// Parallel-path reminder: a brokered SSH target is only a boundary if the
	// agent's own ~/.ssh keys cannot reach the host. doctor can't probe (no
	// network), but when both targets and user keys exist it must surface the
	// requirement — apply enforces it, but verify standing config too.
	if report.SSHTargetsConfig.Count > 0 {
		if n := len(sshexec.DiscoverUserKeys(paths.HomeDir)); n > 0 {
			hints = append(hints, fmt.Sprintf("%d private key(s) in ~/.ssh: brokered SSH targets are only a boundary if none of them reach those hosts — verify with `openscope ssh check-bypass`", n))
		}
	}

	report.HTTPProfilesConfig = checkHTTPProfilesConfig(paths)
	if !report.HTTPProfilesConfig.OK {
		hints = append(hints, "http profiles config is invalid — fix "+paths.HTTPProfilesFile+" or remove the broken file")
	}

	report.SystemCommandsConfig = checkSystemCommandsConfig(paths)
	if !report.SystemCommandsConfig.OK {
		hints = append(hints, "system commands config is invalid — fix "+paths.SystemCommandsFile+" or remove the broken file")
	}

	report.PrivilegeSeparation = checkPrivilegeSeparation(paths, config.SystemMode(), report.SSHTargetsConfig, report.SystemCommandsConfig)
	if !report.PrivilegeSeparation.OK {
		hints = append(hints, "local privileged brokering is configured but the broker is not privilege-separated — a same-uid agent can read brokered ssh keys and run privileged system commands directly, bypassing policy; route privileged brokering through a root helper (see docs/macos-privileged-helper.md)")
	}

	report.Hints = hints
	report.OK = report.ConfigDirExists &&
		report.DaemonRunning &&
		(!appleChecks || (report.AsappleSigned && report.NotesAccess.OK)) &&
		report.SSHTargetsConfig.OK &&
		report.SSHKeyProtection.OK &&
		report.HTTPProfilesConfig.OK &&
		report.SystemCommandsConfig.OK &&
		report.PrivilegeSeparation.OK

	return report
}

// checkPrivilegeSeparation reports whether privileged brokering is contained.
// It only matters for LOCAL privileged work: a remote (HTTP/VPC) broker has no
// local same-uid agent, and an install with no ssh targets or system commands
// brokers nothing privileged locally — both stay OK regardless of uid.
func checkPrivilegeSeparation(paths config.Paths, systemMode bool, ssh ConfigCheck, system ConfigCheck) PrivilegeCheck {
	m := privsep.Detect()
	local := strings.TrimSpace(paths.HTTPURL) == ""
	privileged := ssh.Count > 0 || system.Present

	separated, root, reason := m.Separated, m.Root, m.Reason
	// privsep.Detect() classifies THIS process's euid, but doctor is normally
	// run by the user (euid 501), not the daemon. On a root-daemon install that
	// would mis-report the broker as unseparated. The root LaunchDaemon's
	// presence is the deployment-level signal that the broker runs as root,
	// independent of whichever uid invokes doctor (same signal config uses to
	// place the audit log) — trust it over our own euid.
	if systemMode {
		separated, root = true, true
		reason = "root LaunchDaemon installed — broker runs as root, separated from the local agent uid"
	}

	return PrivilegeCheck{
		Checked:   true,
		OK:        separated || !(local && privileged),
		Separated: separated,
		Root:      root,
		EUID:      m.EUID,
		Reason:    reason,
	}
}

func checkSocket(socketPath string) bool {
	conn, err := net.DialTimeout("unix", socketPath, 2*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func checkBroker(paths config.Paths) bool {
	if strings.TrimSpace(paths.HTTPURL) != "" {
		client := &http.Client{Timeout: 2 * time.Second}
		resp, err := client.Get(strings.TrimRight(paths.HTTPURL, "/") + "/healthz")
		if err != nil {
			return false
		}
		defer resp.Body.Close()

		var payload map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
			return false
		}
		ok, _ := payload["ok"].(bool)
		return ok
	}
	return checkSocket(paths.SocketPath)
}

func findAsapple() string {
	// Prefer binary next to the running openscoped inside an app bundle
	exePath, err := os.Executable()
	if err == nil {
		candidate := exePath[:len(exePath)-len("openscope")] + "asapple"
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	// Fall back to app bundle location
	bundlePath := "/Applications/OpenScope.app/Contents/Resources/bin/asapple"
	if _, err := os.Stat(bundlePath); err == nil {
		return bundlePath
	}
	return ""
}

func checkSigned(path string) bool {
	err := exec.Command("codesign", "--verify", "--strict", path).Run()
	return err == nil
}

func checkNotesAccess(asapplePath string) NotesCheck {
	if asapplePath == "" {
		return NotesCheck{Checked: false, OK: false, Error: "asapple not found"}
	}

	// Run a minimal AppleScript that touches Notes but produces no real output.
	// If Automation permission is denied, NSAppleScript returns an error.
	script := `tell application "Notes" to get name of first account`
	cmd := exec.Command("osascript", "-e", script)
	cmd.Env = append(os.Environ(), "TERM=dumb")
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := string(out)
		if msg == "" {
			msg = err.Error()
		}
		return NotesCheck{Checked: true, OK: false, Error: msg}
	}
	return NotesCheck{Checked: true, OK: true}
}

func checkSSHTargetsConfig(paths config.Paths) ConfigCheck {
	_, err := os.Stat(paths.SSHTargetsFile)
	if err != nil {
		if os.IsNotExist(err) {
			return ConfigCheck{Checked: true, Present: false, OK: true, Source: paths.SSHTargetsFile}
		}
		return ConfigCheck{Checked: true, Present: false, OK: false, Source: paths.SSHTargetsFile, Error: err.Error()}
	}

	targets, err := admin.LoadSSHTargets(paths.SSHTargetsFile)
	if err != nil {
		return ConfigCheck{Checked: true, Present: true, OK: false, Source: paths.SSHTargetsFile, Error: err.Error()}
	}
	return ConfigCheck{
		Checked: true,
		Present: true,
		OK:      true,
		Count:   len(targets.Targets),
		Source:  paths.SSHTargetsFile,
	}
}

func checkSSHKeyProtection(paths config.Paths) KeyProtectionCheck {
	targets, err := admin.LoadSSHTargetsOrDefault(paths)
	if err != nil {
		return KeyProtectionCheck{
			Checked: true,
			OK:      false,
			Warnings: []SSHKeyWarning{{
				Level:   "critical",
				Message: "cannot load ssh targets: " + err.Error(),
			}},
		}
	}
	if len(targets.Targets) == 0 {
		return KeyProtectionCheck{Checked: true, OK: true}
	}

	var warnings []SSHKeyWarning
	agentReadable := false
	for _, target := range targets.Targets {
		for _, w := range sshexec.AuditKeyProtection(target, paths.HomeDir) {
			level := w.Level
			// A brokered key the agent's user can read (no identity_file → ~/.ssh
			// fallback, key under ~/.ssh, mode looser than 0600, or not root-owned)
			// lets the agent ssh directly and bypass the broker. That is an error,
			// not a hygiene warning: the key MUST be root-owned and unreadable.
			if keyReadableCode(w.Code) {
				level = "critical"
				agentReadable = true
			}
			warnings = append(warnings, SSHKeyWarning{
				Target:  target.Alias,
				Level:   level,
				Code:    w.Code,
				Message: w.Message,
			})
		}
	}

	return KeyProtectionCheck{
		Checked:  true,
		OK:       !agentReadable,
		Warnings: warnings,
	}
}

// keyReadableCode reports whether an AuditKeyProtection code means the agent's
// own (non-root) user can read the key — the precondition for bypassing the
// broker by sshing directly. Loose-dir and missing-file are weaker hygiene
// findings that do not, by themselves, expose the key.
func keyReadableCode(code string) bool {
	switch code {
	case sshexec.KeyNoIdentityFile, sshexec.KeyUnderDotSSH, sshexec.KeyModeTooOpen, sshexec.KeyNotRootOwned, sshexec.KeyNotRegularFile:
		return true
	}
	return false
}

func checkHTTPProfilesConfig(paths config.Paths) ConfigCheck {
	_, err := os.Stat(paths.HTTPProfilesFile)
	if err != nil {
		if os.IsNotExist(err) {
			return ConfigCheck{Checked: true, Present: false, OK: true, Source: paths.HTTPProfilesFile}
		}
		return ConfigCheck{Checked: true, Present: false, OK: false, Source: paths.HTTPProfilesFile, Error: err.Error()}
	}

	profiles, err := admin.LoadHTTPProfiles(paths.HTTPProfilesFile)
	if err != nil {
		return ConfigCheck{Checked: true, Present: true, OK: false, Source: paths.HTTPProfilesFile, Error: err.Error()}
	}
	return ConfigCheck{
		Checked: true,
		Present: true,
		OK:      true,
		Count:   len(profiles.Profiles),
		Source:  paths.HTTPProfilesFile,
	}
}

func checkSystemCommandsConfig(paths config.Paths) ConfigCheck {
	_, err := os.Stat(paths.SystemCommandsFile)
	if err != nil {
		if os.IsNotExist(err) {
			return ConfigCheck{Checked: true, Present: false, OK: true, Source: paths.SystemCommandsFile}
		}
		return ConfigCheck{Checked: true, Present: false, OK: false, Source: paths.SystemCommandsFile, Error: err.Error()}
	}

	cmds, err := admin.LoadSystemCommands(paths.SystemCommandsFile)
	if err != nil {
		return ConfigCheck{Checked: true, Present: true, OK: false, Source: paths.SystemCommandsFile, Error: err.Error()}
	}
	return ConfigCheck{
		Checked: true,
		Present: true,
		OK:      true,
		Count:   len(cmds.Packages.Managers),
		Source:  paths.SystemCommandsFile,
	}
}

// docRow is one line of the human-readable doctor table.
type docRow struct {
	name   string
	ok     bool
	detail string
}

// ANSI colors for the doctor table. The CLI decides whether to enable them
// (stdout is a terminal, NO_COLOR unset) and passes color=true to Text.
const (
	ansiReset = "\x1b[0m"
	ansiGreen = "\x1b[32m"
	ansiRed   = "\x1b[31m"
)

func colorize(s, code string, on bool) string {
	if !on {
		return s
	}
	return code + s + ansiReset
}

// Text renders the report as a human-readable table — the default
// `openscope doctor` output. When color is true the per-check status and the
// overall verdict are ANSI-colored (green ok, red fail). `openscope doctor
// --json` returns the structured Report instead (for scripts and the pilot
// harness).
func (r Report) Text(color bool) string {
	var b strings.Builder

	bi := r.Build
	b.WriteString("OpenScope doctor\n")
	ver := bi.Version
	if bi.Commit != "" {
		ver += " (" + bi.Commit + ")"
	}
	fmt.Fprintf(&b, "  version  %s\n", ver)
	fmt.Fprintf(&b, "  build    %s/%s %s\n", bi.OS, bi.Arch, bi.Go)
	if r.ConfigDir != "" {
		fmt.Fprintf(&b, "  config   %s\n", r.ConfigDir)
	}
	if r.Socket != "" {
		fmt.Fprintf(&b, "  socket   %s\n", r.Socket)
	}
	b.WriteString("\n")

	rows := r.checkRows()
	nameW := 0
	for _, row := range rows {
		if len(row.name) > nameW {
			nameW = len(row.name)
		}
	}
	for _, row := range rows {
		icon, mark, code := "✓", "ok", ansiGreen
		if !row.ok {
			icon, mark, code = "✗", "FAIL", ansiRed
		}
		status := colorize(fmt.Sprintf("%s %-4s", icon, mark), code, color)
		fmt.Fprintf(&b, "  %s  %-*s  %s\n", status, nameW, row.name, row.detail)
	}

	b.WriteString("\n")
	if r.OK {
		fmt.Fprintf(&b, "  Overall: %s\n", colorize("OK", ansiGreen, color))
	} else {
		fmt.Fprintf(&b, "  Overall: %s\n", colorize("FAIL", ansiRed, color))
	}

	if len(r.Hints) > 0 {
		b.WriteString("\n  Hints:\n")
		for _, h := range r.Hints {
			fmt.Fprintf(&b, "    - %s\n", h)
		}
	}
	return b.String()
}

// checkRows turns the report into table rows in display order, omitting checks
// that don't apply to this platform (the Apple-automation checks off macOS).
func (r Report) checkRows() []docRow {
	rows := []docRow{
		{name: "config dir", ok: r.ConfigDirExists, detail: presentOr(r.ConfigDirExists, "exists", "missing")},
		{name: "daemon", ok: r.DaemonRunning, detail: presentOr(r.DaemonRunning, "running", "not reachable")},
	}

	if runtime.GOOS == "darwin" {
		asapple := "signed"
		switch {
		case r.AsapplePath == "":
			asapple = "not found"
		case !r.AsappleSigned:
			asapple = "unsigned"
		}
		rows = append(rows,
			docRow{name: "asapple", ok: r.AsapplePath != "" && r.AsappleSigned, detail: asapple},
			docRow{name: "notes access", ok: r.NotesAccess.OK, detail: presentOr(r.NotesAccess.OK, "granted", "denied")},
		)
	}

	rows = append(rows,
		docRow{name: "ssh targets", ok: r.SSHTargetsConfig.OK, detail: configDetail(r.SSHTargetsConfig)},
		docRow{name: "ssh key protection", ok: r.SSHKeyProtection.OK, detail: keyProtectionDetail(r.SSHKeyProtection)},
		docRow{name: "http profiles", ok: r.HTTPProfilesConfig.OK, detail: configDetail(r.HTTPProfilesConfig)},
		docRow{name: "system commands", ok: r.SystemCommandsConfig.OK, detail: configDetail(r.SystemCommandsConfig)},
		docRow{name: "privilege separation", ok: r.PrivilegeSeparation.OK, detail: privsepDetail(r.PrivilegeSeparation)},
	)
	return rows
}

func presentOr(ok bool, yes, no string) string {
	if ok {
		return yes
	}
	return no
}

func configDetail(c ConfigCheck) string {
	switch {
	case c.Error != "":
		return "invalid: " + c.Error
	case !c.Present:
		return "none configured"
	case c.Count > 0:
		return fmt.Sprintf("%d configured", c.Count)
	default:
		return "present"
	}
}

func keyProtectionDetail(c KeyProtectionCheck) string {
	if c.OK {
		return "ok"
	}
	n := 0
	for _, w := range c.Warnings {
		if w.Level == "critical" {
			n++
		}
	}
	return fmt.Sprintf("%d agent-readable key(s) — see hints", n)
}

func privsepDetail(c PrivilegeCheck) string {
	if c.Separated {
		return "separated (root daemon)"
	}
	if c.OK {
		return fmt.Sprintf("euid %d — nothing privileged brokered locally", c.EUID)
	}
	return fmt.Sprintf("NOT separated (euid %d) — see hints", c.EUID)
}

// daemonRestartHint is the platform-appropriate way to restart openscoped.
func daemonRestartHint() string {
	switch runtime.GOOS {
	case "darwin":
		if config.SystemMode() {
			return "sudo launchctl kickstart -k system/com.ezblock.openscope.openscoped"
		}
		return "launchctl kickstart -k gui/$(id -u)/com.ezblock.openscope.openscoped"
	default:
		return "sudo systemctl restart openscoped"
	}
}

// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package doctor

import (
	"net"
	"os"
	"os/exec"
	"time"

	"github.com/agentscope/ascope/config"
)

type Report struct {
	OK              bool         `json:"ok"`
	ConfigDirExists bool         `json:"config_dir_exists"`
	DaemonRunning   bool         `json:"daemon_running"`
	AsapplePath     string       `json:"asapple_path,omitempty"`
	AsappleSigned   bool         `json:"asapple_signed"`
	NotesAccess     NotesCheck   `json:"notes_access"`
	Hints           []string     `json:"hints,omitempty"`
}

type NotesCheck struct {
	Checked bool   `json:"checked"`
	OK      bool   `json:"ok"`
	Error   string `json:"error,omitempty"`
}

func Run(paths config.Paths) Report {
	report := Report{}
	var hints []string

	// Config dir
	if _, err := os.Stat(paths.ConfigDir); err == nil {
		report.ConfigDirExists = true
	} else {
		hints = append(hints, "config directory missing — run: ascope status")
	}

	// Daemon reachability
	report.DaemonRunning = checkSocket(paths.SocketPath)
	if !report.DaemonRunning {
		hints = append(hints, "daemon not running — restart: launchctl kickstart -k gui/$(id -u)/com.ezblock.agentscope.ascoped")
	}

	// asapple binary
	asapplePath := findAsapple()
	report.AsapplePath = asapplePath
	if asapplePath == "" {
		hints = append(hints, "asapple not found — rebuild the AgentScope.app bundle")
	} else {
		report.AsappleSigned = checkSigned(asapplePath)
		if !report.AsappleSigned {
			hints = append(hints, "asapple is not code-signed — rebuild the AgentScope.app bundle from Xcode")
		}
	}

	// Notes Automation permission — probe with a minimal AppleScript
	report.NotesAccess = checkNotesAccess(asapplePath)
	if !report.NotesAccess.OK {
		hints = append(hints, "Notes access denied — run: tccutil reset AppleEvents com.ezblock.agentscope && open /Applications/AgentScope.app")
		hints = append(hints, "then re-run any Notes action to trigger the macOS approval prompt")
	}

	report.Hints = hints
	report.OK = report.ConfigDirExists &&
		report.DaemonRunning &&
		report.AsappleSigned &&
		report.NotesAccess.OK

	return report
}

func checkSocket(socketPath string) bool {
	conn, err := net.DialTimeout("unix", socketPath, 2*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func findAsapple() string {
	// Prefer binary next to the running ascoped inside an app bundle
	exePath, err := os.Executable()
	if err == nil {
		candidate := exePath[:len(exePath)-len("ascope")] + "asapple"
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	// Fall back to app bundle location
	bundlePath := "/Applications/AgentScope.app/Contents/Resources/bin/asapple"
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

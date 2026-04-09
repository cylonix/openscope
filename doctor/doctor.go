// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package doctor

import (
	"encoding/json"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/openscope/openscope/admin"
	"github.com/openscope/openscope/config"
)

type Report struct {
	OK                 bool        `json:"ok"`
	ConfigDirExists    bool        `json:"config_dir_exists"`
	DaemonRunning      bool        `json:"daemon_running"`
	AsapplePath        string      `json:"asapple_path,omitempty"`
	AsappleSigned      bool        `json:"asapple_signed"`
	NotesAccess        NotesCheck  `json:"notes_access"`
	SSHTargetsConfig   ConfigCheck `json:"ssh_targets_config"`
	HTTPProfilesConfig ConfigCheck `json:"http_profiles_config"`
	Hints              []string    `json:"hints,omitempty"`
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
	report := Report{}
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
			hints = append(hints, "daemon not running — restart: launchctl kickstart -k gui/$(id -u)/com.ezblock.openscope.openscoped")
		}
	}

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

	report.SSHTargetsConfig = checkSSHTargetsConfig(paths)
	if !report.SSHTargetsConfig.OK {
		hints = append(hints, "ssh targets config is invalid — fix /Library/Application Support/OpenScope/ssh_targets.yaml or remove the broken file")
	}

	report.HTTPProfilesConfig = checkHTTPProfilesConfig(paths)
	if !report.HTTPProfilesConfig.OK {
		hints = append(hints, "http profiles config is invalid — fix /Library/Application Support/OpenScope/http_profiles.yaml or remove the broken file")
	}

	report.Hints = hints
	report.OK = report.ConfigDirExists &&
		report.DaemonRunning &&
		report.AsappleSigned &&
		report.NotesAccess.OK &&
		report.SSHTargetsConfig.OK &&
		report.HTTPProfilesConfig.OK

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

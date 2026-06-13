// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package systemexec

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openscope/openscope/admin"
	"github.com/openscope/openscope/appdef"
	"github.com/openscope/openscope/config"
	"github.com/openscope/openscope/executor"
)

type stubRunner struct {
	LastName string
	LastArgs []string
	Result   executor.Result
	Err      error
}

func (s *stubRunner) Run(name string, args []string) (executor.Result, error) {
	s.LastName = name
	s.LastArgs = args
	return s.Result, s.Err
}

func testPaths(t *testing.T) config.Paths {
	t.Helper()
	dir := t.TempDir()
	return config.Paths{
		SystemCommandsFile: filepath.Join(dir, "system_commands.yaml"),
	}
}

func writeConfig(t *testing.T, paths config.Paths, cmds admin.SystemCommands) {
	t.Helper()
	if cmds.Version == 0 {
		cmds.Version = 1
	}
	if err := admin.SaveSystemCommands(paths.SystemCommandsFile, cmds); err != nil {
		t.Fatalf("write config: %v", err)
	}
}

func fullConfig() admin.SystemCommands {
	return admin.SystemCommands{
		Version: 1,
		Packages: admin.PackageConfig{
			Managers: []admin.ManagerConfig{
				{Name: "brew", Binary: "/opt/homebrew/bin/brew", Sudo: false},
				{Name: "npm", Binary: "/usr/local/bin/npm", Sudo: false},
				{Name: "pip3", Binary: "/usr/bin/pip3", Sudo: true},
			},
			Allowed: []string{"jq", "ripgrep", "prettier"},
			Blocked: []string{"malware"},
		},
		Services: admin.ServiceConfig{
			Allowed: []string{"postgresql", "redis"},
		},
		Processes: admin.ProcessConfig{
			AllowedSignals: []string{"TERM", "HUP"},
			AllowedNames:   []string{"node", "python3"},
			AllowKillByPID: true,
		},
		Ports: admin.PortConfig{
			Allowed: []int{3000, 8080},
		},
		Files: admin.FileConfig{
			AllowedChmodPrefixes: []string{"/Users/test/src"},
			AllowedChownPrefixes: []string{"/Users/test/data"},
		},
		Apps: admin.AppConfig{
			AllowedSourcePrefixes: []string{"/Users/test/Library/Developer/Xcode/DerivedData"},
			AllowedInstallDirs:    []string{"/Applications"},
			AllowedNames:          []string{"Kidfence", "TestApp"},
		},
		Builds: admin.BuildConfig{
			AllowedProjectPrefixes: []string{"/Volumes/2TB-1/src"},
		},
	}
}

var emptyDef = appdef.Definition{}

func TestManagePackagesInstall(t *testing.T) {
	paths := testPaths(t)
	writeConfig(t, paths, fullConfig())

	stub := &stubRunner{Result: executor.Result{Stdout: "installed jq", ExitCode: 0}}
	e := Executor{Paths: paths, Runner: stub}

	result, err := e.Run(emptyDef, "manage_packages", map[string]string{
		"op":      "install",
		"manager": "brew",
		"package": "jq",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", result.ExitCode)
	}
	if stub.LastName != "/opt/homebrew/bin/brew" {
		t.Fatalf("expected brew binary, got %q", stub.LastName)
	}
	if len(stub.LastArgs) != 2 || stub.LastArgs[0] != "install" || stub.LastArgs[1] != "jq" {
		t.Fatalf("unexpected args: %v", stub.LastArgs)
	}
}

func TestManagePackagesNpmInstall(t *testing.T) {
	paths := testPaths(t)
	writeConfig(t, paths, fullConfig())

	stub := &stubRunner{Result: executor.Result{Stdout: "added prettier", ExitCode: 0}}
	e := Executor{Paths: paths, Runner: stub}

	_, err := e.Run(emptyDef, "manage_packages", map[string]string{
		"op":      "install",
		"manager": "npm",
		"package": "prettier",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stub.LastArgs[0] != "install" || stub.LastArgs[1] != "-g" || stub.LastArgs[2] != "prettier" {
		t.Fatalf("expected npm install -g prettier, got %v", stub.LastArgs)
	}
}

// withEUID overrides the effective-uid probe for the duration of a test.
func withEUID(t *testing.T, uid int) {
	t.Helper()
	old := geteuid
	geteuid = func() int { return uid }
	t.Cleanup(func() { geteuid = old })
}

func sudoManagerPaths(t *testing.T) config.Paths {
	t.Helper()
	paths := testPaths(t)
	cfg := fullConfig()
	// Use a real root-owned binary so RequireSudoSafe passes at runtime.
	for i := range cfg.Packages.Managers {
		if cfg.Packages.Managers[i].Name == "pip3" {
			cfg.Packages.Managers[i].Binary = "/usr/bin/true"
		}
	}
	writeConfig(t, paths, cfg)
	return paths
}

func TestManagePackagesSudoManager(t *testing.T) {
	// Legacy separated-user deployment: non-root daemon, escalation opted in.
	paths := sudoManagerPaths(t)
	withEUID(t, 501)
	t.Setenv("OPENSCOPE_ALLOW_SUDO_ESCALATION", "1")

	stub := &stubRunner{Result: executor.Result{Stdout: "ok", ExitCode: 0}}
	e := Executor{Paths: paths, Runner: stub}

	_, err := e.Run(emptyDef, "manage_packages", map[string]string{
		"op": "install", "manager": "pip3", "package": "jq",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stub.LastName != "/usr/bin/sudo" {
		t.Fatalf("expected sudo, got %q", stub.LastName)
	}
	if stub.LastArgs[0] != "-n" || stub.LastArgs[1] != "/usr/bin/true" {
		t.Fatalf("expected sudo -n /usr/bin/true, got %v", stub.LastArgs)
	}
}

func TestManagePackagesRootRunsDirect(t *testing.T) {
	// Root daemon (the privileged-helper model): run the binary directly, never
	// via sudo — there is no NOPASSWD wildcard for a same-uid agent to abuse.
	paths := sudoManagerPaths(t)
	withEUID(t, 0)

	stub := &stubRunner{Result: executor.Result{Stdout: "ok", ExitCode: 0}}
	e := Executor{Paths: paths, Runner: stub}

	_, err := e.Run(emptyDef, "manage_packages", map[string]string{
		"op": "install", "manager": "pip3", "package": "jq",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stub.LastName != "/usr/bin/true" {
		t.Fatalf("root should run the binary directly, got %q (args %v)", stub.LastName, stub.LastArgs)
	}
}

func TestManagePackagesSudoRefusedWithoutOptIn(t *testing.T) {
	// Non-root daemon, no opt-in: the NOPASSWD sudo path is the broker bypass on
	// a same-uid box, so it is refused rather than used.
	paths := sudoManagerPaths(t)
	withEUID(t, 501)
	t.Setenv("OPENSCOPE_ALLOW_SUDO_ESCALATION", "")

	stub := &stubRunner{Result: executor.Result{ExitCode: 0}}
	e := Executor{Paths: paths, Runner: stub}

	_, err := e.Run(emptyDef, "manage_packages", map[string]string{
		"op": "install", "manager": "pip3", "package": "jq",
	})
	if err == nil {
		t.Fatal("expected a non-root daemon without opt-in to refuse the sudo escalation")
	}
	if !strings.Contains(err.Error(), "needs a root broker") {
		t.Fatalf("unexpected error: %v", err)
	}
	if stub.LastName != "" {
		t.Fatalf("nothing should have executed, ran %q", stub.LastName)
	}
}

func TestManagePackagesSudoRejectsUserWritableBinary(t *testing.T) {
	paths := testPaths(t)
	cfg := fullConfig()

	// Point the sudo manager at a user-writable script.
	script := filepath.Join(t.TempDir(), "fake_pip.sh")
	os.WriteFile(script, []byte("#!/bin/sh\n"), 0o755)
	for i := range cfg.Packages.Managers {
		if cfg.Packages.Managers[i].Name == "pip3" {
			cfg.Packages.Managers[i].Binary = script
		}
	}
	// Save directly (bypass AddManager validation to simulate a pre-existing bad config).
	cfg.Version = 1
	admin.SaveSystemCommands(paths.SystemCommandsFile, cfg)

	stub := &stubRunner{Result: executor.Result{ExitCode: 0}}
	e := Executor{Paths: paths, Runner: stub}

	_, err := e.Run(emptyDef, "manage_packages", map[string]string{
		"op":      "install",
		"manager": "pip3",
		"package": "jq",
	})
	if err == nil {
		t.Fatalf("expected a user-writable privileged binary to be rejected at runtime")
	}
	if !strings.Contains(err.Error(), "refusing privileged execution") {
		t.Fatalf("unexpected error message: %v", err)
	}
}

func TestManagePackagesRejectsBlockedPackage(t *testing.T) {
	paths := testPaths(t)
	writeConfig(t, paths, fullConfig())

	stub := &stubRunner{Result: executor.Result{ExitCode: 0}}
	e := Executor{Paths: paths, Runner: stub}

	_, err := e.Run(emptyDef, "manage_packages", map[string]string{
		"op":      "install",
		"manager": "brew",
		"package": "malware",
	})
	if err == nil {
		t.Fatalf("expected blocked package to be rejected")
	}
	if !strings.Contains(err.Error(), "not in the allowed list") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestManagePackagesRejectsUnknownManager(t *testing.T) {
	paths := testPaths(t)
	writeConfig(t, paths, fullConfig())

	stub := &stubRunner{}
	e := Executor{Paths: paths, Runner: stub}

	_, err := e.Run(emptyDef, "manage_packages", map[string]string{
		"op":      "install",
		"manager": "unknown",
		"package": "jq",
	})
	if err == nil {
		t.Fatalf("expected unknown manager to be rejected")
	}
}

func TestManagePackagesRejectsUnsafeChars(t *testing.T) {
	paths := testPaths(t)
	writeConfig(t, paths, fullConfig())

	stub := &stubRunner{}
	e := Executor{Paths: paths, Runner: stub}

	_, err := e.Run(emptyDef, "manage_packages", map[string]string{
		"op":      "install",
		"manager": "brew",
		"package": "jq; rm -rf /",
	})
	if err == nil {
		t.Fatalf("expected injection attempt to be rejected")
	}
	if !strings.Contains(err.Error(), "unsupported characters") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestManagePackagesList(t *testing.T) {
	paths := testPaths(t)
	writeConfig(t, paths, fullConfig())

	stub := &stubRunner{Result: executor.Result{Stdout: "jq\nripgrep\n", ExitCode: 0}}
	e := Executor{Paths: paths, Runner: stub}

	result, err := e.Run(emptyDef, "manage_packages", map[string]string{
		"op":      "list",
		"manager": "brew",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var data map[string]any
	if err := json.Unmarshal([]byte(result.Stdout), &data); err != nil {
		t.Fatalf("unmarshal output: %v", err)
	}
	if data["op"] != "list" {
		t.Fatalf("expected op=list, got %v", data["op"])
	}
}

func TestManageServicesRestart(t *testing.T) {
	paths := testPaths(t)
	writeConfig(t, paths, fullConfig())

	stub := &stubRunner{Result: executor.Result{Stdout: "restarted", ExitCode: 0}}
	e := Executor{Paths: paths, Runner: stub}

	_, err := e.Run(emptyDef, "manage_services", map[string]string{
		"op":      "restart",
		"service": "postgresql",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stub.LastName != "/opt/homebrew/bin/brew" {
		t.Fatalf("expected brew binary, got %q", stub.LastName)
	}
	if len(stub.LastArgs) != 3 || stub.LastArgs[0] != "services" || stub.LastArgs[1] != "restart" || stub.LastArgs[2] != "postgresql" {
		t.Fatalf("unexpected args: %v", stub.LastArgs)
	}
}

func TestManageServicesRejectsDisallowed(t *testing.T) {
	paths := testPaths(t)
	writeConfig(t, paths, fullConfig())

	stub := &stubRunner{}
	e := Executor{Paths: paths, Runner: stub}

	_, err := e.Run(emptyDef, "manage_services", map[string]string{
		"op":      "start",
		"service": "mysql",
	})
	if err == nil {
		t.Fatalf("expected disallowed service to be rejected")
	}
}

func TestManageProcessesKillByName(t *testing.T) {
	paths := testPaths(t)
	writeConfig(t, paths, fullConfig())

	stub := &stubRunner{Result: executor.Result{ExitCode: 0}}
	e := Executor{Paths: paths, Runner: stub}

	_, err := e.Run(emptyDef, "manage_processes", map[string]string{
		"op":     "kill",
		"name":   "node",
		"signal": "TERM",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stub.LastName != "/usr/bin/pkill" {
		t.Fatalf("expected pkill, got %q", stub.LastName)
	}
	if len(stub.LastArgs) != 2 || stub.LastArgs[0] != "-TERM" || stub.LastArgs[1] != "node" {
		t.Fatalf("unexpected args: %v", stub.LastArgs)
	}
}

func TestManageProcessesKillByPID(t *testing.T) {
	paths := testPaths(t)
	writeConfig(t, paths, fullConfig())

	stub := &stubRunner{Result: executor.Result{ExitCode: 0}}
	e := Executor{Paths: paths, Runner: stub}

	_, err := e.Run(emptyDef, "manage_processes", map[string]string{
		"op":  "kill",
		"pid": "12345",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stub.LastName != "/bin/kill" {
		t.Fatalf("expected kill, got %q", stub.LastName)
	}
}

func TestManageProcessesRejectsPID1(t *testing.T) {
	paths := testPaths(t)
	writeConfig(t, paths, fullConfig())

	stub := &stubRunner{}
	e := Executor{Paths: paths, Runner: stub}

	_, err := e.Run(emptyDef, "manage_processes", map[string]string{
		"op":  "kill",
		"pid": "1",
	})
	if err == nil {
		t.Fatalf("expected PID 1 to be rejected")
	}
}

func TestManageProcessesRejectsDisallowedSignal(t *testing.T) {
	paths := testPaths(t)
	writeConfig(t, paths, fullConfig())

	stub := &stubRunner{}
	e := Executor{Paths: paths, Runner: stub}

	_, err := e.Run(emptyDef, "manage_processes", map[string]string{
		"op":     "kill",
		"name":   "node",
		"signal": "USR1",
	})
	if err == nil {
		t.Fatalf("expected disallowed signal to be rejected")
	}
}

func TestManageProcessesRejectsDisabledPIDKill(t *testing.T) {
	paths := testPaths(t)
	cfg := fullConfig()
	cfg.Processes.AllowKillByPID = false
	writeConfig(t, paths, cfg)

	stub := &stubRunner{}
	e := Executor{Paths: paths, Runner: stub}

	_, err := e.Run(emptyDef, "manage_processes", map[string]string{
		"op":  "kill",
		"pid": "12345",
	})
	if err == nil {
		t.Fatalf("expected kill-by-PID to be rejected when disabled")
	}
}

func TestCheckPort(t *testing.T) {
	paths := testPaths(t)
	writeConfig(t, paths, fullConfig())

	stub := &stubRunner{Result: executor.Result{Stdout: "node 12345 TCP *:3000", ExitCode: 0}}
	e := Executor{Paths: paths, Runner: stub}

	_, err := e.Run(emptyDef, "check_port", map[string]string{"port": "3000"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stub.LastName != "/usr/sbin/lsof" {
		t.Fatalf("expected lsof, got %q", stub.LastName)
	}
}

func TestReleasePortRejectsDisallowed(t *testing.T) {
	paths := testPaths(t)
	writeConfig(t, paths, fullConfig())

	stub := &stubRunner{}
	e := Executor{Paths: paths, Runner: stub}

	_, err := e.Run(emptyDef, "release_port", map[string]string{"port": "9999"})
	if err == nil {
		t.Fatalf("expected disallowed port to be rejected")
	}
}

func TestManageFilesChmod(t *testing.T) {
	paths := testPaths(t)
	writeConfig(t, paths, fullConfig())

	stub := &stubRunner{Result: executor.Result{ExitCode: 0}}
	e := Executor{Paths: paths, Runner: stub}

	_, err := e.Run(emptyDef, "manage_files", map[string]string{
		"op":   "chmod",
		"path": "/Users/test/src/project/script.sh",
		"mode": "755",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stub.LastName != "/bin/chmod" {
		t.Fatalf("expected chmod, got %q", stub.LastName)
	}
	if stub.LastArgs[0] != "755" || stub.LastArgs[1] != "/Users/test/src/project/script.sh" {
		t.Fatalf("unexpected args: %v", stub.LastArgs)
	}
}

func TestManageFilesChmodRejectsSetuid(t *testing.T) {
	paths := testPaths(t)
	writeConfig(t, paths, fullConfig())

	stub := &stubRunner{}
	e := Executor{Paths: paths, Runner: stub}

	_, err := e.Run(emptyDef, "manage_files", map[string]string{
		"op":   "chmod",
		"path": "/Users/test/src/file",
		"mode": "4755",
	})
	if err == nil {
		t.Fatalf("expected setuid mode to be rejected")
	}
}

func TestManageFilesChmodRejectsPathOutsidePrefix(t *testing.T) {
	paths := testPaths(t)
	writeConfig(t, paths, fullConfig())

	stub := &stubRunner{}
	e := Executor{Paths: paths, Runner: stub}

	_, err := e.Run(emptyDef, "manage_files", map[string]string{
		"op":   "chmod",
		"path": "/etc/passwd",
		"mode": "644",
	})
	if err == nil {
		t.Fatalf("expected path outside prefix to be rejected")
	}
}

func TestManageFilesChmodRejectsRelativePath(t *testing.T) {
	paths := testPaths(t)
	writeConfig(t, paths, fullConfig())

	stub := &stubRunner{}
	e := Executor{Paths: paths, Runner: stub}

	_, err := e.Run(emptyDef, "manage_files", map[string]string{
		"op":   "chmod",
		"path": "relative/path",
		"mode": "755",
	})
	if err == nil {
		t.Fatalf("expected relative path to be rejected")
	}
}

func TestManageFilesChown(t *testing.T) {
	paths := testPaths(t)
	writeConfig(t, paths, fullConfig())

	stub := &stubRunner{Result: executor.Result{ExitCode: 0}}
	e := Executor{Paths: paths, Runner: stub}

	_, err := e.Run(emptyDef, "manage_files", map[string]string{
		"op":    "chown",
		"path":  "/Users/test/data/file.db",
		"owner": "randy:staff",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stub.LastName != "/usr/sbin/chown" {
		t.Fatalf("expected chown, got %q", stub.LastName)
	}
}

func TestUnsupportedAction(t *testing.T) {
	paths := testPaths(t)
	writeConfig(t, paths, fullConfig())

	stub := &stubRunner{}
	e := Executor{Paths: paths, Runner: stub}

	_, err := e.Run(emptyDef, "nonexistent", map[string]string{})
	if err == nil {
		t.Fatalf("expected unsupported action to fail")
	}
}

func TestManageServicesLaunchctlList(t *testing.T) {
	paths := testPaths(t)
	cfg := fullConfig()
	cfg.Services.AllowLaunchctl = true
	writeConfig(t, paths, cfg)

	stub := &stubRunner{Result: executor.Result{Stdout: "running", ExitCode: 0}}
	e := Executor{Paths: paths, Runner: stub}

	_, err := e.Run(emptyDef, "manage_services", map[string]string{
		"op":      "launchctl_list",
		"service": "postgresql",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stub.LastName != "/bin/launchctl" {
		t.Fatalf("expected launchctl, got %q", stub.LastName)
	}
	if stub.LastArgs[0] != "list" || stub.LastArgs[1] != "postgresql" {
		t.Fatalf("unexpected args: %v", stub.LastArgs)
	}
}

func TestManageServicesLaunchctlDisabled(t *testing.T) {
	paths := testPaths(t)
	writeConfig(t, paths, fullConfig())

	stub := &stubRunner{}
	e := Executor{Paths: paths, Runner: stub}

	_, err := e.Run(emptyDef, "manage_services", map[string]string{
		"op":      "launchctl_list",
		"service": "postgresql",
	})
	if err == nil {
		t.Fatalf("expected launchctl to be rejected when disabled")
	}
}

func TestManageAppsQuit(t *testing.T) {
	paths := testPaths(t)
	writeConfig(t, paths, fullConfig())

	stub := &stubRunner{Result: executor.Result{ExitCode: 0}}
	e := Executor{Paths: paths, Runner: stub}

	result, err := e.Run(emptyDef, "manage_apps", map[string]string{
		"op":   "quit",
		"name": "Kidfence",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", result.ExitCode)
	}
}

func TestManageAppsInstall(t *testing.T) {
	paths := testPaths(t)
	writeConfig(t, paths, fullConfig())

	stub := &stubRunner{Result: executor.Result{ExitCode: 0}}
	e := Executor{Paths: paths, Runner: stub}

	_, err := e.Run(emptyDef, "manage_apps", map[string]string{
		"op":     "install",
		"name":   "Kidfence",
		"source": "/Users/test/Library/Developer/Xcode/DerivedData/Kidfence-abc/Build/Products/Debug/Kidfence.app",
		"dest":   "/Applications",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// The last call should be ditto (rm -rf runs first, then ditto).
	if stub.LastName != "/usr/bin/ditto" {
		t.Fatalf("expected ditto, got %q", stub.LastName)
	}
}

func TestManageAppsRejectsDisallowedName(t *testing.T) {
	paths := testPaths(t)
	writeConfig(t, paths, fullConfig())

	stub := &stubRunner{}
	e := Executor{Paths: paths, Runner: stub}

	_, err := e.Run(emptyDef, "manage_apps", map[string]string{
		"op":   "quit",
		"name": "NotAllowed",
	})
	if err == nil {
		t.Fatalf("expected disallowed app to be rejected")
	}
}

func TestManageAppsRejectsDisallowedSource(t *testing.T) {
	paths := testPaths(t)
	writeConfig(t, paths, fullConfig())

	stub := &stubRunner{}
	e := Executor{Paths: paths, Runner: stub}

	_, err := e.Run(emptyDef, "manage_apps", map[string]string{
		"op":     "install",
		"name":   "Kidfence",
		"source": "/tmp/evil/Kidfence.app",
		"dest":   "/Applications",
	})
	if err == nil {
		t.Fatalf("expected disallowed source to be rejected")
	}
}

func TestManageAppsRejectsDisallowedDest(t *testing.T) {
	paths := testPaths(t)
	writeConfig(t, paths, fullConfig())

	stub := &stubRunner{}
	e := Executor{Paths: paths, Runner: stub}

	_, err := e.Run(emptyDef, "manage_apps", map[string]string{
		"op":     "install",
		"name":   "Kidfence",
		"source": "/Users/test/Library/Developer/Xcode/DerivedData/Kidfence-abc/Build/Products/Debug/Kidfence.app",
		"dest":   "/tmp/evil",
	})
	if err == nil {
		t.Fatalf("expected disallowed dest to be rejected")
	}
}

func TestManageAppsSymlink(t *testing.T) {
	paths := testPaths(t)
	writeConfig(t, paths, fullConfig())

	stub := &stubRunner{Result: executor.Result{ExitCode: 0}}
	e := Executor{Paths: paths, Runner: stub}

	_, err := e.Run(emptyDef, "manage_apps", map[string]string{
		"op":     "symlink",
		"name":   "Kidfence",
		"source": "/Users/test/Library/Developer/Xcode/DerivedData/Kidfence-abc/Build/Products/Debug/Kidfence.app",
		"dest":   "/Applications",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stub.LastName != "/bin/ln" {
		t.Fatalf("expected ln, got %q", stub.LastName)
	}
}

func TestBuildXcodebuild(t *testing.T) {
	paths := testPaths(t)
	writeConfig(t, paths, fullConfig())

	stub := &stubRunner{Result: executor.Result{Stdout: "BUILD SUCCEEDED", ExitCode: 0}}
	e := Executor{Paths: paths, Runner: stub}

	_, err := e.Run(emptyDef, "build", map[string]string{
		"op":            "xcodebuild",
		"project":       "/Volumes/2TB-1/src/ezblock/kidfence-mac/Kidfence.xcodeproj",
		"target":        "FilterExtension",
		"configuration": "Debug",
		"action":        "build",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stub.LastName != "/usr/bin/xcodebuild" {
		t.Fatalf("expected xcodebuild, got %q", stub.LastName)
	}
	expected := []string{"-project", "/Volumes/2TB-1/src/ezblock/kidfence-mac/Kidfence.xcodeproj", "-target", "FilterExtension", "-configuration", "Debug", "build"}
	for i, arg := range expected {
		if i >= len(stub.LastArgs) || stub.LastArgs[i] != arg {
			t.Fatalf("expected arg[%d]=%q, got %v", i, arg, stub.LastArgs)
		}
	}
}

func TestBuildXcodebuildWithProvisioningAndArch(t *testing.T) {
	paths := testPaths(t)
	writeConfig(t, paths, fullConfig())

	stub := &stubRunner{Result: executor.Result{Stdout: "ok", ExitCode: 0}}
	e := Executor{Paths: paths, Runner: stub}

	_, err := e.Run(emptyDef, "build", map[string]string{
		"op":                 "xcodebuild",
		"project":            "/Volumes/2TB-1/src/ezblock/kidfence-mac/Kidfence.xcodeproj",
		"target":             "Kidfence",
		"configuration":      "Debug",
		"allow_provisioning": "true",
		"arch":               "arm64",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	argsStr := strings.Join(stub.LastArgs, " ")
	if !strings.Contains(argsStr, "-allowProvisioningUpdates") {
		t.Fatalf("expected -allowProvisioningUpdates in args: %v", stub.LastArgs)
	}
	if !strings.Contains(argsStr, "ARCHS=arm64") {
		t.Fatalf("expected ARCHS=arm64 in args: %v", stub.LastArgs)
	}
}

func TestBuildRejectsDisallowedProject(t *testing.T) {
	paths := testPaths(t)
	writeConfig(t, paths, fullConfig())

	stub := &stubRunner{}
	e := Executor{Paths: paths, Runner: stub}

	_, err := e.Run(emptyDef, "build", map[string]string{
		"op":      "xcodebuild",
		"project": "/tmp/evil/Project.xcodeproj",
	})
	if err == nil {
		t.Fatalf("expected disallowed project to be rejected")
	}
}

func TestBuildRejectsInvalidAction(t *testing.T) {
	paths := testPaths(t)
	writeConfig(t, paths, fullConfig())

	stub := &stubRunner{}
	e := Executor{Paths: paths, Runner: stub}

	_, err := e.Run(emptyDef, "build", map[string]string{
		"op":      "xcodebuild",
		"project": "/Volumes/2TB-1/src/project/Test.xcodeproj",
		"action":  "install",
	})
	if err == nil {
		t.Fatalf("expected unsupported action to be rejected")
	}
}

func TestGenerateSudoers(t *testing.T) {
	cmds := fullConfig()
	output := GenerateSudoers(cmds, "randy")

	if !strings.Contains(output, "randy ALL=(root) NOPASSWD: /usr/bin/pip3 install *") {
		t.Fatalf("expected pip3 sudoers entry, got:\n%s", output)
	}
	if strings.Contains(output, "brew") {
		t.Fatalf("brew should not appear in sudoers (sudo=false)")
	}
}

func TestInstallPkgGates(t *testing.T) {
	oldEuid := geteuid
	oldTeam := pkgTeamIDOf
	oldLaunch := launchInstaller
	defer func() { geteuid = oldEuid; pkgTeamIDOf = oldTeam; launchInstaller = oldLaunch }()
	geteuid = func() int { return 0 } // install_pkg requires a root broker

	dir := t.TempDir()
	pkg := filepath.Join(dir, "OpenScope-1.0.pkg")
	if err := os.WriteFile(pkg, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	launched := ""
	launchInstaller = func(p, _ string) error { launched = p; return nil }
	e := Executor{}

	// Fail closed: no scope configured at all.
	if _, err := e.installPkg(admin.SystemCommands{}, map[string]string{"pkg": pkg}); err == nil {
		t.Fatal("expected refusal when no pkg scope is configured")
	}

	// Team-ID gate.
	teamCmds := admin.SystemCommands{}
	teamCmds.Pkg.AllowedTeamIDs = []string{"P7Y2NJ7JP3"}

	pkgTeamIDOf = func(string) (string, error) { return "P7Y2NJ7JP3", nil }
	launched = ""
	if _, err := e.installPkg(teamCmds, map[string]string{"pkg": pkg}); err != nil {
		t.Fatalf("matching team id should launch: %v", err)
	}
	if launched != pkg {
		t.Fatalf("installer not launched for allowed pkg")
	}

	pkgTeamIDOf = func(string) (string, error) { return "WRONGTEAM00", nil }
	if _, err := e.installPkg(teamCmds, map[string]string{"pkg": pkg}); err == nil {
		t.Fatal("expected refusal for a non-allowed signing team")
	}

	pkgTeamIDOf = func(string) (string, error) { return "", nil } // unsigned
	if _, err := e.installPkg(teamCmds, map[string]string{"pkg": pkg}); err == nil {
		t.Fatal("expected refusal for an unsigned pkg when team-ids are required")
	}

	// Prefix gate: outside the allowed prefix.
	outCmds := admin.SystemCommands{}
	outCmds.Pkg.AllowedPrefixes = []string{"/some/other/dir"}
	if _, err := e.installPkg(outCmds, map[string]string{"pkg": pkg}); err == nil {
		t.Fatal("expected refusal for a pkg outside the allowed prefix")
	}

	// Root-owned gate: a user-owned pkg is rejected (test runs as non-root).
	rootCmds := admin.SystemCommands{}
	rootCmds.Pkg.RequireRootOwned = true
	if _, err := e.installPkg(rootCmds, map[string]string{"pkg": pkg}); err == nil {
		t.Fatal("expected refusal for a non-root-owned pkg")
	}

	// Non-.pkg path is rejected.
	if _, err := e.installPkg(teamCmds, map[string]string{"pkg": filepath.Join(dir, "x.zip")}); err == nil {
		t.Fatal("expected refusal for a non-.pkg path")
	}
}

func TestInstallPkgNeedsRootBroker(t *testing.T) {
	oldEuid := geteuid
	defer func() { geteuid = oldEuid }()
	geteuid = func() int { return 501 } // non-root daemon
	dir := t.TempDir()
	pkg := filepath.Join(dir, "x.pkg")
	_ = os.WriteFile(pkg, []byte("x"), 0o644)
	cmds := admin.SystemCommands{}
	cmds.Pkg.RequireRootOwned = true
	if _, err := (Executor{}).installPkg(cmds, map[string]string{"pkg": pkg}); err == nil {
		t.Fatal("install_pkg must refuse on a non-root broker")
	}
}

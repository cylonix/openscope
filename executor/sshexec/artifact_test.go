// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package sshexec

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openscope/openscope/admin"
	"github.com/openscope/openscope/appdef"
	"github.com/openscope/openscope/config"
	"github.com/openscope/openscope/executor"
)

// writeImageTar writes a minimal `docker save`-shaped tar: a config blob with
// os/architecture, a manifest naming it, and a big layer entry that must be
// skipped, in the given entry order.
func writeImageTar(t *testing.T, path, osName, arch string, gzipped, manifestFirst bool) {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	add := func(name string, data []byte) {
		t.Helper()
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(data)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	config := []byte(fmt.Sprintf(`{"architecture":%q,"os":%q,"config":{},"rootfs":{"type":"layers"}}`, arch, osName))
	manifest := []byte(`[{"Config":"blobs/sha256/cfg","RepoTags":["x:latest"],"Layers":["layer.tar"]}]`)
	layer := bytes.Repeat([]byte{0}, 8192)
	if manifestFirst {
		add("manifest.json", manifest)
		add("layer.tar", layer)
		add("blobs/sha256/cfg", config)
	} else {
		add("layer.tar", layer)
		add("blobs/sha256/cfg", config)
		add("manifest.json", manifest)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}

	out := buf.Bytes()
	if gzipped {
		var gzBuf bytes.Buffer
		gz := gzip.NewWriter(&gzBuf)
		if _, err := gz.Write(out); err != nil {
			t.Fatal(err)
		}
		if err := gz.Close(); err != nil {
			t.Fatal(err)
		}
		out = gzBuf.Bytes()
	}
	if err := os.WriteFile(path, out, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestDockerImagePlatform(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct {
		name                   string
		gzipped, manifestFirst bool
	}{
		{"plain-manifest-first", false, true},
		{"plain-manifest-last", false, false},
		{"gzipped", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(dir, tc.name+".tar")
			writeImageTar(t, p, "linux", "arm64", tc.gzipped, tc.manifestFirst)
			got, err := dockerImagePlatform(p)
			if err != nil {
				t.Fatalf("dockerImagePlatform: %v", err)
			}
			if got != "linux/arm64" {
				t.Errorf("platform = %q, want linux/arm64", got)
			}
		})
	}

	t.Run("not-an-image", func(t *testing.T) {
		p := filepath.Join(dir, "junk.tar")
		var buf bytes.Buffer
		tw := tar.NewWriter(&buf)
		_ = tw.WriteHeader(&tar.Header{Name: "readme.txt", Mode: 0o644, Size: 2, Typeflag: tar.TypeReg})
		_, _ = tw.Write([]byte("hi"))
		_ = tw.Close()
		if err := os.WriteFile(p, buf.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := dockerImagePlatform(p); err == nil {
			t.Error("expected an error for a tar without an image config")
		}
	})
}

// gatedDef is a deploy verb with the docker-image artifact gate.
func gatedDef(platform string) appdef.Definition {
	return appdef.Definition{
		Version: 1,
		App:     appdef.App{Name: "ssh", Executor: "ssh", SecurityMode: "protected"},
		Actions: map[string]appdef.Action{
			"deploy_web": {
				StdinFile:     "image",
				StdinMedia:    "docker-image",
				StdinPlatform: platform,
				Command:       "docker load && docker-compose up -d web",
				Parameters: []appdef.Parameter{
					{Name: "target", Type: "string", PolicyKey: "target"},
					{Name: "image", Type: "string", Constraint: "local_source"},
				},
			},
		},
	}
}

func gateTestPaths(t *testing.T, srcDir string, facts *admin.TargetFacts) config.Paths {
	t.Helper()
	paths := config.Paths{SSHTargetsFile: filepath.Join(t.TempDir(), "ssh_targets.yaml")}
	if err := admin.SaveSSHTargets(paths.SSHTargetsFile, admin.SSHTargets{
		Version: 1,
		Targets: []admin.SSHTarget{{
			Alias: "origin", Host: "o", User: "deploy",
			AllowedUploadSources: []string{srcDir},
			Facts:                facts,
		}},
	}); err != nil {
		t.Fatal(err)
	}
	return paths
}

func TestArtifactGateRefusesWrongPlatform(t *testing.T) {
	srcDir := t.TempDir()
	img := filepath.Join(srcDir, "web.tar.gz")
	writeImageTar(t, img, "linux", "arm64", true, true)

	runner := &stubRunner{result: executor.Result{ExitCode: 0}}
	exec := Executor{Paths: gateTestPaths(t, srcDir, nil), Runner: runner}
	_, err := exec.Run(gatedDef("linux/amd64"), "deploy_web", map[string]string{"target": "origin", "image": img})
	if err == nil {
		t.Fatal("expected the gate to refuse an arm64 image for an amd64 verb")
	}
	if !strings.Contains(err.Error(), "linux/arm64") || !strings.Contains(err.Error(), "linux/amd64") {
		t.Errorf("error should name both platforms: %v", err)
	}
	if runner.name != "" {
		t.Error("no remote command may run when the gate refuses")
	}
}

func TestArtifactGatePassesAndReports(t *testing.T) {
	srcDir := t.TempDir()
	img := filepath.Join(srcDir, "web.tar.gz")
	writeImageTar(t, img, "linux", "amd64", true, true)

	runner := &stubRunner{result: executor.Result{Stdout: "Loaded image\n", ExitCode: 0}}
	exec := Executor{Paths: gateTestPaths(t, srcDir, nil), Runner: runner}
	res, err := exec.Run(gatedDef("linux/amd64"), "deploy_web", map[string]string{"target": "origin", "image": img})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !strings.Contains(res.Stdout, `"artifact_platform":"linux/amd64"`) {
		t.Errorf("payload should report the detected platform, got %s", res.Stdout)
	}
}

// With no stdin_platform on the verb, pinned target facts supply the
// expectation — the incident shape: arm64 build, amd64 droplet.
func TestArtifactGateUsesTargetFacts(t *testing.T) {
	srcDir := t.TempDir()
	img := filepath.Join(srcDir, "web.tar.gz")
	writeImageTar(t, img, "linux", "arm64", true, true)

	facts := &admin.TargetFacts{OS: "Linux", Arch: "x86_64"}
	runner := &stubRunner{result: executor.Result{ExitCode: 0}}
	exec := Executor{Paths: gateTestPaths(t, srcDir, facts), Runner: runner}
	_, err := exec.Run(gatedDef(""), "deploy_web", map[string]string{"target": "origin", "image": img})
	if err == nil {
		t.Fatal("expected facts-derived platform to refuse the artifact")
	}
	if !strings.Contains(err.Error(), "pinned facts") {
		t.Errorf("error should say the expectation came from facts: %v", err)
	}
}

// seqRunner returns scripted results per call, recording each remote command.
type seqRunner struct {
	results  []executor.Result
	commands []string
}

func (s *seqRunner) Run(name string, args []string, stdin io.Reader) (executor.Result, error) {
	if stdin != nil {
		_, _ = io.Copy(io.Discard, stdin)
	}
	s.commands = append(s.commands, args[len(args)-1])
	i := len(s.commands) - 1
	if i >= len(s.results) {
		i = len(s.results) - 1
	}
	return s.results[i], nil
}

func verifyDef(retries, delaySeconds int) appdef.Definition {
	return appdef.Definition{
		Version: 1,
		App:     appdef.App{Name: "ssh", Executor: "ssh", SecurityMode: "protected"},
		Actions: map[string]appdef.Action{
			"deploy_web": {
				Command:            "docker-compose up -d web",
				Verify:             "curl -sf localhost:8003/",
				VerifyRetries:      retries,
				VerifyDelaySeconds: delaySeconds,
				Parameters: []appdef.Parameter{
					{Name: "target", Type: "string", PolicyKey: "target"},
				},
			},
		},
	}
}

func verifyTestPaths(t *testing.T) config.Paths {
	t.Helper()
	paths := config.Paths{SSHTargetsFile: filepath.Join(t.TempDir(), "ssh_targets.yaml")}
	if err := admin.SaveSSHTargets(paths.SSHTargetsFile, admin.SSHTargets{
		Version: 1,
		Targets: []admin.SSHTarget{{Alias: "origin", Host: "o", User: "deploy"}},
	}); err != nil {
		t.Fatal(err)
	}
	return paths
}

func TestVerifyFailureFailsTheAction(t *testing.T) {
	runner := &seqRunner{results: []executor.Result{
		{Stdout: "recreated\n", ExitCode: 0}, // main command
		{Stderr: "curl: (7) refused", ExitCode: 1},
		{Stderr: "curl: (7) refused", ExitCode: 1},
	}}
	var slept []time.Duration
	old := sleepFn
	sleepFn = func(d time.Duration) { slept = append(slept, d) }
	defer func() { sleepFn = old }()

	exec := Executor{Paths: verifyTestPaths(t), Runner: runner}
	_, err := exec.Run(verifyDef(1, 5), "deploy_web", map[string]string{"target": "origin"})
	if err == nil {
		t.Fatal("verify failed twice — the action must fail")
	}
	if !strings.Contains(err.Error(), "verify failed after 2 attempt(s)") {
		t.Errorf("error = %v", err)
	}
	if !strings.Contains(err.Error(), "NOT healthy") || !strings.Contains(err.Error(), "recreated") {
		t.Errorf("error should carry the health warning and the command output: %v", err)
	}
	if len(runner.commands) != 3 {
		t.Errorf("remote calls = %d, want command + 2 verify attempts", len(runner.commands))
	}
	if len(slept) != 2 || slept[0] != 5*time.Second {
		t.Errorf("each verify attempt should be preceded by the settle delay, got %v", slept)
	}
}

func TestVerifyRetrySucceeds(t *testing.T) {
	runner := &seqRunner{results: []executor.Result{
		{Stdout: "recreated\n", ExitCode: 0},
		{Stderr: "curl: (7) refused", ExitCode: 1}, // first verify: still settling
		{Stdout: "ok\n", ExitCode: 0},              // retry passes
	}}
	old := sleepFn
	sleepFn = func(time.Duration) {}
	defer func() { sleepFn = old }()

	exec := Executor{Paths: verifyTestPaths(t), Runner: runner}
	res, err := exec.Run(verifyDef(1, 5), "deploy_web", map[string]string{"target": "origin"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !strings.Contains(res.Stdout, `"verify":"ok"`) {
		t.Errorf("payload should record verify ok, got %s", res.Stdout)
	}
	if !strings.Contains(res.Stdout, `"verify_output":"ok"`) {
		t.Errorf("payload should carry the verify output, got %s", res.Stdout)
	}
}

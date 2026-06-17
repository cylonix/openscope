// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package admin

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/openscope/openscope/config"
)

func TestLoadSSMTargetsNormalizesAndValidates(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ssm_targets.yaml")
	if err := os.WriteFile(path, []byte(`version: 1
targets:
  - alias: web
    instance_id: i-web
    region: us-west-2
    allowed_path_prefixes: ["/var/log/", "/var/log/"]
  - alias: api
    instance_id: i-api
    region: us-west-2
    allowed_services: [orders-api, orders-api]
`), 0o600); err != nil {
		t.Fatal(err)
	}
	targets, err := LoadSSMTargets(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	// Sorted by alias; dedup applied to lists.
	if len(targets.Targets) != 2 || targets.Targets[0].Alias != "api" {
		t.Fatalf("targets = %+v", targets.Targets)
	}
	if web, ok := FindSSMTarget(targets, "web"); !ok || len(web.AllowedPathPrefixes) != 1 {
		t.Fatalf("web target not normalized: %+v", web)
	}
}

func TestLoadSSMTargetsOrDefaultMissing(t *testing.T) {
	got, err := LoadSSMTargetsOrDefault(config.Paths{SSMTargetsFile: filepath.Join(t.TempDir(), "absent.yaml")})
	if err != nil {
		t.Fatalf("missing file should default, got %v", err)
	}
	if got.Version != 1 || len(got.Targets) != 0 {
		t.Fatalf("default = %+v", got)
	}
}

func TestSSMTargetsValidateRejectsIncomplete(t *testing.T) {
	bad := SSMTargets{Version: 1, Targets: []SSMTarget{{Alias: "x"}}}
	if err := bad.Validate(); err == nil {
		t.Error("target missing instance_id/region must be invalid")
	}
}

func TestSSMTargetAllowLists(t *testing.T) {
	target := SSMTarget{
		AllowedServices:     []string{"orders-api"},
		AllowedPaths:        []string{"/etc/orders-api/version"},
		AllowedPathPrefixes: []string{"/var/log"},
	}
	if !SSMTargetAllowsService(target, "orders-api") || SSMTargetAllowsService(target, "nginx") {
		t.Error("service allow-list wrong")
	}
	if !SSMTargetAllowsPath(target, "/etc/orders-api/version") || !SSMTargetAllowsPath(target, "/var/log/app.log") {
		t.Error("allowed paths should match exact + under-prefix")
	}
	if SSMTargetAllowsPath(target, "/etc/shadow") {
		t.Error("disallowed path matched")
	}
}

func TestAddRemoveSSMTargetRoundtrip(t *testing.T) {
	paths := config.Paths{SSMTargetsFile: filepath.Join(t.TempDir(), "ssm_targets.yaml")}
	if _, added, err := AddSSMTarget(paths, SSMTarget{Alias: "prod", InstanceID: "i-1", Region: "us-west-2"}); err != nil || !added {
		t.Fatalf("add: err=%v added=%v", err, added)
	}
	if _, added, _ := AddSSMTarget(paths, SSMTarget{Alias: "prod", InstanceID: "i-1", Region: "us-west-2"}); added {
		t.Error("re-adding the same alias should be a no-op")
	}
	got, _ := LoadSSMTargetsOrDefault(paths)
	if _, ok := FindSSMTarget(got, "prod"); !ok {
		t.Fatal("prod not persisted")
	}
	if _, removed, _ := RemoveSSMTarget(paths, "prod"); !removed {
		t.Error("remove should report removed")
	}
}

func TestSSMTargetValidate(t *testing.T) {
	if err := (SSMTarget{Alias: "x"}).Validate(); err == nil {
		t.Error("missing instance_id/region should fail")
	}
	if err := (SSMTarget{Alias: "x", InstanceID: "i-1", Region: "us-west-2", AllowedPaths: []string{"rel"}}).Validate(); err == nil {
		t.Error("relative allowed path should fail")
	}
	if err := (SSMTarget{Alias: "x", InstanceID: "i-1", Region: "us-west-2"}).Validate(); err != nil {
		t.Errorf("valid target rejected: %v", err)
	}
}

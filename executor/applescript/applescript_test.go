// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package applescript

import (
	"testing"

	"github.com/openscope/openscope/appdef"
	"github.com/openscope/openscope/executor"
)

type fakeHelper struct {
	called    bool
	gotAction string
	result    executor.Result
}

func (f *fakeHelper) run(_ appdef.Definition, actionName string, _ map[string]string) (executor.Result, error) {
	f.called = true
	f.gotAction = actionName
	return f.result, nil
}

// When a Helper is injected (the root-daemon forwarder in phase 4), Run must
// delegate Apple-event execution to it instead of spawning asapple locally.
func TestExecutorDelegatesToHelper(t *testing.T) {
	fake := &fakeHelper{result: executor.Result{Stdout: "delegated"}}
	e := Executor{Helper: fake}
	def := appdef.Definition{
		App:     appdef.App{Name: "notes"},
		Actions: map[string]appdef.Action{"read_note": {}},
	}

	res, err := e.Run(def, "read_note", map[string]string{"folder": "Work"})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if !fake.called || fake.gotAction != "read_note" {
		t.Fatalf("Run did not delegate to the helper (called=%v action=%q)", fake.called, fake.gotAction)
	}
	if res.Stdout != "delegated" {
		t.Fatalf("helper result not returned: %+v", res)
	}
}

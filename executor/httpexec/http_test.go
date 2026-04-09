// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package httpexec

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/openscope/openscope/admin"
	"github.com/openscope/openscope/appdef"
	"github.com/openscope/openscope/config"
)

func TestExecutorPerformsGETWithPathAndQuery(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.URL.Path, "/rest/api/3/issue/ENG-123"; got != want {
			t.Fatalf("path = %q, want %q", got, want)
		}
		if got, want := r.URL.Query().Get("fields"), "summary,status"; got != want {
			t.Fatalf("fields query = %q, want %q", got, want)
		}
		if got, want := r.Header.Get("Authorization"), "Bearer secret"; got != want {
			t.Fatalf("authorization header = %q, want %q", got, want)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"key":"ENG-123","fields":{"summary":"Hello"}}`))
	}))
	defer server.Close()

	paths := config.Paths{HTTPProfilesFile: filepath.Join(t.TempDir(), "http_profiles.yaml")}
	if err := admin.SaveHTTPProfiles(paths.HTTPProfilesFile, admin.HTTPProfiles{
		Version: 1,
		Profiles: []admin.HTTPProfile{{
			Name:    "jira-work",
			BaseURL: server.URL,
			Headers: map[string]string{"Authorization": "Bearer secret"},
		}},
	}); err != nil {
		t.Fatalf("SaveHTTPProfiles returned error: %v", err)
	}

	exec := Executor{Paths: paths, Client: server.Client()}
	def := appdef.Definition{
		Actions: map[string]appdef.Action{
			"get_issue": {Script: "GET /rest/api/3/issue/{issue}"},
		},
	}

	result, err := exec.Run(def, "get_issue", map[string]string{
		"profile":      "jira-work",
		"issue":        "ENG-123",
		"query.fields": "summary,status",
	})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	var payload map[string]any
	if err := json.Unmarshal([]byte(result.Stdout), &payload); err != nil {
		t.Fatalf("Unmarshal returned error: %v", err)
	}
	if payload["status_code"].(float64) != 200 {
		t.Fatalf("unexpected payload: %#v", payload)
	}
}

func TestExecutorPerformsPOSTWithJSONBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.Method, http.MethodPost; got != want {
			t.Fatalf("method = %q, want %q", got, want)
		}
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Fatalf("content-type = %q, want application/json", got)
		}
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("Decode returned error: %v", err)
		}
		if body["text"] != "hello" {
			t.Fatalf("unexpected body: %#v", body)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	paths := config.Paths{HTTPProfilesFile: filepath.Join(t.TempDir(), "http_profiles.yaml")}
	if err := admin.SaveHTTPProfiles(paths.HTTPProfilesFile, admin.HTTPProfiles{
		Version: 1,
		Profiles: []admin.HTTPProfile{{Name: "demo", BaseURL: server.URL}},
	}); err != nil {
		t.Fatalf("SaveHTTPProfiles returned error: %v", err)
	}

	exec := Executor{Paths: paths, Client: server.Client()}
	def := appdef.Definition{
		Actions: map[string]appdef.Action{
			"send": {Script: "POST /v1/messages"},
		},
	}

	if _, err := exec.Run(def, "send", map[string]string{
		"profile":   "demo",
		"body.text": "hello",
	}); err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
}

func TestExecutorRejectsMissingProfileAndHTTPErrors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer server.Close()

	paths := config.Paths{HTTPProfilesFile: filepath.Join(t.TempDir(), "http_profiles.yaml")}
	if err := admin.SaveHTTPProfiles(paths.HTTPProfilesFile, admin.HTTPProfiles{
		Version: 1,
		Profiles: []admin.HTTPProfile{{Name: "demo", BaseURL: server.URL}},
	}); err != nil {
		t.Fatalf("SaveHTTPProfiles returned error: %v", err)
	}

	exec := Executor{Paths: paths, Client: server.Client()}
	def := appdef.Definition{Actions: map[string]appdef.Action{"bad": {Script: "GET /v1/forbidden"}}}

	if _, err := exec.Run(def, "bad", map[string]string{}); err == nil {
		t.Fatalf("expected missing profile to fail")
	}
	if _, err := exec.Run(def, "bad", map[string]string{"profile": "demo"}); err == nil {
		t.Fatalf("expected non-2xx response to fail")
	}
}

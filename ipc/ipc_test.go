// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipc

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/openscope/openscope/config"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}

func TestCallUsesHTTPWhenConfigured(t *testing.T) {
	originalClient := httpClient
	httpClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method != http.MethodPost {
			t.Fatalf("unexpected method %q", r.Method)
		}
		if r.URL.String() != "http://openscoped.local/v1/actions" {
			t.Fatalf("unexpected URL %q", r.URL.String())
		}

		var request Request
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatalf("Decode() error = %v", err)
		}
		if request.App != "notes" || request.Action != "read_note" || request.Agent != "openclaw" {
			t.Fatalf("unexpected request %#v", request)
		}

		payload, err := json.Marshal(Response{
			OK:       true,
			App:      request.App,
			Action:   request.Action,
			Agent:    request.Agent,
			Data:     map[string]any{"title": "Sprint Plan"},
			ExitCode: 0,
		})
		if err != nil {
			t.Fatalf("Marshal() error = %v", err)
		}

		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewReader(payload)),
			Header:     make(http.Header),
		}, nil
	})}
	defer func() {
		httpClient = originalClient
	}()

	response, err := Call(config.Paths{HTTPURL: "http://openscoped.local"}, Request{
		App:    "notes",
		Action: "read_note",
		Agent:  "openclaw",
	})
	if err != nil {
		t.Fatalf("Call() error = %v", err)
	}
	if !response.OK {
		t.Fatalf("expected OK response, got %#v", response)
	}
}

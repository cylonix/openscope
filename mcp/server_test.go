// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package mcp

import (
	"bufio"
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

type stubProvider struct {
	tools  []Tool
	called string
}

func (p *stubProvider) Tools() []Tool { return p.tools }
func (p *stubProvider) Call(name string, _ map[string]json.RawMessage) ToolResult {
	p.called = name
	return TextResult("ok:"+name, false)
}

// decodeResponses splits the server's newline-delimited output into parsed
// JSON-RPC responses.
func decodeResponses(t *testing.T, out *bytes.Buffer) []rpcResponse {
	t.Helper()
	var resps []rpcResponse
	sc := bufio.NewScanner(out)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var r rpcResponse
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatalf("decode response %q: %v", line, err)
		}
		resps = append(resps, r)
	}
	return resps
}

func TestHandshakeAndToolsList(t *testing.T) {
	in := strings.NewReader(strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"ping"}`,
	}, "\n") + "\n")

	var out bytes.Buffer
	prov := &stubProvider{tools: []Tool{{Name: "ssh_tail_logs", InputSchema: map[string]any{"type": "object"}}}}
	s := &Server{Conn: NewConn(in, &out), Provider: prov, Name: "openscope", Version: "test", Instructions: "hi"}
	if err := s.Run(); err != nil {
		t.Fatalf("Run: %v", err)
	}

	resps := decodeResponses(t, &out)
	// initialize, tools/list, ping -> 3 responses; the notification produces none.
	if len(resps) != 3 {
		t.Fatalf("want 3 responses, got %d: %+v", len(resps), resps)
	}

	// initialize result: protocolVersion echoed + listChanged advertised.
	var initRes struct {
		ProtocolVersion string `json:"protocolVersion"`
		Capabilities    struct {
			Tools struct {
				ListChanged bool `json:"listChanged"`
			} `json:"tools"`
		} `json:"capabilities"`
		Instructions string `json:"instructions"`
	}
	if err := json.Unmarshal(resps[0].Result, &initRes); err != nil {
		t.Fatalf("initialize result: %v", err)
	}
	if initRes.ProtocolVersion != "2025-06-18" {
		t.Fatalf("protocolVersion = %q", initRes.ProtocolVersion)
	}
	if !initRes.Capabilities.Tools.ListChanged {
		t.Fatalf("listChanged not advertised")
	}
	if initRes.Instructions != "hi" {
		t.Fatalf("instructions = %q", initRes.Instructions)
	}

	// tools/list result carries the provider's tool.
	var listRes struct {
		Tools []Tool `json:"tools"`
	}
	if err := json.Unmarshal(resps[1].Result, &listRes); err != nil {
		t.Fatalf("tools/list result: %v", err)
	}
	if len(listRes.Tools) != 1 || listRes.Tools[0].Name != "ssh_tail_logs" {
		t.Fatalf("tools/list = %+v", listRes.Tools)
	}
}

func TestToolsCallAndUnknownMethod(t *testing.T) {
	in := strings.NewReader(strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"ssh_tail_logs","arguments":{"target":"prod"}}}`,
		`{"jsonrpc":"2.0","id":2,"method":"does/not/exist"}`,
	}, "\n") + "\n")

	var out bytes.Buffer
	prov := &stubProvider{}
	s := &Server{Conn: NewConn(in, &out), Provider: prov, Name: "openscope", Version: "test"}
	if err := s.Run(); err != nil {
		t.Fatalf("Run: %v", err)
	}

	resps := decodeResponses(t, &out)
	if len(resps) != 2 {
		t.Fatalf("want 2 responses, got %d", len(resps))
	}
	if prov.called != "ssh_tail_logs" {
		t.Fatalf("provider.Call not invoked with tool name, got %q", prov.called)
	}
	var callRes ToolResult
	if err := json.Unmarshal(resps[0].Result, &callRes); err != nil {
		t.Fatalf("tools/call result: %v", err)
	}
	if len(callRes.Content) != 1 || callRes.Content[0].Text != "ok:ssh_tail_logs" {
		t.Fatalf("tools/call content = %+v", callRes.Content)
	}
	if resps[1].Error == nil || resps[1].Error.Code != codeMethodNotFound {
		t.Fatalf("unknown method should return MethodNotFound, got %+v", resps[1].Error)
	}
}

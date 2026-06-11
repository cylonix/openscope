package router

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/openscope/openscope/router/internal/store"
)

func TestJSONLMirrorAppendsAuditEvent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	ms := &memStore{}
	rs := WithJSONLMirror(ms, path)

	tenantID := uuid.New()
	err := rs.AppendRouterEvent(context.Background(), nil, store.RouterEvent{
		RequestID: uuid.New(), TenantID: tenantID, Role: "developer",
		Endpoint: "/v1/chat", Model: "us.amazon.nova-micro-v1:0",
		Decision: "deny", Result: "dlp_block", Reason: "matched DLP rule(s): private-key-block",
	})
	if err != nil {
		t.Fatalf("AppendRouterEvent: %v", err)
	}
	if len(ms.events) != 1 {
		t.Fatal("underlying store did not receive the event")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("mirror file: %v", err)
	}
	var line map[string]any
	if err := json.Unmarshal(data, &line); err != nil {
		t.Fatalf("mirror line not JSON: %v", err)
	}
	if line["app"] != "router" || line["action"] != "/v1/chat" || line["decision"] != "deny" || line["result"] != "dlp_block" {
		t.Errorf("mirror line = %v", line)
	}
	params, _ := line["params"].(map[string]any)
	if params["tenant_id"] != tenantID.String() {
		t.Errorf("params = %v", params)
	}
}

// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package cpclient

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

type fakeCP struct {
	mu      sync.Mutex
	batches [][]UsageEvent
	tokens  []string
	fail    bool
}

func (f *fakeCP) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/usage", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.fail {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		var body struct {
			BatchID string       `json:"batch_id"`
			Events  []UsageEvent `json:"events"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		f.batches = append(f.batches, body.Events)
		f.tokens = append(f.tokens, r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusOK)
	})
	return mux
}

func (f *fakeCP) eventCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, b := range f.batches {
		n += len(b)
	}
	return n
}

func (f *fakeCP) setFail(v bool) {
	f.mu.Lock()
	f.fail = v
	f.mu.Unlock()
}

func newTestClient(t *testing.T, url string) (*Client, string) {
	t.Helper()
	spool := filepath.Join(t.TempDir(), "cp_spool.jsonl")
	c := New(Config{
		BaseURL:         url,
		DeploymentToken: "osk_deploy_test",
		FlushInterval:   20 * time.Millisecond,
		SpoolPath:       spool,
	})
	t.Cleanup(c.Close)
	return c, spool
}

func TestNilClientIsNoOp(t *testing.T) {
	var c *Client
	c.Record(UsageEvent{Kind: "action"}) // must not panic
	c.Close()
	if c := New(Config{}); c != nil {
		t.Error("New with empty BaseURL should return nil")
	}
}

func TestUsageDelivery(t *testing.T) {
	cp := &fakeCP{}
	srv := httptest.NewServer(cp.handler())
	defer srv.Close()
	c, _ := newTestClient(t, srv.URL)

	c.Record(UsageEvent{Kind: "action", App: "ssh", Action: "check_host", Decision: "allow", Result: "success"})
	c.Record(UsageEvent{Kind: "chat", Model: "us.amazon.nova-micro-v1:0", Decision: "deny", Result: "dlp_block"})

	deadline := time.Now().Add(2 * time.Second)
	for cp.eventCount() < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if cp.eventCount() != 2 {
		t.Fatalf("delivered %d events, want 2", cp.eventCount())
	}
	cp.mu.Lock()
	defer cp.mu.Unlock()
	if cp.tokens[0] != "Bearer osk_deploy_test" {
		t.Errorf("auth header = %q", cp.tokens[0])
	}
}

func TestSpoolAndReplayAcrossRestart(t *testing.T) {
	cp := &fakeCP{}
	srv := httptest.NewServer(cp.handler())
	defer srv.Close()

	cp.setFail(true)
	c, spool := newTestClient(t, srv.URL)
	c.Record(UsageEvent{Kind: "action", App: "ssh", Result: "success", Decision: "allow"})
	// Wait for a failed flush to land the event in the spool.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if data, err := os.ReadFile(spool); err == nil && len(data) > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	c.Close()
	if data, err := os.ReadFile(spool); err != nil || len(data) == 0 {
		t.Fatalf("event not spooled: err=%v len=%d", err, len(data))
	}

	// "Restart": a new client over the same spool, CP healthy again.
	cp.setFail(false)
	c2 := New(Config{
		BaseURL:         srv.URL,
		DeploymentToken: "osk_deploy_test",
		FlushInterval:   20 * time.Millisecond,
		SpoolPath:       spool,
	})
	defer c2.Close()
	deadline = time.Now().Add(2 * time.Second)
	for cp.eventCount() < 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if cp.eventCount() != 1 {
		t.Fatalf("spooled event not replayed after restart")
	}
	// clearSpool runs just after the successful POST — allow it a moment.
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(spool); os.IsNotExist(err) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Error("spool not cleared after successful replay")
}

func TestRecordNeverBlocks(t *testing.T) {
	// No server, tiny interval irrelevant: fill the channel far past its
	// 1024 capacity; Record must return immediately and count drops.
	c := New(Config{BaseURL: "http://127.0.0.1:1", FlushInterval: time.Hour})
	defer c.Close()

	done := make(chan struct{})
	go func() {
		for range 5000 {
			c.Record(UsageEvent{Kind: "action"})
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Record blocked")
	}
	if c.Dropped() == 0 {
		t.Error("expected dropped events with a full buffer")
	}
}

func TestSpoolCapDropsOldest(t *testing.T) {
	spool := filepath.Join(t.TempDir(), "spool.jsonl")
	c := &Client{cfg: Config{SpoolPath: spool, MaxSpoolBytes: 600}}
	var events []UsageEvent
	for i := range 100 {
		events = append(events, UsageEvent{Kind: "action", App: "ssh", RequestID: string(rune('a' + i%26))})
	}
	c.writeSpool(events)
	info, err := os.Stat(spool)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() > 600 {
		t.Errorf("spool size %d exceeds cap", info.Size())
	}
	kept := c.readSpool()
	if len(kept) == 0 || len(kept) >= 100 {
		t.Errorf("kept %d events, want a non-empty tail subset", len(kept))
	}
	// The tail (newest) must be what survived.
	if kept[len(kept)-1].RequestID != events[99].RequestID {
		t.Error("newest event was dropped; cap must drop oldest")
	}
}

func TestManifestVerify(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	ring := map[string]string{"test-key": base64.StdEncoding.EncodeToString(pub)}
	payload := json.RawMessage(`{"product":"broker","version":"v0.2.0"}`)

	good := &Manifest{
		Kind: "release", Version: "v0.2.0", Payload: payload,
		Signature:   base64.StdEncoding.EncodeToString(ed25519.Sign(priv, payload)),
		PublicKeyID: "test-key",
	}
	if err := good.Verify(ring); err != nil {
		t.Errorf("valid manifest rejected: %v", err)
	}

	tampered := *good
	tampered.Payload = json.RawMessage(`{"product":"broker","version":"v9.9.9"}`)
	if err := tampered.Verify(ring); err == nil {
		t.Error("tampered payload accepted")
	}

	unknown := *good
	unknown.PublicKeyID = "not-in-ring"
	if err := unknown.Verify(ring); err == nil {
		t.Error("unknown key id accepted")
	}
}

func TestFetchUpdateManifest(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	// Install a test key into the package ring for the duration.
	VendorKeys["test-fetch-key"] = base64.StdEncoding.EncodeToString(pub)
	defer delete(VendorKeys, "test-fetch-key")

	payload, _ := json.Marshal(ReleaseInfo{Product: "broker", Version: "v0.3.0", ReleasedAt: "2026-06-09"})
	manifest := Manifest{
		Kind: "release", Version: "v0.3.0", Payload: payload,
		Signature:   base64.StdEncoding.EncodeToString(ed25519.Sign(priv, payload)),
		PublicKeyID: "test-fetch-key",
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/updates/latest" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(manifest)
	}))
	defer srv.Close()

	c, _ := newTestClient(t, srv.URL)
	_, info, err := c.FetchUpdateManifest("broker")
	if err != nil {
		t.Fatalf("FetchUpdateManifest: %v", err)
	}
	if info.Version != "v0.3.0" {
		t.Errorf("version = %s", info.Version)
	}

	// Corrupt signature must be rejected at fetch time.
	manifest.Signature = base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
	if _, _, err := c.FetchUpdateManifest("broker"); err == nil {
		t.Error("bad signature accepted by fetch")
	}
}

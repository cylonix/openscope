// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package cpclient is the customer-side client for the OpenScope control
// plane. Customer-deployed routers and brokers connect OUTBOUND to the
// vendor control plane for usage metering, signed policy-bundle/update
// manifests, and enrollment.
//
// Two invariants:
//
//  1. STRICTLY OPTIONAL — with no OPENSCOPE_CONTROL_PLANE_URL the client
//     is a no-op; OpenScope runs fully standalone.
//  2. NEVER IN THE REQUEST PATH — Record is non-blocking, all network I/O
//     happens in one background goroutine, and an unreachable control
//     plane only ever costs telemetry (spooled to disk, capped), never
//     customer traffic.
//
// Usage events carry metadata only: counts, tokens, costs, decisions,
// rule IDs. There is no field for prompt or response bodies.
package cpclient

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// Config configures the client. Zero BaseURL → disabled no-op client.
type Config struct {
	BaseURL         string // OPENSCOPE_CONTROL_PLANE_URL
	DeploymentToken string // OPENSCOPE_DEPLOYMENT_TOKEN (osk_deploy_*)
	FlushInterval   time.Duration
	SpoolPath       string // JSONL spool for events the CP couldn't take
	MaxSpoolBytes   int64
	HTTPClient      *http.Client
}

// FromEnv builds a Config from the standard env vars. spoolPath is where
// the caller wants undelivered events spooled (e.g. <StateDir>/cp_spool.jsonl).
func FromEnv(spoolPath string) Config {
	return Config{
		BaseURL:         os.Getenv("OPENSCOPE_CONTROL_PLANE_URL"),
		DeploymentToken: os.Getenv("OPENSCOPE_DEPLOYMENT_TOKEN"),
		SpoolPath:       spoolPath,
	}
}

// UsageEvent is one metered decision — metadata only, no bodies, no params.
type UsageEvent struct {
	Timestamp    time.Time `json:"ts"`
	RequestID    string    `json:"request_id,omitempty"`
	Kind         string    `json:"kind"` // "action" (broker) | "chat" | "scan" (router)
	App          string    `json:"app,omitempty"`
	Action       string    `json:"action,omitempty"`
	Model        string    `json:"model,omitempty"`
	Decision     string    `json:"decision"`
	Result       string    `json:"result"`
	DLPRuleIDs   []string  `json:"dlp_rule_ids,omitempty"`
	InputTokens  int       `json:"input_tokens,omitempty"`
	OutputTokens int       `json:"output_tokens,omitempty"`
	CostUSD      float64   `json:"cost_usd,omitempty"`
	DurationMs   int64     `json:"duration_ms,omitempty"`
}

// Client batches usage events to the control plane. Construct with New;
// a nil *Client is safe to call (no-op), so callers can hold one
// unconditionally.
type Client struct {
	cfg     Config
	http    *http.Client
	events  chan UsageEvent
	done    chan struct{}
	closeMu sync.Once
	wg      sync.WaitGroup

	mu      sync.Mutex
	dropped int64
}

// New returns nil when cfg.BaseURL is empty — the control plane is off and
// every method no-ops.
func New(cfg Config) *Client {
	if cfg.BaseURL == "" {
		return nil
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = 60 * time.Second
	}
	if cfg.MaxSpoolBytes <= 0 {
		cfg.MaxSpoolBytes = 8 << 20 // 8 MiB of spooled telemetry
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	c := &Client{
		cfg:    cfg,
		http:   hc,
		events: make(chan UsageEvent, 1024),
		done:   make(chan struct{}),
	}
	c.wg.Add(1)
	go c.loop()
	return c
}

// Record enqueues a usage event. NEVER blocks: when the buffer is full the
// event is dropped (counted) — customer traffic always wins over telemetry.
func (c *Client) Record(e UsageEvent) {
	if c == nil {
		return
	}
	select {
	case c.events <- e:
	default:
		c.mu.Lock()
		c.dropped++
		c.mu.Unlock()
	}
}

// Dropped reports events discarded because the buffer was full.
func (c *Client) Dropped() int64 {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.dropped
}

// Close flushes pending events (best-effort) and stops the loop. Safe to
// call more than once.
func (c *Client) Close() {
	if c == nil {
		return
	}
	c.closeMu.Do(func() { close(c.done) })
	c.wg.Wait()
}

func (c *Client) loop() {
	defer c.wg.Done()
	ticker := time.NewTicker(c.cfg.FlushInterval)
	defer ticker.Stop()

	var pending []UsageEvent
	for {
		select {
		case e := <-c.events:
			pending = append(pending, e)
			if len(pending) >= 256 {
				pending = c.flush(pending)
			}
		case <-ticker.C:
			pending = c.flush(pending)
		case <-c.done:
			// Final best-effort flush of channel + pending.
			for {
				select {
				case e := <-c.events:
					pending = append(pending, e)
					continue
				default:
				}
				break
			}
			c.flush(pending)
			return
		}
	}
}

// flush sends spooled + pending events. On failure everything goes to the
// spool (capped) and flush returns nil — the next tick retries from disk.
func (c *Client) flush(pending []UsageEvent) []UsageEvent {
	spooled := c.readSpool()
	all := append(spooled, pending...)
	if len(all) == 0 {
		return nil
	}
	if err := c.postUsage(all); err != nil {
		c.writeSpool(all)
		return nil
	}
	c.clearSpool()
	return nil
}

func (c *Client) postUsage(events []UsageEvent) error {
	body, err := json.Marshal(map[string]any{
		"batch_id": newBatchID(),
		"events":   events,
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, strings.TrimRight(c.cfg.BaseURL, "/")+"/v1/usage", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.cfg.DeploymentToken)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("control plane returned %d", resp.StatusCode)
	}
	return nil
}

// --- disk spool --------------------------------------------------------

func (c *Client) readSpool() []UsageEvent {
	if c.cfg.SpoolPath == "" {
		return nil
	}
	data, err := os.ReadFile(c.cfg.SpoolPath)
	if err != nil {
		return nil
	}
	var out []UsageEvent
	for line := range strings.SplitSeq(string(data), "\n") {
		if line == "" {
			continue
		}
		var e UsageEvent
		if json.Unmarshal([]byte(line), &e) == nil {
			out = append(out, e)
		}
	}
	return out
}

// writeSpool persists events as JSONL, dropping the OLDEST lines when the
// file would exceed MaxSpoolBytes — recent telemetry is worth more.
func (c *Client) writeSpool(events []UsageEvent) {
	if c.cfg.SpoolPath == "" {
		return
	}
	var buf bytes.Buffer
	for _, e := range events {
		line, err := json.Marshal(e)
		if err != nil {
			continue
		}
		buf.Write(line)
		buf.WriteByte('\n')
	}
	data := buf.Bytes()
	if int64(len(data)) > c.cfg.MaxSpoolBytes {
		cut := int64(len(data)) - c.cfg.MaxSpoolBytes
		if idx := bytes.IndexByte(data[cut:], '\n'); idx >= 0 {
			data = data[cut+int64(idx)+1:]
		}
	}
	_ = os.WriteFile(c.cfg.SpoolPath, data, 0o600)
}

func (c *Client) clearSpool() {
	if c.cfg.SpoolPath != "" {
		_ = os.Remove(c.cfg.SpoolPath)
	}
}

func newBatchID() string {
	return fmt.Sprintf("b-%d", time.Now().UnixNano())
}

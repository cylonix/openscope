// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package reflector

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// httpMailbox is the production Transport: a blind HTTP long-poll mailbox client
// (the kidfence-server pattern). It uses only net/http, so the daemon leg works
// through any corporate egress proxy that passes ordinary request/response — no
// websocket, no HTTP/2 full-duplex stream to be buffered or duration-capped. The
// daemon leg authenticates with its osk_deploy_* token, exactly like cpclient.
type httpMailbox struct {
	baseURL string
	token   string
	leg     string
	hc      *http.Client
}

// NewHTTPMailbox builds the daemon-leg relay transport. deployToken is the
// osk_deploy_* credential (from cpclient enrollment). The client has no global
// timeout: each call carries its own context deadline so long-poll fetches are
// not cut short.
func NewHTTPMailbox(relayURL, deployToken string) Transport {
	return &httpMailbox{
		baseURL: strings.TrimRight(relayURL, "/"),
		token:   deployToken,
		leg:     "daemon",
		hc:      &http.Client{},
	}
}

// newExternalMailbox builds the external-leg client. It authenticates only by
// possessing the rendezvous id (no token), so CreateSession/CloseSession are not
// used from this leg.
func newExternalMailbox(relayURL string) *httpMailbox {
	return &httpMailbox{baseURL: strings.TrimRight(relayURL, "/"), leg: "external", hc: &http.Client{}}
}

func (h *httpMailbox) CreateSession(ctx context.Context, req SessionRequest) (string, error) {
	body, _ := json.Marshal(map[string]any{
		"daemon_eph_pub": req.DaemonEphemeralPub,
		"ttl_seconds":    int(req.TTL / time.Second),
	})
	resp, err := h.do(ctx, http.MethodPost, "/v1/reflect/session", "", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return "", h.statusErr(resp)
	}
	var out struct {
		RendezvousID string `json:"rendezvous_id"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&out); err != nil {
		return "", fmt.Errorf("reflector: decode session response: %w", err)
	}
	if out.RendezvousID == "" {
		return "", fmt.Errorf("reflector: relay returned empty rendezvous id")
	}
	return out.RendezvousID, nil
}

func (h *httpMailbox) Fetch(ctx context.Context, rendezvousID string) (Frame, error) {
	q := "?rendezvous=" + rendezvousID + "&leg=" + h.leg
	for {
		if ctx.Err() != nil {
			return Frame{}, ctx.Err()
		}
		resp, err := h.do(ctx, http.MethodGet, "/v1/reflect/fetch"+q, "", nil)
		if err != nil {
			return Frame{}, err
		}
		switch {
		case resp.StatusCode == http.StatusNoContent:
			resp.Body.Close()
			continue // long-poll window elapsed with no frame; re-poll
		case resp.StatusCode == http.StatusGone:
			resp.Body.Close()
			return Frame{}, ErrSessionClosed
		case resp.StatusCode/100 != 2:
			err := h.statusErr(resp)
			resp.Body.Close()
			return Frame{}, err
		}
		var out struct {
			Frame []byte `json:"frame"`
		}
		dec := json.NewDecoder(io.LimitReader(resp.Body, 2<<20))
		decErr := dec.Decode(&out)
		resp.Body.Close()
		if decErr != nil {
			return Frame{}, fmt.Errorf("reflector: decode fetch response: %w", decErr)
		}
		return DecodeFrame(out.Frame)
	}
}

func (h *httpMailbox) Send(ctx context.Context, rendezvousID string, f Frame) error {
	body, _ := json.Marshal(map[string]any{
		"rendezvous": rendezvousID,
		"leg":        h.leg,
		"frame":      f.Encode(),
	})
	resp, err := h.do(ctx, http.MethodPost, "/v1/reflect/send", "", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return h.statusErr(resp)
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	return nil
}

func (h *httpMailbox) CloseSession(ctx context.Context, rendezvousID string) error {
	resp, err := h.do(ctx, http.MethodDelete, "/v1/reflect/session?rendezvous="+rendezvousID, "", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	return nil
}

func (h *httpMailbox) do(ctx context.Context, method, path, _ string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, h.baseURL+path, body)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if h.token != "" {
		req.Header.Set("Authorization", "Bearer "+h.token)
	}
	return h.hc.Do(req)
}

func (h *httpMailbox) statusErr(resp *http.Response) error {
	msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	return fmt.Errorf("reflector: relay returned %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
}

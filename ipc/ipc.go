// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package ipc

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/openscope/openscope/config"
)

var httpClient = http.DefaultClient

// clientFor returns the HTTP client for broker calls. OPENSCOPE_HTTP_CA
// points at a PEM bundle for private-CA TLS (self-managed broker certs).
func clientFor(paths config.Paths) (*http.Client, error) {
	if paths.ClientCAFile == "" {
		return httpClient, nil
	}
	pem, err := os.ReadFile(paths.ClientCAFile)
	if err != nil {
		return nil, fmt.Errorf("read CA bundle: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("no certificates found in %s", paths.ClientCAFile)
	}
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		},
	}, nil
}

type Request struct {
	App    string            `json:"app"`
	Action string            `json:"action"`
	Agent  string            `json:"agent"`
	Params map[string]string `json:"params,omitempty"`
	Mode   string            `json:"mode,omitempty"`
}

type Response struct {
	OK       bool   `json:"ok"`
	App      string `json:"app,omitempty"`
	Action   string `json:"action,omitempty"`
	Agent    string `json:"agent,omitempty"`
	Data     any    `json:"data,omitempty"`
	Error    string `json:"error,omitempty"`
	ExitCode int    `json:"exit_code"`
}

func Call(paths config.Paths, request Request) (Response, error) {
	if paths.HTTPURL != "" {
		return callHTTP(paths, request)
	}

	conn, err := net.Dial("unix", paths.SocketPath)
	if err != nil {
		return Response{}, fmt.Errorf("connect to daemon: %w", err)
	}
	defer conn.Close()

	if err := json.NewEncoder(conn).Encode(request); err != nil {
		return Response{}, fmt.Errorf("send request: %w", err)
	}

	var response Response
	if err := json.NewDecoder(conn).Decode(&response); err != nil {
		return Response{}, fmt.Errorf("read response: %w", err)
	}

	return response, nil
}

func callHTTP(paths config.Paths, request Request) (Response, error) {
	payload, err := json.Marshal(request)
	if err != nil {
		return Response{}, fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, strings.TrimRight(paths.HTTPURL, "/")+"/v1/actions", bytes.NewReader(payload))
	if err != nil {
		return Response{}, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	// Remote brokers require a Bearer agent token; the daemon derives the
	// agent identity from it (OPENSCOPE_TOKEN).
	if paths.ClientToken != "" {
		req.Header.Set("Authorization", "Bearer "+paths.ClientToken)
	}

	client, err := clientFor(paths)
	if err != nil {
		return Response{}, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return Response{}, fmt.Errorf("connect to daemon: %w", err)
	}
	defer resp.Body.Close()

	var response Response
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return Response{}, fmt.Errorf("read response: %w", err)
	}

	return response, nil
}

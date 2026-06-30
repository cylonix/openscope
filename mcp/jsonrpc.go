// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// Package mcp implements a minimal, dependency-free MCP server over stdio for
// openscope-mcp. The broker already hand-rolls its JSON IPC; this mirrors that
// approach to keep the root module's yaml.v3-only dependency policy intact (no
// MCP SDK, no JSON-RPC library). Only the tools-only surface is implemented:
// initialize, tools/list, tools/call, and the tools/list_changed notification.
package mcp

import (
	"encoding/json"
	"io"
	"sync"
)

// JSON-RPC 2.0 standard error codes.
const (
	codeMethodNotFound = -32601
	codeInvalidParams  = -32602
	codeInternalError  = -32603
)

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

type rpcNotification struct {
	JSONRPC string `json:"jsonrpc"`
	Method  string `json:"method"`
	Params  any    `json:"params,omitempty"`
}

// Conn is a newline-delimited JSON-RPC 2.0 connection over stdio. Writes are
// serialized so a background notification (tools/list_changed) cannot interleave
// with a request response.
type Conn struct {
	dec *json.Decoder
	mu  sync.Mutex
	w   io.Writer
}

// NewConn builds a Conn reading requests from r and writing responses to w.
func NewConn(r io.Reader, w io.Writer) *Conn {
	return &Conn{dec: json.NewDecoder(r), w: w}
}

func (c *Conn) read() (rpcRequest, error) {
	var req rpcRequest
	err := c.dec.Decode(&req)
	return req, err
}

func (c *Conn) writeMessage(v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, err := c.w.Write(append(data, '\n')); err != nil {
		return err
	}
	return nil
}

func (c *Conn) reply(id json.RawMessage, result any) error {
	raw, err := json.Marshal(result)
	if err != nil {
		return c.replyError(id, codeInternalError, "marshal result: "+err.Error())
	}
	return c.writeMessage(rpcResponse{JSONRPC: "2.0", ID: id, Result: raw})
}

func (c *Conn) replyError(id json.RawMessage, code int, msg string) error {
	return c.writeMessage(rpcResponse{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: code, Message: msg}})
}

// Notify sends a server-initiated notification (no id, no response expected).
func (c *Conn) Notify(method string, params any) error {
	return c.writeMessage(rpcNotification{JSONRPC: "2.0", Method: method, Params: params})
}

// Copyright (c) EZBLOCK Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package mcp

import (
	"encoding/json"
	"errors"
	"io"
)

// protocolVersion is advertised when the client does not request one. When the
// client sends a version we echo it (best-effort negotiation for a tools-only
// server).
const protocolVersion = "2025-06-18"

// Tool is an MCP tool advertised in tools/list.
type Tool struct {
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	InputSchema map[string]any `json:"inputSchema"`
}

// Content is one item in a tool result.
type Content struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`
}

// ToolResult is the result of a tools/call. IsError carries an execution or
// policy failure back to the model as a tool error (distinct from a JSON-RPC
// protocol error).
type ToolResult struct {
	Content []Content `json:"content"`
	IsError bool      `json:"isError,omitempty"`
}

// TextResult is a convenience for a single-text-block result.
func TextResult(text string, isError bool) ToolResult {
	return ToolResult{Content: []Content{{Type: "text", Text: text}}, IsError: isError}
}

// Provider supplies the (dynamic) tool surface and executes calls. The
// capabilities-backed implementation lives in the openscope-mcp binary.
type Provider interface {
	Tools() []Tool
	Call(name string, args map[string]json.RawMessage) ToolResult
}

// Server speaks MCP over a Conn, delegating tool listing and calls to a Provider.
type Server struct {
	Conn         *Conn
	Provider     Provider
	Name         string
	Version      string
	Instructions string
}

// Run reads and dispatches messages until EOF.
func (s *Server) Run() error {
	for {
		req, err := s.Conn.read()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		s.dispatch(req)
	}
}

func (s *Server) dispatch(req rpcRequest) {
	isNotification := len(req.ID) == 0
	switch req.Method {
	case "initialize":
		s.handleInitialize(req)
	case "notifications/initialized":
		// Acknowledgement notification: no response.
	case "ping":
		s.Conn.reply(req.ID, struct{}{})
	case "tools/list":
		s.Conn.reply(req.ID, map[string]any{"tools": s.Provider.Tools()})
	case "tools/call":
		s.handleToolsCall(req)
	default:
		if !isNotification {
			s.Conn.replyError(req.ID, codeMethodNotFound, "method not found: "+req.Method)
		}
	}
}

func (s *Server) handleInitialize(req rpcRequest) {
	var params struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	_ = json.Unmarshal(req.Params, &params)
	version := params.ProtocolVersion
	if version == "" {
		version = protocolVersion
	}
	s.Conn.reply(req.ID, map[string]any{
		"protocolVersion": version,
		"capabilities":    map[string]any{"tools": map[string]any{"listChanged": true}},
		"serverInfo":      map[string]any{"name": s.Name, "version": s.Version},
		"instructions":    s.Instructions,
	})
}

func (s *Server) handleToolsCall(req rpcRequest) {
	var params struct {
		Name      string                     `json:"name"`
		Arguments map[string]json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(req.Params, &params); err != nil {
		s.Conn.replyError(req.ID, codeInvalidParams, "invalid params: "+err.Error())
		return
	}
	if params.Name == "" {
		s.Conn.replyError(req.ID, codeInvalidParams, "missing tool name")
		return
	}
	s.Conn.reply(req.ID, s.Provider.Call(params.Name, params.Arguments))
}

// NotifyToolsChanged tells the client the tool list changed; it should re-fetch
// via tools/list. Safe to call from a background goroutine.
func (s *Server) NotifyToolsChanged() error {
	return s.Conn.Notify("notifications/tools/list_changed", nil)
}

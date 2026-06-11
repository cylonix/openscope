// Package provider defines the cloud-agnostic LLM backend interface the
// router forwards approved requests through. AWS Bedrock is the first
// implementation (internal/bedrock); Anthropic, OpenAI, and Azure direct
// implementations plug in behind the same interface.
package provider

import "context"

// Message is one turn of a conversation.
type Message struct {
	Role    string // "user" | "assistant" | "system"
	Content string
}

// Request is the shape the router builds from an approved /v1/chat body.
// It maps 1:1 to Bedrock's Converse API but carries nothing AWS-specific.
type Request struct {
	ModelID   string
	Messages  []Message
	MaxTokens int
}

// Response is what the handler builds the audit/receipt rows from.
type Response struct {
	ModelID      string
	Content      string
	InputTokens  int
	OutputTokens int
	FinishReason string
	LatencyMs    int64
}

// Invoker is one model-serving backend. Name and Region are stamped onto
// receipts and surfaced in the dashboards so an auditor sees exactly where
// each call was served ("AWS Bedrock · us-west-2").
type Invoker interface {
	Invoke(ctx context.Context, req Request) (*Response, error)
	Name() string
	Region() string // "" when the backend has no region concept
}

package provider

import (
	"context"
	"fmt"
	"sync"
)

// Fake is an in-process Invoker for tests, offline demos, and deployment
// smoke tests (OPENSCOPE_PROVIDER=mock). It never leaves the process: it
// echoes a canned or derived response and records every request it saw.
type Fake struct {
	// Reply, when set, computes the response. Defaults to a short echo
	// with token counts derived from the input length.
	Reply func(req Request) (*Response, error)

	mu       sync.Mutex
	requests []Request
}

func (f *Fake) Name() string   { return "Mock Provider" }
func (f *Fake) Region() string { return "local" }

func (f *Fake) Invoke(_ context.Context, req Request) (*Response, error) {
	f.mu.Lock()
	f.requests = append(f.requests, req)
	f.mu.Unlock()

	if f.Reply != nil {
		return f.Reply(req)
	}
	inputChars := 0
	for _, m := range req.Messages {
		inputChars += len(m.Content)
	}
	return &Response{
		ModelID:      req.ModelID,
		Content:      fmt.Sprintf("[mock] processed %d message(s) for model %s", len(req.Messages), req.ModelID),
		InputTokens:  inputChars/4 + 1, // ~4 chars/token heuristic
		OutputTokens: 12,
		FinishReason: "end_turn",
	}, nil
}

// Requests returns a copy of every request Invoke has seen.
func (f *Fake) Requests() []Request {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]Request, len(f.requests))
	copy(out, f.requests)
	return out
}

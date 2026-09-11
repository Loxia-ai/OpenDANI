// Package engine is the inference engine abstraction (Architecture §6.7, DL-R11-01: engines are
// subprocesses by physical necessity). The DEMO ships two implementations behind one interface:
//
//   - LlamaEngine  — REAL CPU inference: supervises llama.cpp's `llama-server` (OpenAI-compatible)
//                    as a child process and proxies /v1/chat/completions to it. (M2/M6)
//   - StubEngine   — deterministic canned completion with realistic token-paced latency, for the
//                    request-path/routing/benchmark plumbing without a model. (the ONE mocked piece)
//
// When the T4 GPU quota lands, a vLLM implementation slots in here with no data-plane changes.
package engine

import (
	"context"
	"time"
)

// Message is one OpenAI chat message.
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// Request is an OpenAI-shaped chat completion request.
type Request struct {
	Model     string    `json:"model"`
	Messages  []Message `json:"messages"`
	MaxTokens int       `json:"max_tokens,omitempty"`
	Stream    bool      `json:"stream,omitempty"`
}

// Result is the completion plus the telemetry the benchmark + audit care about.
type Result struct {
	Text             string
	Engine           string
	Model            string
	PromptTokens     int
	CompletionTokens int
	FirstTokenMs     int64
	TotalMs          int64
}

// Engine is a model-serving backend the worker supervises.
type Engine interface {
	Name() string                                            // "llama.cpp" | "stub" | "vllm"
	Start(ctx context.Context) error                         // spawn/warm; returns when ready to serve
	Chat(ctx context.Context, req Request) (*Result, error)  // one completion
	Close() error                                            // stop the subprocess
}

// prompt collapses chat messages to the last user turn (for the stub + token accounting).
func lastUser(req Request) string {
	for i := len(req.Messages) - 1; i >= 0; i-- {
		if req.Messages[i].Role == "user" {
			return req.Messages[i].Content
		}
	}
	if len(req.Messages) > 0 {
		return req.Messages[len(req.Messages)-1].Content
	}
	return ""
}

// approxTokens is the ~4-chars-per-token heuristic the sim used (engine.js).
func approxTokens(s string) int {
	n := len(s) / 4
	if n < 1 {
		return 1
	}
	return n
}

func msSince(t time.Time) int64 { return time.Since(t).Milliseconds() }

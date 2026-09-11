package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// OpenAIProxy is an engine that forwards to an EXISTING OpenAI-compatible server (Ollama, vLLM,
// LM Studio, llama-server, …) instead of supervising its own subprocess. This is how a node with an
// accelerator the agent didn't launch — e.g. an NVIDIA GPU via Ollama, or an AMX CPU via OpenVINO's
// server — joins DANI as a worker: point the engine at the local endpoint and DANI routes to it like
// any other worker. (M6: OpenAI /v1/chat/completions only.)
type OpenAIProxy struct {
	base    string // e.g. http://127.0.0.1:11434/v1
	model   string // upstream model name (may differ from the DANI model-id, e.g. "qwen2.5:7b")
	apiKey  string
	client  *http.Client
	startTimeout time.Duration
	pollEvery    time.Duration
}

// OpenAIConfig configures the proxy engine.
type OpenAIConfig struct {
	BaseURL string // OpenAI-compatible base, default http://127.0.0.1:11434/v1 (Ollama)
	Model   string // upstream model name to request
	APIKey  string // optional bearer token
}

func NewOpenAIProxy(c OpenAIConfig) *OpenAIProxy {
	if c.BaseURL == "" {
		c.BaseURL = "http://127.0.0.1:11434/v1"
	}
	return &OpenAIProxy{
		base: strings.TrimRight(c.BaseURL, "/"), model: c.Model, apiKey: c.APIKey,
		client: &http.Client{Timeout: 5 * time.Minute},
		startTimeout: 2 * time.Minute, pollEvery: 2 * time.Second,
	}
}

func (o *OpenAIProxy) Name() string { return "openai-proxy" }

// Start waits until the upstream endpoint is reachable (its /models list responds).
func (o *OpenAIProxy) Start(ctx context.Context) error {
	deadline := time.Now().Add(o.startTimeout)
	for {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, o.base+"/models", nil)
		o.auth(req)
		resp, err := o.client.Do(req)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode < 500 {
				return nil
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("openai-proxy: upstream %s not reachable", o.base)
		}
		select {
		case <-time.After(o.pollEvery):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (o *OpenAIProxy) Close() error { return nil }

func (o *OpenAIProxy) auth(r *http.Request) {
	if o.apiKey != "" {
		r.Header.Set("Authorization", "Bearer "+o.apiKey)
	}
}

func (o *OpenAIProxy) Chat(ctx context.Context, req Request) (*Result, error) {
	start := time.Now()
	if req.MaxTokens <= 0 {
		req.MaxTokens = 256
	}
	// send the UPSTREAM model name; the DANI model-id the client used is mapped by the worker.
	payload := map[string]any{"model": o.model, "messages": req.Messages, "max_tokens": req.MaxTokens, "stream": false}
	body, _ := json.Marshal(payload)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, o.base+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	o.auth(httpReq)
	resp, err := o.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("openai-proxy call: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("openai-proxy upstream status %d", resp.StatusCode)
	}
	var oa openAIResp // reuse the struct from llama.go (same package)
	if err := json.NewDecoder(resp.Body).Decode(&oa); err != nil {
		return nil, fmt.Errorf("decode upstream response: %w", err)
	}
	text := ""
	if len(oa.Choices) > 0 {
		text = oa.Choices[0].Message.Content
	}
	model := o.model
	return &Result{
		Text: text, Engine: "openai-proxy", Model: model,
		PromptTokens: oa.Usage.PromptTokens, CompletionTokens: oa.Usage.CompletionTokens,
		TotalMs: time.Since(start).Milliseconds(),
	}, nil
}

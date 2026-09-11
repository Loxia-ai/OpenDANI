package engine

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestOpenAIProxy: the proxy forwards to an upstream OpenAI-compatible server, sends the upstream
// model name, and maps the response back into a Result.
func TestOpenAIProxy(t *testing.T) {
	var gotModel string
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/models" {
			rw.WriteHeader(http.StatusOK)
			_, _ = rw.Write([]byte(`{"object":"list","data":[]}`))
			return
		}
		var req map[string]any
		_ = json.NewDecoder(r.Body).Decode(&req)
		gotModel, _ = req["model"].(string)
		rw.Header().Set("Content-Type", "application/json")
		_, _ = rw.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"hello from gpu"}}],"usage":{"prompt_tokens":3,"completion_tokens":4}}`))
	}))
	defer srv.Close()

	eng := NewOpenAIProxy(OpenAIConfig{BaseURL: srv.URL + "/v1", Model: "qwen2.5:7b"})
	if err := eng.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	res, err := eng.Chat(context.Background(), Request{
		Model: "qwen2.5-7b", Messages: []Message{{Role: "user", Content: "hi"}}, MaxTokens: 16,
	})
	if err != nil {
		t.Fatalf("chat: %v", err)
	}
	if res.Text != "hello from gpu" {
		t.Fatalf("text = %q", res.Text)
	}
	if gotModel != "qwen2.5:7b" {
		t.Fatalf("upstream model = %q, want qwen2.5:7b (the engine-model, not the DANI id)", gotModel)
	}
	if res.CompletionTokens != 4 || res.Engine != "openai-proxy" {
		t.Fatalf("unexpected result %+v", res)
	}
}

func TestOpenAIProxyLifecycle(t *testing.T) {
	// defaults branch
	def := NewOpenAIProxy(OpenAIConfig{})
	if def.base != "http://127.0.0.1:11434/v1" || def.Name() != "openai-proxy" {
		t.Fatalf("defaults wrong: %s", def.base)
	}
	if err := def.Close(); err != nil {
		t.Fatal(err)
	}
	// Start happy path + bearer auth forwarded
	var gotAuth string
	ts := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		rw.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()
	p := NewOpenAIProxy(OpenAIConfig{BaseURL: ts.URL, Model: "m", APIKey: "sekrit"})
	if err := p.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer sekrit" {
		t.Fatalf("auth header missing: %q", gotAuth)
	}
	// Start timeout on a permanently-5xx upstream
	bad := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) { rw.WriteHeader(500) }))
	defer bad.Close()
	p2 := NewOpenAIProxy(OpenAIConfig{BaseURL: bad.URL})
	p2.startTimeout = 50 * time.Millisecond
	p2.pollEvery = 10 * time.Millisecond
	if err := p2.Start(context.Background()); err == nil {
		t.Fatal("permanently-5xx upstream must time out")
	}
	// ctx cancel while polling
	p3 := NewOpenAIProxy(OpenAIConfig{BaseURL: bad.URL})
	p3.pollEvery = 10 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(30 * time.Millisecond); cancel() }()
	if err := p3.Start(ctx); err != context.Canceled {
		t.Fatalf("cancel: %v", err)
	}
}

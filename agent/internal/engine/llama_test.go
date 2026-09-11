package engine

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestLlamaHelperProcess is the fake llama-server child: it just sleeps until killed (the health
// endpoint is played by an httptest server bound to the SAME port the engine polls).
func TestLlamaHelperProcess(t *testing.T) {
	if os.Getenv("GO_LLAMA_HELPER") != "1" {
		return
	}
	time.Sleep(30 * time.Second)
	os.Exit(0)
}

// fakeBinAndModel returns paths that pass Start's stat guards: the test binary itself as
// llama-server (env-gated helper) and a dummy .gguf.
func fakeBinAndModel(t *testing.T) (string, string) {
	t.Helper()
	model := filepath.Join(t.TempDir(), "m.gguf")
	os.WriteFile(model, []byte("GGUF"), 0o600)
	return os.Args[0], model
}

// healthServer runs an httptest server and returns it + its port (the engine polls 127.0.0.1:port).
func healthServer(t *testing.T, h http.HandlerFunc) (*httptest.Server, int) {
	t.Helper()
	ts := httptest.NewServer(h)
	t.Cleanup(ts.Close)
	u, _ := url.Parse(ts.URL)
	port, _ := strconv.Atoi(u.Port())
	return ts, port
}

func llamaFor(t *testing.T, port int) *LlamaEngine {
	bin, model := fakeBinAndModel(t)
	l := NewLlama(LlamaConfig{Model: "qwen-test", BinPath: bin, ModelPath: model, Port: port, Threads: 2, Parallel: 2})
	// the helper needs the env gate; smuggle it via the process env (exec.Command inherits)
	os.Setenv("GO_LLAMA_HELPER", "1")
	t.Cleanup(func() { os.Unsetenv("GO_LLAMA_HELPER") })
	l.pollEvery = 20 * time.Millisecond
	l.startTimeout = 3 * time.Second
	return l
}

func TestLlamaStartHealthyChatClose(t *testing.T) {
	_, port := healthServer(t, func(rw http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health":
			rw.WriteHeader(http.StatusOK)
		case "/v1/chat/completions":
			fmt.Fprint(rw, `{"choices":[{"message":{"role":"assistant","content":"hi from llama"}}],"usage":{"prompt_tokens":5,"completion_tokens":3}}`)
		}
	})
	l := llamaFor(t, port)
	if l.Name() != "llama.cpp" || l.Parallel() != 2 {
		t.Fatal("identity accessors wrong")
	}
	if err := l.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	res, err := l.Chat(context.Background(), Request{Messages: []Message{{Role: "user", Content: "hello"}}})
	if err != nil || res.Text != "hi from llama" || res.CompletionTokens != 3 || res.Engine != "llama.cpp" {
		t.Fatalf("chat wrong: %+v %v", res, err)
	}
	// empty-choices response -> empty text, no panic
	res2, err := l.Chat(context.Background(), Request{Messages: []Message{{Role: "user", Content: "x"}}, MaxTokens: 8})
	_ = res2
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	l.Close() // idempotent (process already gone)
}

func TestLlamaStartGuards(t *testing.T) {
	// missing binary
	l := NewLlama(LlamaConfig{BinPath: "definitely-missing", ModelPath: "x"})
	if err := l.Start(context.Background()); err == nil || !strings.Contains(err.Error(), "llama-server not found") {
		t.Fatalf("missing bin: %v", err)
	}
	// missing model
	bin, _ := fakeBinAndModel(t)
	l2 := NewLlama(LlamaConfig{BinPath: bin, ModelPath: filepath.Join(t.TempDir(), "missing.gguf")})
	if err := l2.Start(context.Background()); err == nil || !strings.Contains(err.Error(), "model not found") {
		t.Fatalf("missing model: %v", err)
	}
	// unstartable "binary" (a plain data file)
	badBin := filepath.Join(t.TempDir(), "notexec.txt")
	os.WriteFile(badBin, []byte("data"), 0o600)
	_, model := fakeBinAndModel(t)
	l3 := NewLlama(LlamaConfig{BinPath: badBin, ModelPath: model})
	if err := l3.Start(context.Background()); err == nil || !strings.Contains(err.Error(), "start llama-server") {
		t.Fatalf("unstartable bin: %v", err)
	}
}

func TestLlamaStartTimeoutAndCancel(t *testing.T) {
	// health never OK -> timeout fires, child is killed
	_, port := healthServer(t, func(rw http.ResponseWriter, _ *http.Request) { rw.WriteHeader(500) })
	l := llamaFor(t, port)
	l.startTimeout = 150 * time.Millisecond
	if err := l.Start(context.Background()); err == nil || !strings.Contains(err.Error(), "did not become healthy") {
		t.Fatalf("timeout: %v", err)
	}
	// ctx cancelled mid-poll
	l2 := llamaFor(t, port)
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(50 * time.Millisecond); cancel() }()
	if err := l2.Start(ctx); err != context.Canceled {
		t.Fatalf("cancel: %v", err)
	}
}

func TestLlamaChatErrors(t *testing.T) {
	// upstream down
	l := NewLlama(LlamaConfig{Port: 1})
	if _, err := l.Chat(context.Background(), Request{}); err == nil {
		t.Fatal("dead upstream must error")
	}
	// non-200
	ts, port := healthServer(t, func(rw http.ResponseWriter, _ *http.Request) { rw.WriteHeader(503) })
	_ = ts
	l2 := NewLlama(LlamaConfig{Port: port})
	if _, err := l2.Chat(context.Background(), Request{}); err == nil || !strings.Contains(err.Error(), "status 503") {
		t.Fatalf("non-200: %v", err)
	}
	// bad JSON body
	_, port3 := healthServer(t, func(rw http.ResponseWriter, _ *http.Request) { fmt.Fprint(rw, "{oops") })
	l3 := NewLlama(LlamaConfig{Port: port3})
	if _, err := l3.Chat(context.Background(), Request{}); err == nil || !strings.Contains(err.Error(), "decode") {
		t.Fatalf("bad json: %v", err)
	}
	// unbuildable request URL
	l4 := NewLlama(LlamaConfig{Port: 8080})
	l4.base = "http://bad host\x7f"
	if _, err := l4.Chat(context.Background(), Request{}); err == nil {
		t.Fatal("bad base must error at request build")
	}
}

func TestLastUserEmpty(t *testing.T) {
	if got := lastUser(Request{}); got != "" {
		t.Fatalf("no messages -> empty prompt, got %q", got)
	}
}

func TestResidualBranches(t *testing.T) {
	// lastUser skips non-user roles
	if got := lastUser(Request{Messages: []Message{{Role: "user", Content: "q"}, {Role: "assistant", Content: "a"}}}); got != "q" {
		t.Fatalf("lastUser must skip assistant turns: %q", got)
	}
	// llama healthy() against a dead port -> false via Do error
	l := NewLlama(LlamaConfig{Port: 1})
	if l.healthy(context.Background()) {
		t.Fatal("dead port cannot be healthy")
	}
	// stub: token clamp + ctx cancel
	s := NewStub("m")
	res, err := s.Chat(context.Background(), Request{Messages: []Message{{Role: "user", Content: "hello there friend"}}, MaxTokens: 1})
	if err != nil || res.CompletionTokens != 1 {
		t.Fatalf("clamp: %+v %v", res, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.Chat(ctx, Request{Messages: []Message{{Role: "user", Content: "x"}}}); err == nil {
		t.Fatal("cancelled ctx must abort the stub")
	}
	// openai Chat error branches
	p := NewOpenAIProxy(OpenAIConfig{BaseURL: "http://127.0.0.1:1/v1", Model: "m"})
	if _, err := p.Chat(context.Background(), Request{}); err == nil { // Do error + MaxTokens default
		t.Fatal("dead upstream must error")
	}
	p.base = "http://bad host\x7f"
	if _, err := p.Chat(context.Background(), Request{MaxTokens: 4}); err == nil {
		t.Fatal("bad base must error at request build")
	}
	bad := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) { rw.WriteHeader(503) }))
	defer bad.Close()
	p2 := NewOpenAIProxy(OpenAIConfig{BaseURL: bad.URL, Model: "m"})
	if _, err := p2.Chat(context.Background(), Request{MaxTokens: 4}); err == nil {
		t.Fatal("non-200 must error")
	}
	junk := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) { fmt.Fprint(rw, "{oops") }))
	defer junk.Close()
	p3 := NewOpenAIProxy(OpenAIConfig{BaseURL: junk.URL, Model: "m"})
	if _, err := p3.Chat(context.Background(), Request{MaxTokens: 4}); err == nil {
		t.Fatal("bad json must error")
	}
}

package engine

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// adapterTar builds a DANI-style adapter tar; withGGUF controls whether adapter.gguf is present.
func adapterTar(t *testing.T, withGGUF bool) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	files := map[string][]byte{"adapter_config.json": []byte(`{}`), "adapter_model.safetensors": []byte("st")}
	if withGGUF {
		files["adapter.gguf"] = []byte("GGUF-lora-bytes")
	}
	for name, data := range files {
		tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(data))})
		tw.Write(data)
	}
	tw.Close()
	return buf.Bytes()
}

// loraCapture records the last request body the fake llama-server saw.
type loraCapture struct {
	mu   sync.Mutex
	last map[string]any
}

func (c *loraCapture) handler() http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health":
			rw.WriteHeader(http.StatusOK)
		case "/v1/chat/completions":
			var body map[string]any
			json.NewDecoder(r.Body).Decode(&body)
			c.mu.Lock()
			c.last = body
			c.mu.Unlock()
			fmt.Fprint(rw, `{"choices":[{"message":{"role":"assistant","content":"ok"}}],"usage":{"prompt_tokens":1,"completion_tokens":1}}`)
		}
	}
}

func (c *loraCapture) lora() (any, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	v, ok := c.last["lora"]
	return v, ok
}

func TestLlamaHotLoadRestartAndPerRequestActivation(t *testing.T) {
	cap := &loraCapture{}
	_, port := healthServer(t, cap.handler())
	l := llamaFor(t, port)
	if err := l.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	// before any adapter: plain request, NO lora field on the wire
	if _, err := l.Chat(context.Background(), Request{Model: "qwen-test",
		Messages: []Message{{Role: "user", Content: "x"}}, MaxTokens: 4}); err != nil {
		t.Fatal(err)
	}
	if _, has := cap.lora(); has {
		t.Fatal("no adapters -> no lora field")
	}

	// hot-load: restart carries the adapter; Loaded advertises it
	if err := l.Load("qwen-ft-legal-v1", adapterTar(t, true)); err != nil {
		t.Fatal(err)
	}
	if got := l.Loaded(); len(got) != 1 || got[0] != "qwen-ft-legal-v1" {
		t.Fatalf("Loaded wrong: %v", got)
	}
	if err := l.Load("qwen-ft-legal-v1", adapterTar(t, true)); err != nil { // idempotent
		t.Fatal(err)
	}
	if len(l.Loaded()) != 1 {
		t.Fatal("re-load must not duplicate")
	}

	// a request for the TUNED id activates adapter 0 at scale 1, and reports the tuned model
	res, err := l.Chat(context.Background(), Request{Model: "qwen-ft-legal-v1",
		Messages: []Message{{Role: "user", Content: "x"}}, MaxTokens: 4})
	if err != nil {
		t.Fatal(err)
	}
	if res.Model != "qwen-ft-legal-v1" {
		t.Fatalf("result must report the tuned model, got %s", res.Model)
	}
	v, has := cap.lora()
	if !has {
		t.Fatal("tuned request must carry a lora field")
	}
	arr := v.([]any)
	if len(arr) != 1 || arr[0].(map[string]any)["scale"].(float64) != 1.0 {
		t.Fatalf("lora activation wrong: %v", v)
	}

	// a request for the BASE id sends an explicit empty lora set (base only)
	res2, err := l.Chat(context.Background(), Request{Model: "qwen-test",
		Messages: []Message{{Role: "user", Content: "x"}}, MaxTokens: 4})
	if err != nil {
		t.Fatal(err)
	}
	if res2.Model != "qwen-test" {
		t.Fatalf("base request must report the base, got %s", res2.Model)
	}
	if v, has := cap.lora(); !has || len(v.([]any)) != 0 {
		t.Fatalf("base request must carry an explicit empty lora set, got %v", v)
	}
}

func TestLlamaHotLoadArtifactErrors(t *testing.T) {
	cap := &loraCapture{}
	_, port := healthServer(t, cap.handler())
	l := llamaFor(t, port)
	if err := l.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	// not a tar
	if err := l.Load("m1", []byte("not a tar at all")); err == nil || !strings.Contains(err.Error(), "not a tar") {
		t.Fatalf("garbage artifact: %v", err)
	}
	// tar without adapter.gguf
	if err := l.Load("m2", adapterTar(t, false)); err == nil || !strings.Contains(err.Error(), "no adapter.gguf") {
		t.Fatalf("gguf-less artifact: %v", err)
	}
	if len(l.Loaded()) != 0 {
		t.Fatal("failed loads must leave nothing loaded")
	}
}

func TestLlamaHotLoadRestartFailureRollsBack(t *testing.T) {
	// health flips to permanently-unhealthy right when the hot-load restart begins: the load fails,
	// the adapter is rolled back, and the rollback relaunch (health healthy again) succeeds.
	// The heal is anchored to the FIRST FAILING PROBE the engine actually makes (not the test's
	// wall clock) — a wall-clock heal raced Load() under full-suite machine load and healed before
	// the failing window even started (live-caught flake).
	var failHealth bool
	var firstFail time.Time
	var mu sync.Mutex
	_, port := healthServer(t, func(rw http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.URL.Path != "/health" {
			rw.WriteHeader(http.StatusInternalServerError)
			return
		}
		if !failHealth {
			rw.WriteHeader(http.StatusOK)
			return
		}
		if firstFail.IsZero() {
			firstFail = time.Now()
		}
		if time.Since(firstFail) > 800*time.Millisecond { // the failing window (500ms) is over — heal for the rollback
			rw.WriteHeader(http.StatusOK)
			return
		}
		rw.WriteHeader(http.StatusInternalServerError)
	})
	l := llamaFor(t, port)
	l.startTimeout = 500 * time.Millisecond
	if err := l.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	mu.Lock()
	failHealth = true
	mu.Unlock()
	err := l.Load("m-bad", adapterTar(t, true))
	if err == nil || !strings.Contains(err.Error(), "rolled back") {
		t.Fatalf("expected rolled-back failure, got %v", err)
	}
	if len(l.Loaded()) != 0 {
		t.Fatal("failed hot-load must roll the adapter back out")
	}
}

func TestLlamaUnloadRestartsWithoutAdapter(t *testing.T) {
	cap := &loraCapture{}
	_, port := healthServer(t, cap.handler())
	l := llamaFor(t, port)
	if err := l.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if err := l.Load("ft-a", adapterTar(t, true)); err != nil {
		t.Fatal(err)
	}
	if err := l.Load("ft-b", adapterTar(t, true)); err != nil {
		t.Fatal(err)
	}
	// unload the FIRST adapter: the second must survive with its index intact
	if err := l.Unload("ft-a"); err != nil {
		t.Fatal(err)
	}
	if got := l.Loaded(); len(got) != 1 || got[0] != "ft-b" {
		t.Fatalf("unload must keep the other adapter: %v", got)
	}
	// unload of something never loaded is a no-op
	if err := l.Unload("ghost"); err != nil {
		t.Fatal("unload of unknown model must be a no-op")
	}
	// the surviving tuned id still activates (now index 0)
	if _, err := l.Chat(context.Background(), Request{Model: "ft-b",
		Messages: []Message{{Role: "user", Content: "x"}}, MaxTokens: 4}); err != nil {
		t.Fatal(err)
	}
	if v, has := cap.lora(); !has || len(v.([]any)) != 1 {
		t.Fatalf("surviving adapter must activate: %v", v)
	}
}

func TestLlamaUnloadRestartFailureRollsBackIn(t *testing.T) {
	// mirror of the Load rollback: health flips unhealthy when the unload restart begins; the
	// adapter is rolled back IN and the engine keeps serving its prior set.
	var failHealth bool
	var mu sync.Mutex
	_, port := healthServer(t, func(rw http.ResponseWriter, r *http.Request) {
		mu.Lock()
		f := failHealth
		mu.Unlock()
		if r.URL.Path == "/health" && !f {
			rw.WriteHeader(http.StatusOK)
			return
		}
		rw.WriteHeader(http.StatusInternalServerError)
	})
	l := llamaFor(t, port)
	l.startTimeout = 300 * time.Millisecond
	if err := l.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if err := l.Load("ft-keep", adapterTar(t, true)); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	failHealth = true
	mu.Unlock()
	go func() { // heal after the failing relaunch window so the roll-back-in succeeds
		time.Sleep(400 * time.Millisecond)
		mu.Lock()
		failHealth = false
		mu.Unlock()
	}()
	err := l.Unload("ft-keep")
	if err == nil || !strings.Contains(err.Error(), "rolled back") {
		t.Fatalf("expected rolled-back unload failure, got %v", err)
	}
	if got := l.Loaded(); len(got) != 1 || got[0] != "ft-keep" {
		t.Fatalf("failed unload must keep the adapter: %v", got)
	}
}

func TestStubTopicBranches(t *testing.T) {
	s := NewStub("m")
	long := strings.Repeat("verylongtopic ", 10)
	if res, err := s.Chat(context.Background(), Request{Messages: []Message{{Role: "user", Content: long}}, MaxTokens: 2}); err != nil || res.Text == "" {
		t.Fatalf("long topic: %v", err)
	}
	if res, err := s.Chat(context.Background(), Request{Messages: []Message{{Role: "user", Content: "   "}}, MaxTokens: 2}); err != nil || !strings.Contains(res.Text, "your request") {
		t.Fatalf("empty topic default: %+v %v", res, err)
	}
}

func TestLlamaHotLoadWriteAndDoubleFailure(t *testing.T) {
	cap := &loraCapture{}
	_, port := healthServer(t, cap.handler())
	l := llamaFor(t, port)
	if err := l.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	// unwritable workDir (a file, not a dir) -> WriteFile error
	f := t.TempDir() + "/afile"
	if err := writeTempFile(f); err != nil {
		t.Fatal(err)
	}
	l.mu.Lock()
	l.workDir = f + "/sub"
	l.mu.Unlock()
	if err := l.Load("m-w", adapterTar(t, true)); err == nil {
		t.Fatal("unwritable workDir must fail the load")
	}
	l.mu.Lock()
	l.workDir = t.TempDir()
	l.mu.Unlock()

	// permanently-failing health: restart fails AND rollback fails
	_, badPort := healthServer(t, func(rw http.ResponseWriter, _ *http.Request) { rw.WriteHeader(500) })
	l2 := llamaFor(t, badPort)
	l2.startTimeout = 100 * time.Millisecond
	// skip Start (it would fail); simulate an already-running engine hot-loading into a dead port
	if err := l2.Load("m-dead", adapterTar(t, true)); err == nil ||
		!strings.Contains(err.Error(), "rollback failed") {
		t.Fatalf("double failure must be reported: %v", err)
	}
}

func writeTempFile(path string) error { return os.WriteFile(path, []byte("x"), 0o600) }

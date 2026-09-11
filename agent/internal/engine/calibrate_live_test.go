package engine

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"
)

// the REAL measureCandidate + calibChat against the fake llama-server (helper child + httptest
// health/chat on the engine port) — the same harness llama_test uses. Covers the success path the
// seam-swapped unit tests bypass.
func TestMeasureCandidateAgainstFakeServer(t *testing.T) {
	_, port := healthServer(t, func(rw http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health":
			rw.WriteHeader(http.StatusOK)
		case "/v1/chat/completions":
			time.Sleep(25 * time.Millisecond) // instant replies trip the degenerate-measurement guard
			fmt.Fprint(rw, `{"choices":[{"message":{"role":"assistant","content":"func Reverse(s string) string { return s }"}}],"usage":{"prompt_tokens":9,"completion_tokens":12}}`)
		}
	})
	bin, model := fakeBinAndModel(t)
	os.Setenv("GO_LLAMA_HELPER", "1")
	t.Cleanup(func() { os.Unsetenv("GO_LLAMA_HELPER") })
	tokS, err := measureCandidate(context.Background(), LlamaConfig{
		Model: "m", BinPath: bin, ModelPath: model, Port: port, GPULayers: 999,
	})
	if err != nil || tokS <= 0 {
		t.Fatalf("measure against fake server failed: %v (%.2f tok/s)", err, tokS)
	}
}

// LIVE-HARDWARE probe (opt-in, not CI): run the REAL benchmark-then-decide on this machine's llama
// build + model. Gated on env so `go test ./...` stays hermetic:
//
//	DANI_CALIB_BIN=<llama-server[.exe]> DANI_CALIB_MODEL=<model.gguf> DANI_CALIB_BACKEND=cuda \
//	  go test ./internal/engine/ -run TestCalibrateLiveHardware -v -timeout 20m
func TestCalibrateLiveHardware(t *testing.T) {
	bin, model := os.Getenv("DANI_CALIB_BIN"), os.Getenv("DANI_CALIB_MODEL")
	if bin == "" || model == "" {
		t.Skip("set DANI_CALIB_BIN + DANI_CALIB_MODEL (+DANI_CALIB_BACKEND) for a live probe")
	}
	backend := os.Getenv("DANI_CALIB_BACKEND")
	if backend == "" {
		backend = "unknown"
	}
	_ = os.Remove(model + ".dani-calib.json") // force a fresh measurement
	ngl := CalibrateLlama(context.Background(), LlamaConfig{Model: "live", BinPath: bin, ModelPath: model, Port: 18089},
		backend, t.Logf)
	t.Logf("LIVE verdict on this machine: -ngl %d", ngl)
}

// zero-token chat response -> the degenerate guard rejects the candidate end-to-end.
func TestMeasureCandidateDegenerateChat(t *testing.T) {
	_, port := healthServer(t, func(rw http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health":
			rw.WriteHeader(http.StatusOK)
		case "/v1/chat/completions":
			fmt.Fprint(rw, `{"choices":[{"message":{"role":"assistant","content":""}}],"usage":{"prompt_tokens":9,"completion_tokens":0}}`)
		}
	})
	bin, model := fakeBinAndModel(t)
	os.Setenv("GO_LLAMA_HELPER", "1")
	t.Cleanup(func() { os.Unsetenv("GO_LLAMA_HELPER") })
	if _, err := measureCandidate(context.Background(), LlamaConfig{
		Model: "m", BinPath: bin, ModelPath: model, Port: port,
	}); err == nil {
		t.Fatal("degenerate chat must fail the candidate")
	}
}

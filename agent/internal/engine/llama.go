package engine

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

// LlamaEngine supervises llama.cpp's `llama-server` (a real OpenAI-compatible HTTP server) as a
// child subprocess and proxies chat completions to it — genuine CPU inference of a GGUF model
// (DL-R11-01: engines are subprocesses; M6: OpenAI /v1/chat/completions only).
type LlamaEngine struct {
	model        string // friendly model id (for reporting)
	binPath      string // path to llama-server
	modelPath    string // path to the .gguf
	host         string
	port         int
	threads      int
	ctxSize      int
	parallel     int // llama-server slots = real concurrent-serving capacity (continuous batching)
	gpuLayers    int // -ngl: layers offloaded to the GPU backend (0 = pure CPU; harmless on CPU builds)
	cmd          *exec.Cmd
	base         string // http://host:port
	client       *http.Client
	startTimeout time.Duration // health-poll budget (default 5m; tests shrink it)
	pollEvery    time.Duration // health-poll interval (default 2s)

	mu       sync.Mutex     // guards cmd swaps + adapters during hot-load restarts
	workDir  string         // extracted adapter GGUFs land here
	adapters []llamaAdapter // hot-loaded LoRA adapters, in --lora order (index = server adapter id)
}

// llamaAdapter is one hot-loaded LoRA: the DANI model id it serves and its GGUF on disk.
type llamaAdapter struct {
	modelID string
	path    string
}

// buildArgs renders the llama-server argv for the CURRENT config + adapter set.
// -c is the TOTAL context split across slots, so scale it by --parallel to keep per-slot context
// at l.ctxSize. With --parallel>1 llama-server does continuous batching = genuine concurrency.
func (l *LlamaEngine) buildArgs() []string {
	args := []string{
		"-m", l.modelPath,
		"--host", l.host, "--port", strconv.Itoa(l.port),
		"-c", strconv.Itoa(l.ctxSize * l.parallel),
		"--parallel", strconv.Itoa(l.parallel),
		"--no-webui",
	}
	if l.threads > 0 {
		args = append(args, "-t", strconv.Itoa(l.threads))
	}
	// -ngl is ALWAYS explicit: GPU-enabled llama builds default to FULL offload when the flag is
	// omitted, so "0 means unset" would silently run the GPU. DANI decides deliberately (hwcaps
	// detection / calibration / operator) and states it. CPU-only builds accept -ngl and just warn.
	args = append(args, "-ngl", strconv.Itoa(l.gpuLayers))
	l.mu.Lock()
	if len(l.adapters) > 0 {
		for _, a := range l.adapters {
			args = append(args, "--lora", a.path)
		}
		args = append(args, "--lora-init-without-apply")
	}
	l.mu.Unlock()
	return args
}

// LlamaConfig configures a llama-server-backed engine.
type LlamaConfig struct {
	Model     string
	BinPath   string
	ModelPath string
	Port      int
	Threads   int
	CtxSize   int // per-slot context (total = CtxSize × Parallel); 0 = 2048
	Parallel  int // concurrent slots; 0/1 = single-stream (no real concurrency)
	GPULayers int // -ngl layers offloaded to the detected GPU backend; 0 = pure CPU
}

func NewLlama(c LlamaConfig) *LlamaEngine {
	if c.Port == 0 {
		c.Port = 8080
	}
	if c.Parallel <= 0 {
		c.Parallel = 1
	}
	if c.CtxSize == 0 {
		c.CtxSize = 2048 // per slot
	}
	return &LlamaEngine{
		model: c.Model, binPath: c.BinPath, modelPath: c.ModelPath,
		host: "127.0.0.1", port: c.Port, threads: c.Threads, ctxSize: c.CtxSize, parallel: c.Parallel,
		gpuLayers: c.GPULayers,
		base:         fmt.Sprintf("http://127.0.0.1:%d", c.Port),
		client:       &http.Client{Timeout: 5 * time.Minute},
		startTimeout: 5 * time.Minute, pollEvery: 2 * time.Second,
	}
}

// Parallel reports the engine's real concurrent-serving capacity (slots) so the worker can size its
// admission to what the engine can actually batch — not over-promise (D-01).
func (l *LlamaEngine) Parallel() int { return l.parallel }

func (l *LlamaEngine) Name() string { return "llama.cpp" }

// Start launches llama-server and blocks until it reports healthy (or ctx/timeout fires).
func (l *LlamaEngine) Start(ctx context.Context) error {
	if _, err := os.Stat(l.binPath); err != nil {
		return fmt.Errorf("llama-server not found at %s: %w", l.binPath, err)
	}
	if _, err := os.Stat(l.modelPath); err != nil {
		return fmt.Errorf("model not found at %s: %w", l.modelPath, err)
	}
	return l.launch(ctx)
}

// launch (re)spawns llama-server with the CURRENT adapter set and waits for health. Adapters are
// passed with --lora-init-without-apply, so they are LOADED but idle until a request activates
// them by scale — one server truthfully serves the base and every hot-loaded fine-tune.
func (l *LlamaEngine) launch(ctx context.Context) error {
	l.cmd = exec.Command(l.binPath, l.buildArgs()...)
	l.cmd.Stdout = os.Stderr // llama-server logs → our stderr (journald)
	l.cmd.Stderr = os.Stderr
	if err := l.cmd.Start(); err != nil {
		return fmt.Errorf("start llama-server: %w", err)
	}
	// poll /health until ready
	deadline := time.Now().Add(l.startTimeout)
	for {
		if l.healthy(ctx) {
			return nil
		}
		if time.Now().After(deadline) {
			_ = l.Close()
			return fmt.Errorf("llama-server did not become healthy within timeout")
		}
		select {
		case <-time.After(l.pollEvery):
		case <-ctx.Done():
			_ = l.Close()
			return ctx.Err()
		}
	}
}

// Load implements HotLoader (auto-deploy, D-11): the artifact is DANI's adapter tar; it must carry
// an `adapter.gguf` (produced at training time by train_qlora.py --llama-cpp ...). The GGUF is
// extracted, the server RESTARTS with the accumulated --lora set (llama-server cannot attach a new
// adapter file at runtime), and requests addressed to the tuned model id activate it by scale.
func (l *LlamaEngine) Load(modelID string, artifact []byte) error {
	l.mu.Lock()
	for _, a := range l.adapters {
		if a.modelID == modelID {
			l.mu.Unlock()
			return nil // already loaded
		}
	}
	if l.workDir == "" {
		dir, err := os.MkdirTemp("", "dani-llama-adapters-*")
		if err != nil {
			l.mu.Unlock()
			return err
		}
		l.workDir = dir
	}
	dst := filepath.Join(l.workDir, modelID+".gguf")
	l.mu.Unlock()

	gguf, err := extractAdapterGGUF(artifact)
	if err != nil {
		return err
	}
	if err := os.WriteFile(dst, gguf, 0o600); err != nil {
		return err
	}
	l.mu.Lock()
	l.adapters = append(l.adapters, llamaAdapter{modelID: modelID, path: dst})
	l.mu.Unlock()

	// restart with the new adapter set (brief serving gap; the gateway retries around it)
	_ = l.Close()
	if err := l.launch(context.Background()); err != nil {
		// roll the adapter back out so a broken artifact cannot wedge the engine
		l.mu.Lock()
		l.adapters = l.adapters[:len(l.adapters)-1]
		l.mu.Unlock()
		_ = l.Close()
		if lerr := l.launch(context.Background()); lerr != nil {
			return fmt.Errorf("hot-load restart failed AND rollback failed: %v (rollback: %v)", err, lerr)
		}
		return fmt.Errorf("hot-load restart failed (rolled back): %w", err)
	}
	return nil
}

// Unload implements HotUnloader: the adapter is removed from the accumulated set and the server
// restarts without it (mirror of Load — llama-server cannot detach an adapter file at runtime).
// On a failed restart the adapter is rolled back IN so the engine keeps serving its prior set.
func (l *LlamaEngine) Unload(modelID string) error {
	l.mu.Lock()
	idx := -1
	for i, a := range l.adapters {
		if a.modelID == modelID {
			idx = i
			break
		}
	}
	if idx < 0 {
		l.mu.Unlock()
		return nil // not loaded — nothing to do
	}
	removed := l.adapters[idx]
	l.adapters = append(append([]llamaAdapter{}, l.adapters[:idx]...), l.adapters[idx+1:]...)
	l.mu.Unlock()

	_ = l.Close()
	if err := l.launch(context.Background()); err != nil {
		l.mu.Lock()
		l.adapters = append(l.adapters, removed) // roll back in
		l.mu.Unlock()
		_ = l.Close()
		if lerr := l.launch(context.Background()); lerr != nil {
			return fmt.Errorf("unload restart failed AND rollback failed: %v (rollback: %v)", err, lerr)
		}
		return fmt.Errorf("unload restart failed (rolled back): %w", err)
	}
	return nil
}

// Loaded implements HotLoader.
func (l *LlamaEngine) Loaded() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]string, len(l.adapters))
	for i, a := range l.adapters {
		out[i] = a.modelID
	}
	return out
}

// extractAdapterGGUF pulls adapter.gguf out of a DANI adapter tar.
func extractAdapterGGUF(artifact []byte) ([]byte, error) {
	tr := tar.NewReader(bytes.NewReader(artifact))
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("llama hot-load: artifact is not a tar: %w", err)
		}
		if filepath.Base(h.Name) == "adapter.gguf" {
			return io.ReadAll(tr)
		}
	}
	return nil, fmt.Errorf("llama hot-load: artifact carries no adapter.gguf (train with --llama-cpp to embed one)")
}

func (l *LlamaEngine) healthy(ctx context.Context) bool {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, l.base+"/health", nil)
	resp, err := l.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// openAIResp is the subset of llama-server's /v1/chat/completions response we consume.
type openAIResp struct {
	Choices []struct {
		Message Message `json:"message"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
	} `json:"usage"`
}

func (l *LlamaEngine) Chat(ctx context.Context, req Request) (*Result, error) {
	start := time.Now()
	if req.MaxTokens <= 0 {
		req.MaxTokens = 256
	}
	req.Stream = false
	// per-request LoRA activation: a request addressed to a hot-loaded fine-tune's id gets its
	// adapter at scale 1 (all others idle); any other model id runs the plain base (scales default
	// to 0 under --lora-init-without-apply).
	var body []byte
	l.mu.Lock()
	adapterIdx := -1
	for i, a := range l.adapters {
		if a.modelID == req.Model {
			adapterIdx = i
			break
		}
	}
	hasAdapters := len(l.adapters) > 0
	l.mu.Unlock()
	if hasAdapters {
		payload := map[string]any{"model": req.Model, "messages": req.Messages,
			"max_tokens": req.MaxTokens, "stream": false}
		if adapterIdx >= 0 {
			payload["lora"] = []map[string]any{{"id": adapterIdx, "scale": 1.0}}
		} else {
			payload["lora"] = []map[string]any{} // explicit: base only
		}
		body, _ = json.Marshal(payload)
	} else {
		body, _ = json.Marshal(req)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, l.base+"/v1/chat/completions", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := l.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("llama-server call: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("llama-server status %d", resp.StatusCode)
	}
	var oa openAIResp
	if err := json.NewDecoder(resp.Body).Decode(&oa); err != nil {
		return nil, fmt.Errorf("decode llama-server response: %w", err)
	}
	text := ""
	if len(oa.Choices) > 0 {
		text = oa.Choices[0].Message.Content
	}
	served := l.model
	if adapterIdx >= 0 {
		served = req.Model // a hot-loaded fine-tune answered, not the base
	}
	return &Result{
		Text: text, Engine: "llama.cpp", Model: served,
		PromptTokens: oa.Usage.PromptTokens, CompletionTokens: oa.Usage.CompletionTokens,
		TotalMs: msSince(start),
	}, nil
}

func (l *LlamaEngine) Close() error {
	if l.cmd != nil && l.cmd.Process != nil {
		_ = l.cmd.Process.Kill()
		_, _ = l.cmd.Process.Wait()
	}
	return nil
}

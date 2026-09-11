package engine

import (
	"context"
	"hash/fnv"
	"strings"
	"sync"
	"time"
)

// HotLoader is the optional engine capability behind auto-deploy (§6.17.4 "workers pull + verify +
// load"): an engine that can take a promoted model's artifact bytes at runtime and start serving
// that model id. The stub implements it (the orchestration is real; the AI is the mocked piece,
// per the project convention). Real engines: llama.cpp gains this via --lora once adapter-GGUF
// conversion is scripted (flagged); the openai proxy's upstream owns its own model lifecycle.
type HotLoader interface {
	Load(modelID string, artifact []byte) error
	Loaded() []string
}

// HotUnloader is the optional inverse capability (operator undeploy / placement scale-down): an
// engine that can stop serving a hot-loaded model id at runtime. Engines without it simply keep the
// model warm until restart — the placement table remains the routing truth either way.
type HotUnloader interface {
	Unload(modelID string) error
}

// StubEngine fabricates a plausible, prompt-varied completion and paces it with realistic
// per-token latency (ported from the sim's engine.js). It exists so the request path, routing,
// back-pressure, and benchmark harness are exercised honestly without a real model. This is the
// single mocked piece per the project's standing scope ("AI inference is the only thing mocked").
type StubEngine struct {
	model        string
	tokPerSec    float64
	firstTokenMs int64

	mu     sync.Mutex
	loaded []string // hot-loaded model ids (auto-deploy)
}

// NewStub returns a CPU-llama.cpp-shaped stub (the sim's llama.cpp profile: ~14 tok/s, 350ms TTFT).
func NewStub(model string) *StubEngine {
	return &StubEngine{model: model, tokPerSec: 14, firstTokenMs: 350}
}

// Load hot-loads a deployed model id (the artifact bytes stand in for weights — mocked AI).
func (s *StubEngine) Load(modelID string, _ []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, m := range s.loaded {
		if m == modelID {
			return nil
		}
	}
	s.loaded = append(s.loaded, modelID)
	return nil
}

// Unload implements HotUnloader: the stub stops advertising the model id immediately.
func (s *StubEngine) Unload(modelID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, m := range s.loaded {
		if m == modelID {
			s.loaded = append(s.loaded[:i], s.loaded[i+1:]...)
			return nil
		}
	}
	return nil // not loaded — nothing to do
}

// Loaded lists hot-loaded model ids.
func (s *StubEngine) Loaded() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.loaded...)
}

func (s *StubEngine) Name() string                    { return "stub" }
func (s *StubEngine) Start(ctx context.Context) error { return nil }
func (s *StubEngine) Close() error                    { return nil }

var canned = []string{
	"Based on the in-perimeter context provided, here is a concise answer: %s is handled entirely within your network boundary, with no data leaving the deployment.",
	"Summary: %s. All inference ran on-premises; the audit trail records this completion with its classification stamp.",
	`Regarding "%s", the relevant policy and classification controls were applied before this response was produced.`,
	"Here is what I found about %s — generated locally by a small language model on consumer-grade hardware, per the DANI thesis.",
}

func (s *StubEngine) Chat(ctx context.Context, req Request) (*Result, error) {
	start := time.Now()
	prompt := lastUser(req)
	topic := strings.TrimSpace(strings.Join(strings.Fields(prompt), " "))
	if len(topic) > 48 {
		topic = topic[:48]
	}
	if topic == "" {
		topic = "your request"
	}
	h := fnv.New32a()
	_, _ = h.Write([]byte(prompt))
	tmpl := canned[int(h.Sum32())%len(canned)]
	text := strings.Replace(tmpl, "%s", topic, 1)

	maxTok := req.MaxTokens
	if maxTok <= 0 {
		maxTok = 64
	}
	completion := approxTokens(text)
	if completion > maxTok {
		completion = maxTok
	}

	// pace it: first-token latency, then token-by-token at the engine's rate (honors ctx cancel).
	genMs := int64(float64(completion) / s.tokPerSec * 1000)
	total := s.firstTokenMs + genMs
	select {
	case <-time.After(time.Duration(total) * time.Millisecond):
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return &Result{
		Text: text, Engine: "stub", Model: s.model,
		PromptTokens: approxTokens(prompt), CompletionTokens: completion,
		FirstTokenMs: s.firstTokenMs, TotalMs: msSince(start),
	}, nil
}

package serving

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"dani.local/agent/internal/engine"
)

// fakeEngine returns a fixed answer — lets a test stand up an "honest seed" and a "poisoned
// volunteer" that deterministically disagree.
type fakeEngine struct{ answer string }

func (f fakeEngine) Name() string                { return "fake" }
func (f fakeEngine) Start(context.Context) error { return nil }
func (f fakeEngine) Close() error                { return nil }
func (f fakeEngine) Chat(context.Context, engine.Request) (*engine.Result, error) {
	return &engine.Result{Text: f.answer, Engine: "fake", Model: "m", CompletionTokens: 6, TotalMs: 5}, nil
}

// The money scenario: a poisoned volunteer's answer is cross-checked against a trusted seed,
// disagrees, and is REPLACED by the seed's answer before it ever reaches the user — and the
// volunteer's reputation is docked.
func TestSeedVerifyReplacesPoisonedAnswer(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	auth := newAuthority(t)
	p, linkAddr, gw := livePlane(t, auth)
	p.EnableSeedVerify(0.7, 0.5)

	// The volunteer must be the primary so this exercises the cross-check, not direct seed routing.
	vol := NewWorker(WorkerConfig{
		Identity: auth.identity("aaa-vol"), Engine: fakeEngine{answer: "spam spam buy cheap watches at example dot com"},
		ModelID: "m", Class: "unrestricted", AdvertiseHost: "127.0.0.1", ControllerURLs: []string{"https://" + linkAddr},
		MaxConcurrent: 2, QueueDepth: 2, HeartbeatEvery: 100 * time.Millisecond,
	})
	seed := NewWorker(WorkerConfig{
		Identity: auth.identity("zzz-seed"), Engine: fakeEngine{answer: "the capital of france is paris"},
		ModelID: "m", Class: "unrestricted", AdvertiseHost: "127.0.0.1", ControllerURLs: []string{"https://" + linkAddr},
		MaxConcurrent: 2, QueueDepth: 2, HeartbeatEvery: 100 * time.Millisecond, Seed: true,
	})
	// Give the volunteer lower predicted latency before starting either worker so
	// this does not depend on a routing tie-break. Keep the seed available to verify.
	vol.emaMs = 100
	seed.emaMs = 7000
	go func() { _ = vol.Serve(ctx, "127.0.0.1:0") }()
	go func() { _ = seed.Serve(ctx, "127.0.0.1:0") }()
	waitLiveFleet(t, gw, 2)

	body, _ := json.Marshal(map[string]any{"model": "m",
		"messages": []engine.Message{{Role: "user", Content: "capital of france?"}}, "max_tokens": 16})
	resp, err := http.Post("http://"+gw+"/v1/chat/completions", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if got := resp.Header.Get("X-Dani-Verify"); got != "seed-replaced" {
		t.Fatalf("expected seed-replaced, got verify=%q served-by=%q body=%s", got, resp.Header.Get("X-Dani-Served-By"), b)
	}
	if got := resp.Header.Get("X-Dani-Served-By"); got != "zzz-seed" {
		t.Fatalf("served-by should be the seed, got %q", got)
	}
	if !bytes.Contains(b, []byte("paris")) || bytes.Contains(b, []byte("spam")) {
		t.Fatalf("the user must see the SEED answer, never the poison: %s", b)
	}
	if rep := p.reputation.Get("aaa-vol"); rep >= 0.3 {
		t.Fatalf("the poisoned volunteer must be penalized below the 0.3 initial, got %v", rep)
	}
}

// When a volunteer AGREES with the seed, its answer is served and its reputation rises.
func TestSeedVerifyRewardsHonestVolunteer(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	auth := newAuthority(t)
	p, linkAddr, gw := livePlane(t, auth)
	p.EnableSeedVerify(0.7, 0.5)

	same := "the capital of france is paris"
	vol := NewWorker(WorkerConfig{
		Identity: auth.identity("aaa-vol"), Engine: fakeEngine{answer: "paris is the capital of france"}, // reworded, still agrees
		ModelID: "m", Class: "unrestricted", AdvertiseHost: "127.0.0.1", ControllerURLs: []string{"https://" + linkAddr},
		MaxConcurrent: 2, QueueDepth: 2, HeartbeatEvery: 100 * time.Millisecond,
	})
	seed := NewWorker(WorkerConfig{
		Identity: auth.identity("zzz-seed"), Engine: fakeEngine{answer: same},
		ModelID: "m", Class: "unrestricted", AdvertiseHost: "127.0.0.1", ControllerURLs: []string{"https://" + linkAddr},
		MaxConcurrent: 2, QueueDepth: 2, HeartbeatEvery: 100 * time.Millisecond, Seed: true,
	})
	// Advertise a faster volunteer so equal-score routing cannot bypass
	// the agreement/reputation path this test is intended to exercise.
	vol.emaMs = 100
	seed.emaMs = 7000
	go func() { _ = vol.Serve(ctx, "127.0.0.1:0") }()
	go func() { _ = seed.Serve(ctx, "127.0.0.1:0") }()
	waitLiveFleet(t, gw, 2)

	body, _ := json.Marshal(map[string]any{"model": "m",
		"messages": []engine.Message{{Role: "user", Content: "capital?"}}, "max_tokens": 16})
	resp, err := http.Post("http://"+gw+"/v1/chat/completions", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if got := resp.Header.Get("X-Dani-Verify"); got != "seed-agreed" {
		t.Fatalf("expected seed-agreed, got %q (served-by %q)", got, resp.Header.Get("X-Dani-Served-By"))
	}
	if got := resp.Header.Get("X-Dani-Served-By"); got != "aaa-vol" {
		t.Fatalf("an agreeing volunteer keeps serving, got served-by %q", got)
	}
	if rep := p.reputation.Get("aaa-vol"); rep <= 0.3 {
		t.Fatalf("an honest volunteer must be rewarded above the 0.3 initial, got %v", rep)
	}
}

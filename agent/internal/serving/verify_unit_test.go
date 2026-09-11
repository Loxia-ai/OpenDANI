package serving

import (
	"testing"
	"time"
)

func TestSimilarity(t *testing.T) {
	if similarity("", "") != 1 {
		t.Fatal("two empties are identical")
	}
	if similarity("hello world", "") != 0 {
		t.Fatal("one empty = 0")
	}
	if s := similarity("the quick brown fox", "the quick brown fox"); s != 1 {
		t.Fatalf("identical text = 1, got %v", s)
	}
	// non-deterministic phrasing of the SAME answer still scores high
	if s := similarity("the capital of france is paris", "paris is the capital of france"); s < 0.8 {
		t.Fatalf("reordered same answer should be similar, got %v", s)
	}
	// a poisoned/unrelated answer scores low
	if s := similarity("the capital of france is paris", "buy cheap watches at example dot com"); s > 0.2 {
		t.Fatalf("unrelated answer should be dissimilar, got %v", s)
	}
}

func TestExtractAnswer(t *testing.T) {
	body := []byte(`{"choices":[{"message":{"role":"assistant","content":"hello there"}}]}`)
	if got := extractAnswer(body); got != "hello there" {
		t.Fatalf("extract wrong: %q", got)
	}
	if extractAnswer([]byte(`not json`)) != "" {
		t.Fatal("bad json -> empty")
	}
	if extractAnswer([]byte(`{"choices":[]}`)) != "" {
		t.Fatal("no choices -> empty")
	}
}

func TestNeedsVerifyGating(t *testing.T) {
	p := &Plane{workers: map[string]*workerState{}, inflight: map[string]int{}, drained: map[string]bool{},
		revoked: map[string]bool{}, stale: time.Minute}
	// verification off -> never verify
	if p.needsVerify("anyone", false) {
		t.Fatal("verification off must never verify")
	}
	p.EnableSeedVerify(0.7, 0.5)
	// a seed is never verified
	if p.needsVerify("seed-x", true) {
		t.Fatal("a seed is never verified")
	}
	// a fresh volunteer (initial 0.3 < 0.7) IS verified
	if !p.needsVerify("vol-1", false) {
		t.Fatal("a low-reputation volunteer must be verified")
	}
	// reward it above threshold -> no longer verified
	for i := 0; i < 6; i++ {
		p.reputation.Reward("vol-1")
	}
	if p.needsVerify("vol-1", false) {
		t.Fatalf("a high-reputation volunteer should skip verification (score %v)", p.reputation.Get("vol-1"))
	}
}

func TestAgrees(t *testing.T) {
	var p Plane // verify nil -> agrees is a no-op true
	if !p.agrees("a", "totally different") {
		t.Fatal("with verification off, agrees must default true")
	}
	p2 := &Plane{workers: map[string]*workerState{}, inflight: map[string]int{}, drained: map[string]bool{}, revoked: map[string]bool{}, stale: time.Minute}
	p2.EnableSeedVerify(0.7, 0.5)
	if !p2.agrees("paris is the capital", "the capital is paris") {
		t.Fatal("similar answers should agree")
	}
	if p2.agrees("paris is the capital", "spam spam spam buy now") {
		t.Fatal("dissimilar answers should NOT agree")
	}
}

// reserveSeed picks only healthy seeds serving the model, and reserves a slot.
func TestReserveSeed(t *testing.T) {
	p := &Plane{workers: map[string]*workerState{}, inflight: map[string]int{}, drained: map[string]bool{},
		revoked: map[string]bool{}, stale: time.Minute}
	p.mu.Lock()
	p.workers["vol"] = &workerState{LastSeen: time.Now(), Heartbeat: Heartbeat{NodeUUID: "vol", ModelID: "m", Health: "healthy", MaxConcurrent: 2, QueueDepth: 2}}
	p.workers["seed1"] = &workerState{LastSeen: time.Now(), Heartbeat: Heartbeat{NodeUUID: "seed1", ModelID: "m", Health: "healthy", MaxConcurrent: 2, QueueDepth: 2, Seed: true}}
	p.mu.Unlock()
	c, ok := p.reserveSeed("m", "unrestricted")
	if !ok || c.uuid != "seed1" {
		t.Fatalf("reserveSeed must pick the seed, got %+v ok=%v", c, ok)
	}
	if p.inflight["seed1"] != 1 {
		t.Fatal("reserveSeed must reserve a slot on the seed")
	}
	// no seed for a different model
	if _, ok := p.reserveSeed("other", "unrestricted"); ok {
		t.Fatal("no seed serves 'other' — must return false")
	}
}

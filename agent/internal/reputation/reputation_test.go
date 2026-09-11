package reputation

import (
	"math"
	"testing"
)

func near(a, b float64) bool { return math.Abs(a-b) < 1e-9 }

func TestDefaultsAndGet(t *testing.T) {
	s := New(0, 0, 0) // all defaults
	if s.Get("new") != 0.3 {
		t.Fatalf("unseen node should read the initial 0.3, got %v", s.Get("new"))
	}
}

func TestRewardPenalizeClamp(t *testing.T) {
	s := New(0.5, 0.2, 0.3)
	if v := s.Reward("n"); !near(v, 0.7) {
		t.Fatalf("reward: %v", v)
	}
	if v := s.Penalize("n"); !near(v, 0.4) {
		t.Fatalf("penalize: %v", v)
	}
	// clamps at 1
	for i := 0; i < 20; i++ {
		s.Reward("n")
	}
	if s.Get("n") != 1 {
		t.Fatalf("must clamp at 1, got %v", s.Get("n"))
	}
	// clamps at 0
	for i := 0; i < 20; i++ {
		s.Penalize("n")
	}
	if s.Get("n") != 0 {
		t.Fatalf("must clamp at 0, got %v", s.Get("n"))
	}
}

func TestDistrustFasterThanTrust(t *testing.T) {
	s := New(0, 0, 0) // reward 0.1, penalty 0.25
	if s.reward >= s.penalty {
		t.Fatal("a good network distrusts faster than it trusts")
	}
}

func TestTrustedThreshold(t *testing.T) {
	s := New(0.5, 0.1, 0.1)
	if !s.Trusted("n", 0.5) {
		t.Fatal("0.5 >= 0.5 should be trusted")
	}
	s.Penalize("n") // -> 0.4
	if s.Trusted("n", 0.5) {
		t.Fatal("0.4 < 0.5 should not be trusted")
	}
}

func TestSnapshotSorted(t *testing.T) {
	s := New(0.5, 0.1, 0.1)
	s.Reward("bravo")
	s.Reward("alpha")
	snap := s.Snapshot()
	if len(snap) != 2 || snap[0].ID != "alpha" || snap[1].ID != "bravo" {
		t.Fatalf("snapshot should be sorted by id: %+v", snap)
	}
	if !near(snap[0].Score, 0.6) {
		t.Fatalf("snapshot score wrong: %v", snap[0].Score)
	}
}

package ledger

import "testing"

func TestEarnSpendBalancePriority(t *testing.T) {
	s := New()
	if s.Balance("x") != 0 || s.Priority("x") {
		t.Fatal("unseen id: zero balance, no priority (rides best-effort)")
	}
	s.Earn("x", 100)
	if s.Balance("x") != 100 || !s.Priority("x") {
		t.Fatalf("after earning, x is a priority contributor: bal=%v", s.Balance("x"))
	}
	s.Spend("x", 60)
	if s.Balance("x") != 40 || !s.Priority("x") {
		t.Fatalf("still net positive: bal=%v", s.Balance("x"))
	}
	s.Spend("x", 100) // now net negative -> back to best-effort
	if s.Priority("x") {
		t.Fatalf("a net consumer drops to best-effort: bal=%v", s.Balance("x"))
	}
}

func TestNoStarterCreditsToFarm(t *testing.T) {
	s := New()
	// a freshly minted identity has ZERO balance and is best-effort — nothing to harvest.
	for _, id := range []string{"sybil-1", "sybil-2", "sybil-3"} {
		if s.Priority(id) || s.Balance(id) != 0 {
			t.Fatalf("%s got free priority/credit — Sybil surface!", id)
		}
	}
	// the empty id (anonymous tourist) is never priority
	if s.Priority("") {
		t.Fatal("anonymous must be best-effort")
	}
}

func TestGuards(t *testing.T) {
	s := New()
	s.Earn("", 10)   // no id -> ignored
	s.Earn("x", 0)   // non-positive -> ignored
	s.Earn("x", -5)  // negative -> ignored
	s.Spend("x", 0)  // ignored
	s.Spend("x", -5) // ignored
	if s.Balance("x") != 0 || len(s.Snapshot()) != 0 {
		t.Fatalf("guards should have recorded nothing: bal=%v snap=%v", s.Balance("x"), s.Snapshot())
	}
}

func TestSnapshotSortedByBalance(t *testing.T) {
	s := New()
	s.Earn("small", 10)
	s.Earn("big", 100)
	s.Spend("debtor", 50)
	snap := s.Snapshot()
	if len(snap) != 3 || snap[0].ID != "big" || snap[2].ID != "debtor" {
		t.Fatalf("snapshot order wrong: %+v", snap)
	}
}

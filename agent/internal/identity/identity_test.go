package identity

import (
	"testing"
	"time"
)

// clockAt pins nowFn and returns a function to advance it.
func clockAt(t *testing.T) func(d time.Duration) {
	t.Helper()
	now := time.Unix(1700000000, 0)
	orig := nowFn
	nowFn = func() time.Time { return now }
	t.Cleanup(func() { nowFn = orig })
	return func(d time.Duration) { now = now.Add(d) }
}

func TestResolveDirectoryAndCache(t *testing.T) {
	advance := clockAt(t)
	b := New("entra-id")
	p, err := b.Resolve("alice")
	if err != nil || p.Clearance != "restricted" {
		t.Fatalf("alice: %+v err=%v", p, err)
	}
	// Mutate the directory entry; a cache hit within TTL still returns the cached principal (D39).
	b.Add(Principal{Sub: "alice", Display: "Alice v2", Roles: []string{"user"}, Clearance: "secret"})
	p, _ = b.Resolve("alice")
	if p.Clearance != "restricted" {
		t.Fatal("within TTL the cached principal must win")
	}
	// Past TTL the directory is re-consulted.
	advance(16 * time.Minute)
	p, _ = b.Resolve("alice")
	if p.Clearance != "secret" {
		t.Fatal("past TTL the refreshed principal must win")
	}
}

func TestResolveUnknown(t *testing.T) {
	b := New("entra-id")
	if _, err := b.Resolve("mallory"); err == nil {
		t.Fatal("unknown principal must fail")
	}
}

func TestOutageBehavior(t *testing.T) {
	advance := clockAt(t)
	b := New("entra-id")
	if _, err := b.Resolve("bob"); err != nil {
		t.Fatal(err)
	}
	b.SetOutage(true)
	// Within TTL: served from cache by the normal path.
	if _, err := b.Resolve("bob"); err != nil {
		t.Fatalf("outage within TTL should serve from cache: %v", err)
	}
	// Past TTL: STALE cache still beats failing during an outage (the sim's D39 call).
	advance(20 * time.Minute)
	if p, err := b.Resolve("bob"); err != nil || p.Sub != "bob" {
		t.Fatalf("outage past TTL should serve stale cache: %v", err)
	}
	// Never-resolved principal during an outage: fail closed.
	if _, err := b.Resolve("carol"); err == nil {
		t.Fatal("outage with no cache must fail closed")
	}
}

func TestPrincipalsOrderingWithExtras(t *testing.T) {
	b := New("entra-id")
	b.Add(Principal{Sub: "zack", Clearance: "internal"})
	b.Add(Principal{Sub: "mia", Clearance: "internal"})
	ps := b.Principals()
	if len(ps) != 6 {
		t.Fatalf("expected 6 principals, got %d", len(ps))
	}
	want := []string{"alice", "bob", "carol", "guest", "mia", "zack"}
	for i, w := range want {
		if ps[i].Sub != w {
			t.Fatalf("order[%d]=%s want %s", i, ps[i].Sub, w)
		}
	}
}

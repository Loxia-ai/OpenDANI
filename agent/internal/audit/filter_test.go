package audit

import (
	"context"
	"testing"

	"dani.local/agent/internal/kms"
)

// TestRecentFiltered: the type-prefix filter matches whole families ("deployment.") and exact types
// with underscores ("model.gate_failed") without LIKE-wildcard leakage.
func TestRecentFiltered(t *testing.T) {
	ctx := context.Background()
	ks, _ := kms.NewSoftware()
	l, err := Open(ctx, ":memory:", ks)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	for _, typ := range []string{"deployment.assigned", "deployment.loaded", "model.gate_failed", "model.gateXfailed", "node.drained"} {
		if err := l.Emit(typ, map[string]any{"k": "v"}); err != nil {
			t.Fatal(err)
		}
	}
	// family prefix
	evs, err := l.RecentFiltered(ctx, 50, "deployment.")
	if err != nil || len(evs) != 2 {
		t.Fatalf("family filter: %v %d", err, len(evs))
	}
	// exact type with an underscore must NOT match the X variant (underscore is literal, not a wildcard)
	evs, err = l.RecentFiltered(ctx, 50, "model.gate_failed")
	if err != nil || len(evs) != 1 || evs[0].Type != "model.gate_failed" {
		t.Fatalf("underscore must be literal: %v %+v", err, evs)
	}
	// % must not act as a wildcard either
	if evs, _ = l.RecentFiltered(ctx, 50, "%"); len(evs) != 0 {
		t.Fatalf("%% must be literal: %+v", evs)
	}
	// empty prefix = everything (Recent alias)
	if evs, _ = l.RecentFiltered(ctx, 50, ""); len(evs) != 5 {
		t.Fatalf("empty prefix must return all: %d", len(evs))
	}
	// limit still applies
	if evs, _ = l.RecentFiltered(ctx, 2, ""); len(evs) != 2 {
		t.Fatalf("limit: %d", len(evs))
	}
}

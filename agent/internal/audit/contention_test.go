package audit

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"testing"

	"dani.local/agent/internal/kms"
)

// TestNoSilentEventLossUnderContention is the D-31 regression: audit emits are fire-and-forget, so
// a SQLITE_BUSY between concurrent writers (Emit vs the SignHead anchor ticker) silently DROPPED
// events before dbx serialized SQLite through one pooled connection + busy_timeout. Found live: a
// model.signed record vanished during a sign burst. This hammers both writers and requires every
// emitted event to be durable.
func TestNoSilentEventLossUnderContention(t *testing.T) {
	ctx := context.Background()
	ks, _ := kms.NewSoftware()
	l, err := Open(ctx, filepath.Join(t.TempDir(), "audit.db"), ks) // a FILE db (the live shape), not :memory:
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	const emitters, perEmitter = 8, 40
	var wg sync.WaitGroup
	var mu sync.Mutex
	var emitErrs []error
	for g := 0; g < emitters; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < perEmitter; i++ {
				if err := l.Emit("stress.event", map[string]any{"g": g, "i": i}); err != nil {
					mu.Lock()
					emitErrs = append(emitErrs, err)
					mu.Unlock()
				}
			}
		}(g)
	}
	// the anchor writer racing the emitters (the live contention shape)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 60; i++ {
			if err := l.SignHead(ctx); err != nil {
				mu.Lock()
				emitErrs = append(emitErrs, fmt.Errorf("signhead: %w", err))
				mu.Unlock()
			}
		}
	}()
	wg.Wait()
	if len(emitErrs) > 0 {
		t.Fatalf("writes failed under contention (would be silent loss at fire-and-forget call sites): %v", emitErrs[0])
	}
	records, _, _, err := l.Stats(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if records != emitters*perEmitter {
		t.Fatalf("silent event loss: emitted %d, stored %d", emitters*perEmitter, records)
	}
	if integ, err := l.Verify(ctx); err != nil || !integ.OK {
		t.Fatalf("chain must verify after contention: %+v %v", integ, err)
	}
}

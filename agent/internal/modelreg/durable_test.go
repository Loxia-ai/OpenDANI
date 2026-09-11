package modelreg

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestDurableRegistryRoundTrip: a promoted model + its REAL signatures + rag aliases survive a
// registry rebuild from the snapshot (the controller-restart companion to GenesisOrResume) — and
// VerifyApproval still passes because the SAME KMS verifies the rehydrated signatures.
func TestDurableRegistryRoundTrip(t *testing.T) {
	ctx := context.Background()
	r, store := newReg(t)
	snap := filepath.Join(t.TempDir(), "models.json")
	if _, err := r.SetDurable(snap); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Register(ctx, RegisterMeta{ID: "base", Name: "Base", Version: "1", Engine: "stub", Aliases: []string{"b"}}, []byte("w")); err != nil {
		t.Fatal(err)
	}
	if _, err := r.SubmitCandidate(ctx, CandidateMeta{ID: "ft-v1", Name: "ft", Version: "1", Engine: "stub",
		Classification: "restricted", Base: "base", Lineage: &Lineage{Base: "base", Collection: "legal"}}, "adapter", []byte("adapter-bytes")); err != nil {
		t.Fatal(err)
	}
	for _, role := range signerRoles {
		if _, err := r.Sign(ctx, "ft-v1", role); err != nil {
			t.Fatal(err)
		}
	}
	r.RegisterRagAlias("base", "legal")

	// "restart": a FRESH registry over the same KMS + artifact store rehydrates the snapshot
	r2 := New(r.ks, store)
	if _, err := r2.SetDurable(snap); err != nil {
		t.Fatal(err)
	}
	e := r2.Get("ft-v1")
	if e == nil || e.State != "available" || len(e.Signatures) != 3 {
		t.Fatalf("promoted model must survive: %+v", e)
	}
	if !r2.VerifyApproval("ft-v1") {
		t.Fatal("rehydrated signatures must verify under the same KMS (verify-on-use)")
	}
	if r2.Resolve("b") == nil {
		t.Fatal("alias must survive")
	}
	if _, ok := r2.ResolveRag("base-rag-legal"); !ok {
		t.Fatal("rag alias must survive")
	}
	// tampering with the snapshot's pinned hash makes verify-on-use REJECT the model
	e.Artifact.Hash = "deadbeef"
	if r2.VerifyApproval("ft-v1") {
		t.Fatal("a tampered rehydrated entry must fail verify-on-use")
	}
}

// TestDurableRegistryCorruptSnapshot: refusing to start empty over a live deployment.
func TestDurableRegistryCorruptSnapshot(t *testing.T) {
	r, _ := newReg(t)
	snap := filepath.Join(t.TempDir(), "models.json")
	if err := os.WriteFile(snap, []byte("{nope"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := r.SetDurable(snap); err == nil {
		t.Fatal("corrupt snapshot must be a hard error")
	}
}

// TestDurableRegistryReadError: an unreadable snapshot path (a directory) is an error distinct
// from not-exists.
func TestDurableRegistryReadError(t *testing.T) {
	r, _ := newReg(t)
	if _, err := r.SetDurable(t.TempDir()); err == nil {
		t.Fatal("unreadable snapshot must error")
	}
}

// TestDurableRegistryPersistError: a mutation that cannot persist FAILS (authoritative state must
// not silently diverge from its snapshot).
func TestDurableRegistryPersistError(t *testing.T) {
	ctx := context.Background()
	r, _ := newReg(t)
	bad := filepath.Join(t.TempDir(), "no-such-dir", "models.json")
	if _, err := r.SetDurable(bad); err != nil {
		t.Fatal(err) // path doesn't exist yet -> fine (first boot)
	}
	if _, err := r.Register(ctx, RegisterMeta{ID: "m", Name: "m", Version: "1", Engine: "e"}, []byte("w")); err == nil {
		t.Fatal("Register must fail when the snapshot cannot be written")
	}
	if _, err := r.SubmitCandidate(ctx, CandidateMeta{ID: "c", Name: "c", Version: "1", Engine: "e"}, "adapter", []byte("b")); err == nil {
		t.Fatal("SubmitCandidate must fail when the snapshot cannot be written")
	}
	// Sign: stage the candidate in-memory first (durable off), then fail the persist on Sign
	r2, _ := newReg(t)
	if _, err := r2.SubmitCandidate(ctx, CandidateMeta{ID: "c", Name: "c", Version: "1", Engine: "e"}, "adapter", []byte("b")); err != nil {
		t.Fatal(err)
	}
	if _, err := r2.SetDurable(bad); err != nil {
		t.Fatal(err)
	}
	if _, err := r2.Sign(ctx, "c", RoleSecurity); err == nil {
		t.Fatal("Sign must fail when the snapshot cannot be written")
	}
}

// TestDurableGateHoldPersisted: the fully-signed-but-gate-held state (GateFailed) round-trips.
func TestDurableGateHoldPersisted(t *testing.T) {
	ctx := context.Background()
	r, store := newReg(t)
	r.SetGate(EvalGate{MinTask: 0.9})
	snap := filepath.Join(t.TempDir(), "models.json")
	if _, err := r.SetDurable(snap); err != nil {
		t.Fatal(err)
	}
	if _, err := r.SubmitCandidate(ctx, CandidateMeta{ID: "held", Name: "h", Version: "1", Engine: "e",
		Evals: map[string]float64{"task": 0.1}, Lineage: &Lineage{}}, "adapter", []byte("b")); err != nil {
		t.Fatal(err)
	}
	for _, role := range signerRoles {
		if _, err := r.Sign(ctx, "held", role); err != nil {
			t.Fatal(err)
		}
	}
	r2 := New(r.ks, store)
	if _, err := r2.SetDurable(snap); err != nil {
		t.Fatal(err)
	}
	e := r2.Get("held")
	if e == nil || e.State != "draft" || e.GateFailed == "" {
		t.Fatalf("gate hold must survive the restart: %+v", e)
	}
}

// TestReplicatorReceivesSnapshotAfterMutation: every durable mutation ships a snapshot reflecting it.
func TestReplicatorReceivesSnapshot(t *testing.T) {
	ctx := context.Background()
	r, _ := newReg(t)
	var got [][]byte
	r.SetReplicator(func(b []byte) error { got = append(got, append([]byte{}, b...)); return nil })

	if _, err := r.Register(ctx, RegisterMeta{ID: "base", Name: "b", Version: "1", Engine: "e"}, []byte("w")); err != nil {
		t.Fatal(err)
	}
	if _, err := r.SubmitCandidate(ctx, CandidateMeta{ID: "c", Name: "c", Version: "1", Engine: "e", Lineage: &Lineage{}}, "adapter", []byte("b")); err != nil {
		t.Fatal(err)
	}
	for _, role := range signerRoles {
		if _, err := r.Sign(ctx, "c", role); err != nil {
			t.Fatal(err)
		}
	}
	r.RegisterRagAlias("base", "legal")
	// Register + SubmitCandidate + 3 Sign + RagAlias = 6 replications
	if len(got) != 6 {
		t.Fatalf("expected 6 replications, got %d", len(got))
	}
	// the last snapshot reflects the promoted model
	last := got[len(got)-1]
	if !bytes.Contains(last, []byte(`"base-rag-legal"`)) {
		t.Fatalf("final snapshot missing the rag alias: %s", last)
	}
}

// TestReplicatorNotHoldingLock is the deadlock regression: replicate is invoked AFTER r.mu is
// released, so a callback that itself touches the registry (as the leader's own FSM.Apply does via
// LoadSnapshotBytes) cannot deadlock. If replicate ran under the lock, SnapshotBytes here would hang.
func TestReplicatorNotHoldingLock(t *testing.T) {
	ctx := context.Background()
	r, _ := newReg(t)
	done := make(chan struct{})
	r.SetReplicator(func(b []byte) error {
		_ = r.SnapshotBytes() // needs r.mu — must not be held by the mutator
		_ = r.Get("base")     // ditto
		return nil
	})
	go func() {
		_, _ = r.Register(ctx, RegisterMeta{ID: "base", Name: "b", Version: "1", Engine: "e"}, []byte("w"))
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("mutation deadlocked — replicate must run outside the registry lock")
	}
}

// TestReplicatorErrorPropagates: a replication failure fails the mutation (state must not silently
// diverge from the cluster).
func TestReplicatorErrorPropagates(t *testing.T) {
	ctx := context.Background()
	r, _ := newReg(t)
	r.SetReplicator(func(b []byte) error { return errReplica })
	if _, err := r.Register(ctx, RegisterMeta{ID: "x", Name: "x", Version: "1", Engine: "e"}, []byte("w")); err == nil {
		t.Fatal("Register must fail when replication fails")
	}
	if _, err := r.SubmitCandidate(ctx, CandidateMeta{ID: "c", Name: "c", Version: "1", Engine: "e"}, "adapter", []byte("b")); err == nil {
		t.Fatal("SubmitCandidate must fail when replication fails")
	}
	// Sign: stage a draft with replication OFF, then turn on the failing replicator
	r2, _ := newReg(t)
	if _, err := r2.SubmitCandidate(ctx, CandidateMeta{ID: "d", Name: "d", Version: "1", Engine: "e"}, "adapter", []byte("b")); err != nil {
		t.Fatal(err)
	}
	r2.SetReplicator(func(b []byte) error { return errReplica })
	if _, err := r2.Sign(ctx, "d", RoleSecurity); err == nil {
		t.Fatal("Sign must fail when replication fails")
	}
}

var errReplica = fmt.Errorf("replica down")

// TestLoadSnapshotBytesRoundTrip: a replica loads a snapshot without re-replicating or persisting-fail.
func TestLoadSnapshotBytesRoundTrip(t *testing.T) {
	ctx := context.Background()
	leader, store := newReg(t)
	if _, err := leader.Register(ctx, RegisterMeta{ID: "m", Name: "m", Version: "1", Engine: "e", Aliases: []string{"a"}}, []byte("w")); err != nil {
		t.Fatal(err)
	}
	snap := leader.SnapshotBytes()

	// a follower loads it — no replicator wired, so loading must not attempt to re-replicate
	follower := New(leader.ks, store)
	replicated := false
	follower.SetReplicator(func([]byte) error { replicated = true; return nil })
	if err := follower.LoadSnapshotBytes(snap); err != nil {
		t.Fatal(err)
	}
	if replicated {
		t.Fatal("LoadSnapshotBytes must NOT re-replicate (it is the terminal sink)")
	}
	if follower.Get("m") == nil || follower.Resolve("a") == nil {
		t.Fatal("follower must have the loaded model + alias")
	}
	// corrupt snapshot -> error
	if err := follower.LoadSnapshotBytes([]byte("{bad")); err == nil {
		t.Fatal("corrupt replicated snapshot must error")
	}
}

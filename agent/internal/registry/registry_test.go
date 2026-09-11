package registry

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func open(t *testing.T) *Registry {
	t.Helper()
	r, err := Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return r
}

func sampleNode(uuid string, notAfter time.Time) NodeRecord {
	return NodeRecord{
		UUID: uuid, CertSerial: "01ab", NotBefore: time.Now().Add(-time.Hour), NotAfter: notAfter,
		Generation: 1, HardwareFprint: []byte{0xde, 0xad}, Roles: []string{"worker"}, Class: "restricted",
		Site: "site-hq", Tier: 0, CapabilitiesJSON: []byte(`{"engines":["llama.cpp"]}`),
	}
}

func TestUpsertGetCount(t *testing.T) {
	ctx := context.Background()
	r := open(t)
	if err := r.UpsertEnrolled(ctx, sampleNode("worker-1", time.Now().Add(90*24*time.Hour))); err != nil {
		t.Fatal(err)
	}
	n, err := r.Count(ctx)
	if err != nil || n != 1 {
		t.Fatalf("count=%d err=%v", n, err)
	}
	row, err := r.Get(ctx, "worker-1")
	if err != nil {
		t.Fatal(err)
	}
	if row.Class != "restricted" || row.Roles[0] != "worker" || row.Lifecycle != "active" || row.Generation != 1 {
		t.Fatalf("unexpected row: %+v", row)
	}
	// upsert again (idempotent) keeps a single row
	if err := r.UpsertEnrolled(ctx, sampleNode("worker-1", time.Now().Add(90*24*time.Hour))); err != nil {
		t.Fatal(err)
	}
	if n, _ := r.Count(ctx); n != 1 {
		t.Fatalf("expected 1 row after re-upsert, got %d", n)
	}
}

func TestActiveNodesWithRole(t *testing.T) {
	ctx := context.Background()
	r := open(t)
	// a trainer node, a worker node, and a decommissioned trainer (must be excluded).
	tr := sampleNode("trainer-1", time.Now().Add(90*24*time.Hour))
	tr.Roles = []string{"worker", "trainer"}
	if err := r.UpsertEnrolled(ctx, tr); err != nil {
		t.Fatal(err)
	}
	if err := r.UpsertEnrolled(ctx, sampleNode("worker-1", time.Now().Add(90*24*time.Hour))); err != nil {
		t.Fatal(err)
	}
	dead := sampleNode("trainer-2", time.Now().Add(90*24*time.Hour))
	dead.Roles = []string{"trainer"}
	if err := r.UpsertEnrolled(ctx, dead); err != nil {
		t.Fatal(err)
	}
	if err := r.SetLifecycle(ctx, "trainer-2", "decommissioned"); err != nil {
		t.Fatal(err)
	}

	trainers, err := r.ActiveNodesWithRole(ctx, "trainer")
	if err != nil {
		t.Fatal(err)
	}
	if len(trainers) != 1 || trainers[0] != "trainer-1" {
		t.Fatalf("expected [trainer-1], got %v", trainers)
	}
	workers, _ := r.ActiveNodesWithRole(ctx, "worker")
	if len(workers) != 2 { // trainer-1 also has role worker
		t.Fatalf("expected 2 workers, got %v", workers)
	}
	none, _ := r.ActiveNodesWithRole(ctx, "auditor")
	if len(none) != 0 {
		t.Fatalf("expected no auditors, got %v", none)
	}
}

func TestRenewalStatusView(t *testing.T) {
	ctx := context.Background()
	r := open(t)
	// fresh 90-day cert -> healthy
	mustUpsert(t, r, "fresh", time.Now().Add(90*24*time.Hour))
	// a cert past 90% of a (short) life -> grace_overdue; build one with a window mostly elapsed
	old := sampleNode("old", time.Now().Add(2*time.Hour))
	old.NotBefore = time.Now().Add(-90 * 24 * time.Hour) // long-since issued, almost expired
	if err := r.UpsertEnrolled(ctx, old); err != nil {
		t.Fatal(err)
	}
	// already-expired
	mustUpsert(t, r, "dead", time.Now().Add(-time.Hour))

	if s, _ := r.RenewalStatus(ctx, "fresh"); s != "healthy" {
		t.Fatalf("fresh: want healthy, got %q", s)
	}
	if s, _ := r.RenewalStatus(ctx, "old"); s != "grace_overdue" && s != "renewal_due" {
		t.Fatalf("old: want grace_overdue/renewal_due, got %q", s)
	}
	if s, _ := r.RenewalStatus(ctx, "dead"); s != "expired" {
		t.Fatalf("dead: want expired, got %q", s)
	}
	// revoked overrides
	if err := r.SetLifecycle(ctx, "fresh", "revoked"); err != nil {
		t.Fatal(err)
	}
	if s, _ := r.RenewalStatus(ctx, "fresh"); s != "revoked" {
		t.Fatalf("revoked: want revoked, got %q", s)
	}
}

func TestRenewAndHeartbeat(t *testing.T) {
	ctx := context.Background()
	r := open(t)
	mustUpsert(t, r, "w", time.Now().Add(48*time.Hour))
	if err := r.Renew(ctx, "w", "02cd", time.Now(), time.Now().Add(90*24*time.Hour), 2); err != nil {
		t.Fatal(err)
	}
	if err := r.Heartbeat(ctx, "w", "healthy", "3"); err != nil {
		t.Fatal(err)
	}
	row, _ := r.Get(ctx, "w")
	if row.Generation != 2 {
		t.Fatalf("expected generation 2 after renew, got %d", row.Generation)
	}
	if s, _ := r.RenewalStatus(ctx, "w"); s != "healthy" {
		t.Fatalf("after renew want healthy, got %q", s)
	}
}

func mustUpsert(t *testing.T, r *Registry, uuid string, notAfter time.Time) {
	t.Helper()
	if err := r.UpsertEnrolled(context.Background(), sampleNode(uuid, notAfter)); err != nil {
		t.Fatal(err)
	}
}

func TestDumpAllLoadAllRoundTrip(t *testing.T) {
	ctx := context.Background()
	r := open(t)
	a := sampleNode("node-a", time.Now().Add(90*24*time.Hour))
	a.Roles = []string{"worker", "trainer"}
	mustNoErr(t, r.UpsertEnrolled(ctx, a))
	b := sampleNode("node-b", time.Now().Add(30*24*time.Hour))
	b.Site = "" // NULL site path
	mustNoErr(t, r.UpsertEnrolled(ctx, b))
	mustNoErr(t, r.SetLifecycle(ctx, "node-b", "revoked"))

	rows, err := r.DumpAll(ctx)
	if err != nil || len(rows) != 2 {
		t.Fatalf("dump: %d %v", len(rows), err)
	}
	if rows[0].UUID != "node-a" || rows[0].Roles[1] != "trainer" || rows[1].Lifecycle != "revoked" {
		t.Fatalf("dump content wrong: %+v", rows)
	}
	// restore into a fresh registry: contents replaced, roles/site/lifecycle preserved
	r2 := open(t)
	mustNoErr(t, r2.UpsertEnrolled(ctx, sampleNode("stale", time.Now().Add(time.Hour)))) // must be wiped
	mustNoErr(t, r2.LoadAll(ctx, rows))
	got, err := r2.DumpAll(ctx)
	if err != nil || len(got) != 2 || got[0].UUID != "node-a" || got[1].Lifecycle != "revoked" || got[1].Site != "" {
		t.Fatalf("restore wrong: %+v %v", got, err)
	}
	if n, _ := r2.Count(ctx); n != 2 {
		t.Fatalf("stale row survived LoadAll: %d", n)
	}
}

func TestClosedRegistrySurfacesErrors(t *testing.T) {
	ctx := context.Background()
	r := open(t)
	mustNoErr(t, r.UpsertEnrolled(ctx, sampleNode("n", time.Now().Add(time.Hour))))
	_ = r.Close()
	if err := r.UpsertEnrolled(ctx, sampleNode("m", time.Now().Add(time.Hour))); err == nil {
		t.Fatal("closed upsert must error")
	}
	if err := r.Renew(ctx, "n", "01", time.Now(), time.Now(), 2); err == nil {
		t.Fatal("closed renew must error")
	}
	if err := r.Heartbeat(ctx, "n", "healthy", "1"); err == nil {
		t.Fatal("closed heartbeat must error")
	}
	if err := r.SetLifecycle(ctx, "n", "draining"); err == nil {
		t.Fatal("closed lifecycle must error")
	}
	if _, err := r.RenewalStatus(ctx, "n"); err == nil {
		t.Fatal("closed status must error")
	}
	if _, err := r.DumpAll(ctx); err == nil {
		t.Fatal("closed dump must error")
	}
	if err := r.LoadAll(ctx, nil); err == nil {
		t.Fatal("closed load must error")
	}
	if _, err := r.Count(ctx); err == nil {
		t.Fatal("closed count must error")
	}
	if _, err := r.Get(ctx, "n"); err == nil {
		t.Fatal("closed get must error")
	}
	if _, err := r.ActiveNodesWithRole(ctx, "worker"); err == nil {
		t.Fatal("closed role query must error")
	}
}

func TestOpenBadPath(t *testing.T) {
	if _, err := Open(context.Background(), filepath.Join(t.TempDir(), "no-dir", "x.db")); err == nil {
		t.Fatal("unopenable DSN must error")
	}
}

func mustNoErr(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

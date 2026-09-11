package registry

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	"dani.local/agent/internal/dbx"
)

// pgDSN returns the Postgres DSN under test (DANI_TEST_PG), skipping when unset so CI stays SQLite.
func pgDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("DANI_TEST_PG")
	if dsn == "" {
		t.Skip("DANI_TEST_PG not set; skipping Postgres parity test")
	}
	// clean slate: drop this service's objects (a fresh schema each run)
	db, _, err := dbx.Open(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect pg: %v", err)
	}
	defer db.Close()
	for _, s := range []string{`DROP VIEW IF EXISTS v_renewal_status`, `DROP TABLE IF EXISTS node_capabilities`, `DROP TABLE IF EXISTS nodes`} {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("clean pg (%s): %v", s, err)
		}
	}
	return dsn
}

// TestPostgresRegistryParity runs the core registry flows against a REAL Postgres — the same
// operations the SQLite tests cover — proving the dbx seam + schema_postgres are at parity.
func TestPostgresRegistryParity(t *testing.T) {
	dsn := pgDSN(t)
	ctx := context.Background()
	r, err := Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if r.dialect != dbx.Postgres {
		t.Fatalf("expected postgres dialect, got %s", r.dialect)
	}

	rec := NodeRecord{
		UUID: "n1", CertSerial: "01", NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(2 * time.Hour),
		Generation: 1, HardwareFprint: []byte{0xde, 0xad}, Roles: []string{"worker", "trainer"}, Class: "restricted",
		Site: "site-a", Tier: 0, CapabilitiesJSON: []byte(`{"vram":24}`),
	}
	if err := r.UpsertEnrolled(ctx, rec); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	// re-upsert (ON CONFLICT path) with a bumped serial
	rec.CertSerial = "02"
	if err := r.UpsertEnrolled(ctx, rec); err != nil {
		t.Fatalf("re-upsert: %v", err)
	}
	if n, _ := r.Count(ctx); n != 1 {
		t.Fatalf("expected 1 node, got %d", n)
	}
	if err := r.Renew(ctx, "n1", "03", time.Now(), time.Now().Add(3*time.Hour), 2); err != nil {
		t.Fatalf("renew: %v", err)
	}
	if err := r.Heartbeat(ctx, "n1", "healthy", "cfg-1"); err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	// renewal-status view (the julianday->timestamptz rewrite)
	st, err := r.RenewalStatus(ctx, "n1")
	if err != nil || st == "" {
		t.Fatalf("renewal status: %q %v", st, err)
	}
	// role query + Get
	if uuids, _ := r.ActiveNodesWithRole(ctx, "trainer"); len(uuids) != 1 || uuids[0] != "n1" {
		t.Fatalf("role query wrong: %v", uuids)
	}
	row, err := r.Get(ctx, "n1")
	if err != nil || row.Class != "restricted" || row.Generation != 2 {
		t.Fatalf("get: %+v %v", row, err)
	}
	// lifecycle -> revoked, then renewal-status reflects it
	if err := r.SetLifecycle(ctx, "n1", "revoked"); err != nil {
		t.Fatalf("lifecycle: %v", err)
	}
	if st, _ := r.RenewalStatus(ctx, "n1"); st != "revoked" {
		t.Fatalf("revoked node must report revoked, got %q", st)
	}
	// DumpAll / LoadAll (the Raft snapshot path) round-trips
	rows, err := r.DumpAll(ctx)
	if err != nil || len(rows) != 1 {
		t.Fatalf("dumpall: %v %d", err, len(rows))
	}
	if err := r.LoadAll(ctx, rows); err != nil {
		t.Fatalf("loadall: %v", err)
	}
	if n, _ := r.Count(ctx); n != 1 {
		t.Fatalf("after loadall expected 1 node, got %d", n)
	}
}

var _ = sql.ErrNoRows

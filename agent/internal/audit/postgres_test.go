package audit

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"dani.local/agent/internal/dbx"
	"dani.local/agent/internal/kms"
)

func pgDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("DANI_TEST_PG")
	if dsn == "" {
		t.Skip("DANI_TEST_PG not set; skipping Postgres parity test")
	}
	db, _, err := dbx.Open(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect pg: %v", err)
	}
	defer db.Close()
	for _, s := range []string{`DROP TABLE IF EXISTS audit_heads`, `DROP TABLE IF EXISTS audit_events`} {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("clean pg: %v", err)
		}
	}
	return dsn
}

// TestPostgresAuditParity: the hash-chained, KMS-signed audit log + offline-verifiable compliance
// export work against a REAL Postgres, including tamper detection through the DB.
func TestPostgresAuditParity(t *testing.T) {
	dsn := pgDSN(t)
	ctx := context.Background()
	ks, _ := kms.NewSoftware()
	l, err := Open(ctx, dsn, ks)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if l.dialect != dbx.Postgres {
		t.Fatalf("expected postgres dialect, got %s", l.dialect)
	}
	for i, typ := range []string{"genesis", "node.enrolled", "model.approved", "policy.deny"} {
		if err := l.Emit(typ, map[string]any{"i": i}); err != nil {
			t.Fatalf("emit: %v", err)
		}
		if i%2 == 0 {
			if err := l.SignHead(ctx); err != nil {
				t.Fatalf("signhead: %v", err)
			}
		}
	}
	integ, err := l.Verify(ctx)
	if err != nil || !integ.OK || integ.Records != 4 {
		t.Fatalf("verify: %+v %v", integ, err)
	}
	// resume: a fresh Log over the same DB picks up seq/head
	l2, err := Open(ctx, dsn, ks)
	if err != nil {
		t.Fatal(err)
	}
	defer l2.Close()
	if l2.seq != 4 {
		t.Fatalf("resume seq wrong: %d", l2.seq)
	}
	// compliance export verifies offline
	bundle, err := l2.Export(ctx, "dep-1")
	if err != nil {
		t.Fatal(err)
	}
	if bi, _ := VerifyBundle(bundle); !bi.OK || bi.Records != 4 {
		t.Fatalf("bundle verify: %+v", bi)
	}
	// TAMPER through the DB: an UPDATE to a historical row must break Verify (the whole point)
	db, _, _ := dbx.Open(ctx, dsn)
	defer db.Close()
	if _, err := db.Exec(`UPDATE audit_events SET payload=$1 WHERE seq=2`, `{"i":999}`); err != nil {
		t.Fatal(err)
	}
	if integ, _ := l2.Verify(ctx); integ.OK {
		t.Fatal("tampered Postgres row must fail verify")
	}
}

var _ = json.Marshal

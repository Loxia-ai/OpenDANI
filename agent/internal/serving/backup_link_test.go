package serving

// P2-A2: prove the cross-site backup endpoints work over the REAL mTLS Link, and that a peer with a
// fleet identity can replicate the newest archive end to end.

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	"dani.local/agent/internal/backup"
	_ "modernc.org/sqlite"
)

func TestBackupReplicationOverMTLSLink(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	auth := newAuthority(t)

	// site A controller: a backup dir with one real archive, served over its mTLS Link
	backupDir := t.TempDir()
	state := filepath.Join(t.TempDir(), "state")
	if err := os.MkdirAll(state, 0o755); err != nil {
		t.Fatal(err)
	}
	// a tiny sqlite state file so SnapshotOnce has something consistent to VACUUM
	db, err := sql.Open("sqlite", filepath.Join(state, "registry.db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE t (id INTEGER); INSERT INTO t VALUES (1)`); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	if _, err := backup.SnapshotOnce(ctx, backup.Config{StateDir: state, DestDir: backupDir, Keep: 3}); err != nil {
		t.Fatal(err)
	}

	pa, err := NewPlane(auth.identity("ctrl-a"), "site-a")
	if err != nil {
		t.Fatal(err)
	}
	pa.EnableBackupServe(backupDir)
	linkA, err := pa.ServeLink("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	// site B controller uses ITS fleet identity's mTLS client to pull site A's backup
	pb, err := NewPlane(auth.identity("ctrl-b"), "site-b")
	if err != nil {
		t.Fatal(err)
	}
	destB := t.TempDir()
	got, err := backup.ReplicateOnce(ctx, backup.ReplicateConfig{
		PeerBase: "https://" + linkA, DestDir: destB, Client: pb.Dialer(),
	})
	if err != nil || got == "" {
		t.Fatalf("cross-site pull over mTLS failed: err=%v path=%q", err, got)
	}
	// site B now holds a restorable copy
	if _, err := backup.LatestArchive(destB); err != nil {
		t.Fatalf("site B has no replicated archive: %v", err)
	}

	// a NON-fleet client (no cert / wrong CA) is refused by the mTLS Link
	other := newAuthority(t)
	pc, err := NewPlane(other.identity("stranger"), "site-x")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := backup.ReplicateOnce(ctx, backup.ReplicateConfig{
		PeerBase: "https://" + linkA, DestDir: t.TempDir(), Client: pc.Dialer(),
	}); err == nil {
		t.Fatal("a stranger CA must NOT be able to pull backups over the Link")
	}

	// second pull is idempotent
	time.Sleep(10 * time.Millisecond)
	if got2, err := backup.ReplicateOnce(ctx, backup.ReplicateConfig{
		PeerBase: "https://" + linkA, DestDir: destB, Client: pb.Dialer(),
	}); err != nil || got2 != "" {
		t.Fatalf("idempotent pull: err=%v got=%q", err, got2)
	}
}

package backup

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"database/sql"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

// makeLiveDB creates a WAL-mode SQLite db with committed rows AND leaves it OPEN (so a -wal tail
// exists) — the realistic "live controller" state we must snapshot without downtime.
func makeLiveDB(t *testing.T, path string, rows int) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`PRAGMA journal_mode=WAL`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)`); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < rows; i++ {
		if _, err := db.Exec(`INSERT INTO t (v) VALUES (?)`, fmt.Sprintf("row-%d", i)); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func extract(t *testing.T, archive, dest string) []string {
	t.Helper()
	f, err := os.Open(archive)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	var names []string
	if err := os.MkdirAll(dest, 0o755); err != nil {
		t.Fatal(err)
	}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, h.Name)
		out, err := os.Create(filepath.Join(dest, h.Name))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.Copy(out, tr); err != nil {
			t.Fatal(err)
		}
		_ = out.Close()
	}
	return names
}

func TestSnapshotIsConsistentAndComplete(t *testing.T) {
	ctx := context.Background()
	state := t.TempDir()
	dest := t.TempDir()

	// a live WAL db with 50 committed rows (kept open — a -wal file will exist)
	db := makeLiveDB(t, filepath.Join(state, "registry.db"), 50)
	// JSON state alongside it
	if err := os.WriteFile(filepath.Join(state, "authority.json"), []byte(`{"deployment":"prod"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(state, "models.json"), []byte(`[]`), 0o600); err != nil {
		t.Fatal(err)
	}

	archive, err := SnapshotOnce(ctx, Config{StateDir: state, DestDir: dest, Keep: 5})
	if err != nil {
		t.Fatalf("SnapshotOnce: %v", err)
	}
	// write MORE rows after the snapshot — the snapshot must NOT see them (point-in-time consistency)
	for i := 0; i < 10; i++ {
		if _, err := db.Exec(`INSERT INTO t (v) VALUES ('after-snapshot')`); err != nil {
			t.Fatal(err)
		}
	}

	names := extract(t, archive, t.TempDir())
	// -wal/-shm excluded; db + json present
	for _, n := range names {
		if strings.HasSuffix(n, "-wal") || strings.HasSuffix(n, "-shm") {
			t.Fatalf("snapshot must not carry %s", n)
		}
	}
	joined := strings.Join(names, ",")
	if !strings.Contains(joined, "registry.db") || !strings.Contains(joined, "authority.json") || !strings.Contains(joined, "models.json") {
		t.Fatalf("missing members: %v", names)
	}

	// the snapshotted db opens as a clean single file and holds EXACTLY the 50 committed rows
	restoreDir := t.TempDir()
	extract(t, archive, restoreDir)
	rdb, err := sql.Open("sqlite", filepath.Join(restoreDir, "registry.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer rdb.Close()
	var n int
	if err := rdb.QueryRow(`SELECT count(*) FROM t`).Scan(&n); err != nil {
		t.Fatalf("query snapshot: %v", err)
	}
	if n != 50 {
		t.Fatalf("snapshot row count = %d, want 50 (consistency: post-snapshot writes must be excluded)", n)
	}
}

func TestRetentionPrune(t *testing.T) {
	ctx := context.Background()
	state := t.TempDir()
	dest := t.TempDir()
	makeLiveDB(t, filepath.Join(state, "config.db"), 1)

	clock := time.Date(2026, 7, 7, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 6; i++ {
		c := clock.Add(time.Duration(i) * time.Hour)
		if _, err := SnapshotOnce(ctx, Config{StateDir: state, DestDir: dest, Keep: 3, Now: func() time.Time { return c }}); err != nil {
			t.Fatalf("snapshot %d: %v", i, err)
		}
	}
	entries, _ := os.ReadDir(dest)
	kept := 0
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), archivePrefix) {
			kept++
		}
	}
	if kept != 3 {
		t.Fatalf("retention kept %d archives, want 3", kept)
	}
	// LatestArchive returns the newest (highest timestamp)
	latest, err := LatestArchive(dest)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(latest, "20260707T050000Z") {
		t.Fatalf("latest = %s, want the 05:00 archive", latest)
	}
}

func TestSnapshotErrors(t *testing.T) {
	ctx := context.Background()
	// missing args
	if _, err := SnapshotOnce(ctx, Config{}); err == nil {
		t.Fatal("missing StateDir/DestDir must error")
	}
	// empty state dir
	empty := t.TempDir()
	if _, err := SnapshotOnce(ctx, Config{StateDir: empty, DestDir: t.TempDir()}); err == nil {
		t.Fatal("no state files must error")
	}
	// unreadable state dir
	if _, err := SnapshotOnce(ctx, Config{StateDir: filepath.Join(empty, "nope"), DestDir: t.TempDir()}); err == nil {
		t.Fatal("missing state dir must error")
	}
	// a corrupt .db file fails the VACUUM INTO snapshot
	state := t.TempDir()
	if err := os.WriteFile(filepath.Join(state, "bad.db"), []byte("not a sqlite file at all"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := SnapshotOnce(ctx, Config{StateDir: state, DestDir: t.TempDir()}); err == nil {
		t.Fatal("corrupt db must fail the snapshot")
	}
	// LatestArchive on an empty dir
	if _, err := LatestArchive(t.TempDir()); err == nil {
		t.Fatal("no archives must error")
	}
	if _, err := LatestArchive(filepath.Join(empty, "nope")); err == nil {
		t.Fatal("missing dir must error")
	}
}

func TestRunSchedulerBootSnapshotAndStop(t *testing.T) {
	state := t.TempDir()
	dest := t.TempDir()
	makeLiveDB(t, filepath.Join(state, "audit.db"), 3)
	var audited int
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		Run(ctx, Config{StateDir: state, DestDir: dest, Every: time.Hour, Keep: 2,
			Audit: func(string, map[string]any) { audited++ }})
		close(done)
	}()
	// the boot snapshot lands quickly
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := LatestArchive(dest); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("boot snapshot never appeared")
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not stop on ctx cancel")
	}
	if audited == 0 {
		t.Fatal("backup.created was never audited")
	}
	// Every<=0 returns immediately (no scheduler)
	Run(context.Background(), Config{Every: 0})
}

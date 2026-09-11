package backup

import (
	"archive/tar"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWriteArchiveAndAddFileErrors(t *testing.T) {
	// create-archive error: the path's parent is a FILE, so open fails
	blocker := filepath.Join(t.TempDir(), "block")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeArchive(filepath.Join(blocker, "child.tar.gz"), func(*tar.Writer) error { return nil }); err == nil {
		t.Fatal("archive under a file path must fail")
	}
	// fn-returns-error path (covers the mid-write close cascade)
	ok := filepath.Join(t.TempDir(), "a.tar.gz")
	sentinel := errors.New("boom")
	if err := writeArchive(ok, func(*tar.Writer) error { return sentinel }); !errors.Is(err, sentinel) {
		t.Fatalf("fn error not surfaced: %v", err)
	}
	// addFile with a missing source
	if err := writeArchive(filepath.Join(t.TempDir(), "b.tar.gz"), func(tw *tar.Writer) error {
		return addFile(tw, "gone", filepath.Join(t.TempDir(), "does-not-exist"))
	}); err == nil {
		t.Fatal("addFile on a missing source must fail")
	}
}

func TestSnapshotDestUnwritable(t *testing.T) {
	state := t.TempDir()
	makeLiveDB(t, filepath.Join(state, "x.db"), 1)
	// DestDir whose parent is a file -> MkdirAll fails
	f := filepath.Join(t.TempDir(), "afile")
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := SnapshotOnce(context.Background(), Config{StateDir: state, DestDir: filepath.Join(f, "sub")}); err == nil {
		t.Fatal("unwritable dest must fail")
	}
}

func TestPruneAndSnapshotDBDirect(t *testing.T) {
	// prune over a missing dir surfaces the read error
	if err := prune(Config{DestDir: filepath.Join(t.TempDir(), "nope"), Keep: 1}); err == nil {
		t.Fatal("prune on a missing dir must error")
	}
	// prune with Keep<=0 is a no-op (nil)
	if err := prune(Config{DestDir: t.TempDir(), Keep: 0}); err != nil {
		t.Fatalf("prune keep<=0: %v", err)
	}
	// snapshotDB on a missing source
	if err := snapshotDB(context.Background(), filepath.Join(t.TempDir(), "missing.db"), filepath.Join(t.TempDir(), "o.db")); err == nil {
		t.Fatal("snapshotDB on a missing src must fail")
	}
}

func TestRunLogsSnapshotFailures(t *testing.T) {
	// Every>0 but a bad state dir: the boot snapshot AND the ticked snapshot both fail and are logged
	var logs int
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		Run(ctx, Config{StateDir: filepath.Join(t.TempDir(), "gone"), DestDir: t.TempDir(),
			Every: 5 * time.Millisecond, Log: func(string, ...any) { logs++ }})
		close(done)
	}()
	time.Sleep(60 * time.Millisecond) // let it tick a few times
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not stop")
	}
	if logs < 2 {
		t.Fatalf("expected repeated failure logs, got %d", logs)
	}
}

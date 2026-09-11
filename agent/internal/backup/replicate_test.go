package backup

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// siteA stands up a controller-side backup dir + an httptest server exposing the Link backup
// endpoints, exactly as the mTLS Link mounts them (plain HTTP here; mTLS is covered by the fleet test).
func siteA(t *testing.T) (dir string, base string) {
	t.Helper()
	dir = t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	makeLiveDB(t, filepath.Join(dir, "src", "registry.db"), 20) // src state dir
	// produce a couple of real archives from that state
	state := filepath.Join(dir, "src")
	for i := 0; i < 2; i++ {
		c := time.Date(2026, 7, 7, i, 0, 0, 0, time.UTC)
		if _, err := SnapshotOnce(context.Background(), Config{StateDir: state, DestDir: dir, Keep: 5, Now: func() time.Time { return c }}); err != nil {
			t.Fatal(err)
		}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/link/backup/manifest", ServeManifest(dir))
	mux.HandleFunc("/link/backup/latest", ServeLatest(dir))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return dir, srv.URL
}

func TestReplicatePullsAndVerifies(t *testing.T) {
	_, base := siteA(t)
	destB := t.TempDir()
	cfg := ReplicateConfig{PeerBase: base, DestDir: destB, Client: http.DefaultClient, Keep: 5}

	// first pull: fetches the newest archive
	got, err := ReplicateOnce(context.Background(), cfg)
	if err != nil || got == "" {
		t.Fatalf("first pull: err=%v path=%q", err, got)
	}
	// site B's copy is a valid, restorable archive: extract + open the db
	restore := t.TempDir()
	names := extract(t, got, restore)
	if len(names) == 0 {
		t.Fatal("pulled archive is empty")
	}
	// second pull: already up to date -> no new file
	if got2, err := ReplicateOnce(context.Background(), cfg); err != nil || got2 != "" {
		t.Fatalf("idempotent pull: err=%v path=%q (want no-op)", err, got2)
	}
}

func TestReplicateHashMismatchRejected(t *testing.T) {
	dirA := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dirA, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	makeLiveDB(t, filepath.Join(dirA, "src", "config.db"), 3)
	if _, err := SnapshotOnce(context.Background(), Config{StateDir: filepath.Join(dirA, "src"), DestDir: dirA, Keep: 5}); err != nil {
		t.Fatal(err)
	}
	latest, _ := LatestArchive(dirA)

	// a LYING server: manifest advertises a bogus hash, latest streams the real bytes -> mismatch
	m, _ := Manifest(dirA)
	m[len(m)-1].SHA256 = strings.Repeat("0", 64)
	mux := http.NewServeMux()
	mux.HandleFunc("/link/backup/manifest", func(rw http.ResponseWriter, _ *http.Request) {
		rw.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(rw).Encode(m)
	})
	mux.HandleFunc("/link/backup/latest", func(rw http.ResponseWriter, r *http.Request) {
		http.ServeFile(rw, r, latest)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	destB := t.TempDir()
	if _, err := ReplicateOnce(context.Background(), ReplicateConfig{PeerBase: srv.URL, DestDir: destB, Client: http.DefaultClient}); err == nil || !strings.Contains(err.Error(), "hash mismatch") {
		t.Fatalf("mismatch must be rejected, got %v", err)
	}
	// nothing installed (only the removed .part could linger)
	if files, _ := os.ReadDir(destB); len(files) != 0 {
		t.Fatalf("a rejected pull left files: %v", files)
	}
}

func TestReplicateErrors(t *testing.T) {
	ctx := context.Background()
	// missing config
	if _, err := ReplicateOnce(ctx, ReplicateConfig{}); err == nil {
		t.Fatal("missing config must error")
	}
	// unreachable peer
	if _, err := ReplicateOnce(ctx, ReplicateConfig{PeerBase: "http://127.0.0.1:1", DestDir: t.TempDir(), Client: http.DefaultClient}); err == nil {
		t.Fatal("unreachable peer must error")
	}
	// peer with no backups -> no-op, no error
	empty := httptest.NewServer(ServeManifest(t.TempDir()))
	defer empty.Close()
	if got, err := ReplicateOnce(ctx, ReplicateConfig{PeerBase: empty.URL, DestDir: t.TempDir(), Client: http.DefaultClient}); err != nil || got != "" {
		t.Fatalf("empty peer: err=%v got=%q", err, got)
	}
	// manifest 500
	bad := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) { rw.WriteHeader(500) }))
	defer bad.Close()
	if _, err := ReplicateOnce(ctx, ReplicateConfig{PeerBase: bad.URL, DestDir: t.TempDir(), Client: http.DefaultClient}); err == nil {
		t.Fatal("manifest 500 must error")
	}
	// manifest advertises an archive but /latest 404s
	dirA := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dirA, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	makeLiveDB(t, filepath.Join(dirA, "src", "audit.db"), 2)
	if _, err := SnapshotOnce(ctx, Config{StateDir: filepath.Join(dirA, "src"), DestDir: dirA, Keep: 5}); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/link/backup/manifest", ServeManifest(dirA))
	mux.HandleFunc("/link/backup/latest", func(rw http.ResponseWriter, _ *http.Request) { rw.WriteHeader(404) })
	part := httptest.NewServer(mux)
	defer part.Close()
	if _, err := ReplicateOnce(ctx, ReplicateConfig{PeerBase: part.URL, DestDir: t.TempDir(), Client: http.DefaultClient}); err == nil {
		t.Fatal("latest 404 must error")
	}
}

func TestServeAndManifestGuards(t *testing.T) {
	// Manifest / handlers on a missing dir
	if _, err := Manifest(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Fatal("manifest on a missing dir must error")
	}
	rec := httptest.NewRecorder()
	ServeManifest(filepath.Join(t.TempDir(), "nope"))(rec, httptest.NewRequest("GET", "/link/backup/manifest", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("manifest handler on missing dir: %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	ServeLatest(t.TempDir())(rec, httptest.NewRequest("GET", "/link/backup/latest", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("latest handler with no archive: %d", rec.Code)
	}
	// hashFile on a missing file
	if _, _, err := hashFile(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("hashFile on missing must error")
	}
}

func TestReplicateSchedulerStops(t *testing.T) {
	_, base := siteA(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		Replicate(ctx, ReplicateConfig{PeerBase: base, DestDir: t.TempDir(), Client: http.DefaultClient, Every: 5 * time.Millisecond, Keep: 3})
		close(done)
	}()
	time.Sleep(30 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Replicate did not stop")
	}
	Replicate(context.Background(), ReplicateConfig{Every: 0}) // no-op
}

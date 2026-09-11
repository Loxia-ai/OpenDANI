package backup

// Cross-site replication (PRODUCTION-READINESS P2, cloud-agnostic DR). "Cross-region" without a
// cloud means: a controller at SITE B continuously pulls SITE A's latest consistent backup over the
// mutual-TLS Link (which rides the DANI-coordinated WireGuard mesh between sites), verifies its
// hash, and keeps it locally. If site A is lost, site B restores from the last pulled snapshot — no
// cloud object store, no GRS, no third party.
//
// The transport is the same mTLS the fleet already uses, so only a peer holding a valid fleet
// identity can pull a backup (which contains sensitive state); the puller re-verifies the SHA-256 so
// a truncated or tampered transfer is rejected.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// ManifestEntry describes one available archive.
type ManifestEntry struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// Manifest lists the DANI archives in dir with their sizes and content hashes, newest last.
func Manifest(dir string) ([]ManifestEntry, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("backup manifest: %w", err)
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasPrefix(e.Name(), archivePrefix) && strings.HasSuffix(e.Name(), ".tar.gz") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	out := make([]ManifestEntry, 0, len(names))
	for _, n := range names {
		sum, size, err := hashFile(filepath.Join(dir, n))
		if err != nil {
			return nil, err
		}
		out = append(out, ManifestEntry{Name: n, Size: size, SHA256: sum})
	}
	return out, nil
}

// hashFile returns the hex SHA-256 and byte size of a file.
func hashFile(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, fmt.Errorf("backup hash: %w", err)
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, fmt.Errorf("backup hash: %w", err)
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// ReplicateConfig drives one replication puller.
type ReplicateConfig struct {
	PeerBase string           // the peer's Link base URL (e.g. https://site-a-ctrl:8444)
	DestDir  string           // where pulled archives are stored (site B's warm-standby dir)
	Client   *http.Client     // mTLS Link client (fleet identity)
	Every    time.Duration    // pull interval (0 = one-shot ReplicateOnce)
	Keep     int              // retention for pulled archives
	Now      func() time.Time // unused today; reserved
	Audit    func(string, map[string]any)
	Log      func(string, ...any)
}

func (c *ReplicateConfig) logf(f string, a ...any) {
	if c.Log != nil {
		c.Log(f, a...)
	}
}

// ReplicateOnce pulls the peer's newest archive if we don't already hold it (by name + hash),
// verifying the SHA-256 on arrival. Returns the local path if a new archive was stored, "" if we
// were already up to date.
func ReplicateOnce(ctx context.Context, cfg ReplicateConfig) (string, error) {
	if cfg.PeerBase == "" || cfg.DestDir == "" || cfg.Client == nil {
		return "", fmt.Errorf("replicate: PeerBase, DestDir and Client are required")
	}
	// fetch the peer manifest
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cfg.PeerBase+"/link/backup/manifest", nil)
	if err != nil {
		return "", fmt.Errorf("replicate: %w", err)
	}
	resp, err := cfg.Client.Do(req)
	if err != nil {
		return "", fmt.Errorf("replicate: manifest: %w", err)
	}
	var manifest []ManifestEntry
	dErr := json.NewDecoder(resp.Body).Decode(&manifest)
	code := resp.StatusCode
	resp.Body.Close()
	if code != http.StatusOK {
		return "", fmt.Errorf("replicate: manifest HTTP %d", code)
	}
	if dErr != nil {
		return "", fmt.Errorf("replicate: manifest decode: %w", dErr)
	}
	if len(manifest) == 0 {
		return "", nil // peer has no backups yet
	}
	latest := manifest[len(manifest)-1] // newest last

	if err := os.MkdirAll(cfg.DestDir, 0o750); err != nil {
		return "", fmt.Errorf("replicate: dest: %w", err)
	}
	local := filepath.Join(cfg.DestDir, latest.Name)
	if sum, _, err := hashFile(local); err == nil && sum == latest.SHA256 {
		return "", nil // already have this exact archive
	}

	// pull the latest archive bytes
	dreq, err := http.NewRequestWithContext(ctx, http.MethodGet, cfg.PeerBase+"/link/backup/latest", nil)
	if err != nil {
		return "", fmt.Errorf("replicate: %w", err)
	}
	dresp, err := cfg.Client.Do(dreq)
	if err != nil {
		return "", fmt.Errorf("replicate: fetch: %w", err)
	}
	defer dresp.Body.Close()
	if dresp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("replicate: fetch HTTP %d", dresp.StatusCode)
	}
	// stream to a temp file while hashing, then verify before the atomic rename
	tmp := local + ".part"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o640)
	if err != nil {
		return "", fmt.Errorf("replicate: temp: %w", err)
	}
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(f, h), dresp.Body); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return "", fmt.Errorf("replicate: copy: %w", err)
	}
	_ = f.Close()
	got := hex.EncodeToString(h.Sum(nil))
	if got != latest.SHA256 {
		_ = os.Remove(tmp)
		return "", fmt.Errorf("replicate: hash mismatch (got %s want %s) — refusing tampered/truncated archive", got[:12], latest.SHA256[:12])
	}
	if err := os.Rename(tmp, local); err != nil {
		_ = os.Remove(tmp)
		return "", fmt.Errorf("replicate: install: %w", err)
	}
	if cfg.Audit != nil {
		cfg.Audit("backup.replicated", map[string]any{"archive": latest.Name, "bytes": latest.Size, "from": cfg.PeerBase})
	}
	cfg.logf("replicate: pulled %s (%d bytes) from %s", latest.Name, latest.Size, cfg.PeerBase)
	if err := prune(Config{DestDir: cfg.DestDir, Keep: cfg.Keep}); err != nil {
		cfg.logf("replicate: prune: %v", err)
	}
	return local, nil
}

// Replicate runs ReplicateOnce every cfg.Every until ctx is done (fail-soft: a failed pull is logged
// and retried next tick — the last good snapshot stays put).
func Replicate(ctx context.Context, cfg ReplicateConfig) {
	if cfg.Every <= 0 {
		return
	}
	if _, err := ReplicateOnce(ctx, cfg); err != nil {
		cfg.logf("replicate: initial pull: %v", err)
	}
	t := time.NewTicker(cfg.Every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if _, err := ReplicateOnce(ctx, cfg); err != nil {
				cfg.logf("replicate: %v", err)
			}
		}
	}
}

// ServeManifest is an http.HandlerFunc serving the archive manifest for dir (mount on the mTLS Link).
func ServeManifest(dir string) http.HandlerFunc {
	return func(rw http.ResponseWriter, _ *http.Request) {
		m, err := Manifest(dir)
		if err != nil {
			http.Error(rw, "manifest unavailable", http.StatusInternalServerError)
			return
		}
		rw.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(rw).Encode(m)
	}
}

// ServeLatest is an http.HandlerFunc streaming the newest archive in dir (mount on the mTLS Link).
func ServeLatest(dir string) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		latest, err := LatestArchive(dir)
		if err != nil {
			http.Error(rw, "no backup available", http.StatusNotFound)
			return
		}
		rw.Header().Set("Content-Type", "application/gzip")
		http.ServeFile(rw, r, latest)
	}
}

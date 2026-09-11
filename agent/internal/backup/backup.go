// Package backup produces scheduled, consistent, retained snapshots of a controller's --state
// directory (PRODUCTION-READINESS P2, cloud-agnostic tier). DANI is meant to run in-perimeter on
// whatever hardware the customer has — there is no assumption of a managed cloud database or
// object store — so backup is a first-class agent capability, not an infra checkbox:
//
//   - CONSISTENT with NO downtime: every SQLite database (registry / audit / ingest / config) is
//     snapshotted with `VACUUM INTO`, which writes a transactionally-consistent single-file copy of
//     the LIVE database. No need to stop the controller, and the copy carries no -wal/-shm tail to
//     reconcile on restore.
//   - CLOUD-AGNOSTIC destination: archives are written to any path the operator chooses — a second
//     local disk, an NFS mount, or a peer-site volume reachable over the DANI mesh. No cloud API.
//   - RETAINED: the newest --backup-keep archives are kept; older ones are pruned.
//
// A restore is just: extract the tar.gz into a fresh --state dir and start a controller pointed at
// it — the same resume path the manual tool and the DR drill use.
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
	"sort"
	"strings"
	"time"

	_ "modernc.org/sqlite" // pure-Go SQLite (VACUUM INTO); no CGO
)

// Config drives the backup scheduler.
type Config struct {
	StateDir string           // the controller's --state directory
	DestDir  string           // where archives are written (any path — local/NFS/peer-site mount)
	Every    time.Duration    // snapshot interval (0 disables the scheduler; SnapshotOnce still works)
	Keep     int              // retain this many newest archives (<=0 => keep all)
	Now      func() time.Time // clock seam (tests)
	Audit    func(string, map[string]any)
	Log      func(string, ...any) // optional logger
}

func (c *Config) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c *Config) logf(format string, a ...any) {
	if c.Log != nil {
		c.Log(format, a...)
	}
}

// archivePrefix names DANI backups so pruning only ever touches our own files.
const archivePrefix = "dani-backup-"

// SnapshotOnce produces one consistent archive of the state dir, prunes to Keep, and returns the
// archive path. Safe to call while the controller is running.
func SnapshotOnce(ctx context.Context, cfg Config) (string, error) {
	if cfg.StateDir == "" || cfg.DestDir == "" {
		return "", fmt.Errorf("backup: StateDir and DestDir are required")
	}
	entries, err := os.ReadDir(cfg.StateDir)
	if err != nil {
		return "", fmt.Errorf("backup: read state dir: %w", err)
	}
	if err := os.MkdirAll(cfg.DestDir, 0o750); err != nil {
		return "", fmt.Errorf("backup: dest dir: %w", err)
	}
	stamp := cfg.now().UTC().Format("20060102T150405Z")
	archive := filepath.Join(cfg.DestDir, archivePrefix+stamp+".tar.gz")

	// stage consistent DB snapshots in a temp dir, then tar the state dir with DBs swapped for snaps.
	tmp, err := os.MkdirTemp("", "dani-bk-*")
	if err != nil {
		return "", fmt.Errorf("backup: temp: %w", err)
	}
	defer os.RemoveAll(tmp)

	type member struct{ name, src string } // src = path to include under archive name `name`
	var members []member
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		switch {
		case strings.HasSuffix(name, ".db"):
			snap := filepath.Join(tmp, name)
			if err := snapshotDB(ctx, filepath.Join(cfg.StateDir, name), snap); err != nil {
				return "", err
			}
			members = append(members, member{name, snap})
		case strings.HasSuffix(name, ".db-wal"), strings.HasSuffix(name, ".db-shm"):
			// intentionally skipped: the VACUUM INTO snapshot is a complete, checkpointed copy.
		case strings.HasSuffix(name, ".json"):
			members = append(members, member{name, filepath.Join(cfg.StateDir, name)})
		default:
			// other regular files (e.g. bundles) are copied verbatim.
			members = append(members, member{name, filepath.Join(cfg.StateDir, name)})
		}
	}
	if len(members) == 0 {
		return "", fmt.Errorf("backup: no DANI state files under %s", cfg.StateDir)
	}
	sort.Slice(members, func(i, j int) bool { return members[i].name < members[j].name })

	if err := writeArchive(archive, func(tw *tar.Writer) error {
		for _, m := range members {
			if err := addFile(tw, m.name, m.src); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		_ = os.Remove(archive)
		return "", err
	}

	if cfg.Audit != nil {
		if fi, err := os.Stat(archive); err == nil {
			cfg.Audit("backup.created", map[string]any{"archive": filepath.Base(archive), "bytes": fi.Size(), "files": len(members)})
		}
	}
	cfg.logf("backup: wrote %s (%d files)", archive, len(members))

	if err := prune(cfg); err != nil {
		cfg.logf("backup: prune: %v", err) // a failed prune must not fail the backup
	}
	return archive, nil
}

// snapshotDB writes a transactionally-consistent copy of a live SQLite DB via VACUUM INTO.
func snapshotDB(ctx context.Context, srcPath, destPath string) error {
	if _, err := os.Stat(srcPath); err != nil {
		return fmt.Errorf("backup: db %s: %w", srcPath, err)
	}
	_ = os.Remove(destPath) // VACUUM INTO refuses to overwrite an existing file
	db, err := sql.Open("sqlite", srcPath)
	if err != nil {
		return fmt.Errorf("backup: open %s: %w", srcPath, err)
	}
	defer db.Close()
	if _, err := db.ExecContext(ctx, `VACUUM INTO ?`, destPath); err != nil {
		return fmt.Errorf("backup: snapshot %s: %w", filepath.Base(srcPath), err)
	}
	return nil
}

// writeArchive creates a .tar.gz and runs fn to add members.
func writeArchive(path string, fn func(*tar.Writer) error) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o640)
	if err != nil {
		return fmt.Errorf("backup: create archive: %w", err)
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	if err := fn(tw); err != nil {
		_ = tw.Close()
		_ = gz.Close()
		_ = f.Close()
		return err
	}
	if err := tw.Close(); err != nil {
		_ = gz.Close()
		_ = f.Close()
		return fmt.Errorf("backup: tar close: %w", err)
	}
	if err := gz.Close(); err != nil {
		_ = f.Close()
		return fmt.Errorf("backup: gzip close: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("backup: archive close: %w", err)
	}
	return nil
}

// addFile writes one file into the tar under name.
func addFile(tw *tar.Writer, name, src string) error {
	f, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("backup: open %s: %w", name, err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return fmt.Errorf("backup: stat %s: %w", name, err)
	}
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: fi.Size(), ModTime: fi.ModTime()}); err != nil {
		return fmt.Errorf("backup: header %s: %w", name, err)
	}
	if _, err := io.Copy(tw, f); err != nil {
		return fmt.Errorf("backup: write %s: %w", name, err)
	}
	return nil
}

// prune keeps the newest cfg.Keep archives (by name, which sorts by timestamp) and removes older.
func prune(cfg Config) error {
	if cfg.Keep <= 0 {
		return nil
	}
	entries, err := os.ReadDir(cfg.DestDir)
	if err != nil {
		return err
	}
	var archives []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasPrefix(e.Name(), archivePrefix) && strings.HasSuffix(e.Name(), ".tar.gz") {
			archives = append(archives, e.Name())
		}
	}
	if len(archives) <= cfg.Keep {
		return nil
	}
	sort.Strings(archives) // oldest first
	for _, old := range archives[:len(archives)-cfg.Keep] {
		if err := os.Remove(filepath.Join(cfg.DestDir, old)); err != nil {
			return err
		}
		cfg.logf("backup: pruned %s", old)
	}
	return nil
}

// Run schedules SnapshotOnce every cfg.Every until ctx is done. A backup at boot seeds the first
// archive so a fresh deployment is protected immediately.
func Run(ctx context.Context, cfg Config) {
	if cfg.Every <= 0 {
		return
	}
	if _, err := SnapshotOnce(ctx, cfg); err != nil {
		cfg.logf("backup: initial snapshot failed: %v", err)
	}
	t := time.NewTicker(cfg.Every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if _, err := SnapshotOnce(ctx, cfg); err != nil {
				cfg.logf("backup: snapshot failed: %v", err)
			}
		}
	}
}

// LatestArchive returns the newest DANI archive in dir (restore convenience / tests).
func LatestArchive(dir string) (string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}
	var archives []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasPrefix(e.Name(), archivePrefix) && strings.HasSuffix(e.Name(), ".tar.gz") {
			archives = append(archives, e.Name())
		}
	}
	if len(archives) == 0 {
		return "", fmt.Errorf("backup: no archives in %s", dir)
	}
	sort.Strings(archives)
	return filepath.Join(dir, archives[len(archives)-1]), nil
}

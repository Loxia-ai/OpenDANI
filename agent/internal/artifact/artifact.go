// Package artifact is the Artifact Store (Architecture §6.21 #14, D44): a content-addressed byte
// store for model weights, LoRA adapters, and staged datasets.
//
// Content-addressing by SHA-256 with hash verification on read (verify-on-use, DP13): a blob's name
// IS its content hash, so identical bytes dedupe to one object and any corruption/tampering is caught
// on read. The BYTE storage is pluggable via Backend: a local filesystem (DEMO default) or an object
// store (Azure Blob) so every controller/worker in an HA deployment fetches the same artifact — the
// piece that lets a follower controller SERVE a Raft-replicated model, not just hold its metadata
// (ROADMAP §1, closes the D-18 note).
package artifact

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
)

// writeFile is a seam so tests can exercise the write-error branch (production: os.WriteFile).
var writeFile = os.WriteFile

// ErrHashMismatch is returned by Get when a stored blob no longer hashes to its address — a genuine
// integrity failure (bit-rot or tampering). Callers must treat the artifact as unusable.
var ErrHashMismatch = errors.New("artifact: hash mismatch (integrity failure)")

// Ref is a content-addressed handle to stored bytes.
type Ref struct {
	Hash string `json:"hash"` // "sha256:<hex>" — the content address
	Size int64  `json:"size"`
	Kind string `json:"kind"` // model | adapter | dataset
}

// Backend is the pluggable byte store beneath the content-addressing layer. name is the blob's hex
// digest (its content address). Implementations need not verify hashes — Store does that.
type Backend interface {
	Put(name string, data []byte) error
	Get(name string) ([]byte, error)
	Has(name string) bool
	// LocalPath returns (path, true) when name is a real local file an external process can read
	// directly (fs backend); (\"\", false) for remote backends, which Store materializes on demand.
	LocalPath(name string) (string, bool)
}

// Store layers content-addressing + verify-on-read over a Backend.
type Store struct {
	backend  Backend
	cacheDir string // local materialization dir for Path() when the backend is remote
}

// Open creates (if needed) a filesystem-backed Store rooted at dir (the DEMO default).
func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &Store{backend: &fsBackend{dir: dir}, cacheDir: dir}, nil
}

// OpenWith builds a Store over an arbitrary backend. cacheDir (if set) is where remote blobs are
// materialized for Path(); it is created if missing.
func OpenWith(b Backend, cacheDir string) (*Store, error) {
	if cacheDir != "" {
		if err := os.MkdirAll(cacheDir, 0o700); err != nil {
			return nil, err
		}
	}
	return &Store{backend: b, cacheDir: cacheDir}, nil
}

// HashOf returns the content address ("sha256:<hex>") of data.
func HashOf(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// hexName maps a content address to its backend object name (the bare hex digest).
func hexName(hash string) string {
	if i := len(hash) - 64; i >= 0 {
		return hash[i:]
	}
	return hash
}

// Put stores data content-addressed and returns its Ref. Identical bytes yield the same Ref and one
// stored object (dedup). kind is metadata carried on the Ref (model|adapter|dataset).
func (s *Store) Put(kind string, data []byte) (Ref, error) {
	h := HashOf(data)
	if err := s.backend.Put(hexName(h), data); err != nil {
		return Ref{}, err
	}
	return Ref{Hash: h, Size: int64(len(data)), Kind: kind}, nil
}

// Has reports whether a blob with the given content hash is stored.
func (s *Store) Has(hash string) bool { return s.backend.Has(hexName(hash)) }

// Path returns a LOCAL file path for a stored blob, for handing to an external process (e.g. a
// training script reads its staged dataset directly). For a local backend this is zero-copy; for a
// remote backend the blob is materialized into cacheDir first. Returns "" if it cannot be produced.
func (s *Store) Path(hash string) string {
	name := hexName(hash)
	if p, ok := s.backend.LocalPath(name); ok {
		return p
	}
	data, err := s.backend.Get(name)
	if err != nil {
		return ""
	}
	p := filepath.Join(s.cacheDir, name)
	if err := writeFile(p, data, 0o600); err != nil {
		return ""
	}
	return p
}

// Get reads a blob and verifies it still hashes to its address (verify-on-read, DP13). A mismatch
// returns ErrHashMismatch; a missing blob returns the underlying backend error.
func (s *Store) Get(hash string) ([]byte, error) {
	data, err := s.backend.Get(hexName(hash))
	if err != nil {
		return nil, err
	}
	if HashOf(data) != hash {
		return nil, ErrHashMismatch
	}
	return data, nil
}

// fsBackend is the local-filesystem Backend (DEMO default; single replica on the controller).
type fsBackend struct{ dir string }

func (f *fsBackend) path(name string) string { return filepath.Join(f.dir, name) }

func (f *fsBackend) Put(name string, data []byte) error { return writeFile(f.path(name), data, 0o600) }

func (f *fsBackend) Get(name string) ([]byte, error) { return os.ReadFile(f.path(name)) }

func (f *fsBackend) Has(name string) bool { _, err := os.Stat(f.path(name)); return err == nil }

func (f *fsBackend) LocalPath(name string) (string, bool) { return f.path(name), true }

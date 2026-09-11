package artifact

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestPutGetRoundTrip(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("lora-adapter-bytes")
	ref, err := s.Put("adapter", data)
	if err != nil {
		t.Fatal(err)
	}
	if ref.Kind != "adapter" || ref.Size != int64(len(data)) {
		t.Fatalf("bad ref %+v", ref)
	}
	if ref.Hash != HashOf(data) {
		t.Fatalf("hash %s != %s", ref.Hash, HashOf(data))
	}
	got, err := s.Get(ref.Hash)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(data) {
		t.Fatalf("round-trip mismatch: %q", got)
	}
	if !s.Has(ref.Hash) {
		t.Fatal("Has should be true after Put")
	}
	if s.Has(HashOf([]byte("never-stored"))) {
		t.Fatal("Has should be false for unknown")
	}
}

func TestDedup(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir)
	a, _ := s.Put("model", []byte("same"))
	b, _ := s.Put("model", []byte("same"))
	if a.Hash != b.Hash {
		t.Fatal("identical bytes must share a content address")
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("dedup: expected 1 on-disk object, got %d", len(entries))
	}
}

func TestGetUnknown(t *testing.T) {
	s, _ := Open(t.TempDir())
	if _, err := s.Get(HashOf([]byte("missing"))); err == nil {
		t.Fatal("expected error for missing blob")
	}
}

func TestGetHashMismatch(t *testing.T) {
	s, _ := Open(t.TempDir())
	ref, _ := s.Put("model", []byte("original"))
	// Corrupt the blob on disk without changing its filename (its content address).
	if err := os.WriteFile(s.Path(ref.Hash), []byte("tampered!"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := s.Get(ref.Hash)
	if !errors.Is(err, ErrHashMismatch) {
		t.Fatalf("expected ErrHashMismatch, got %v", err)
	}
}

func TestPutWriteError(t *testing.T) {
	s, _ := Open(t.TempDir())
	orig := writeFile
	defer func() { writeFile = orig }()
	writeFile = func(string, []byte, os.FileMode) error { return errors.New("disk full") }
	if _, err := s.Put("model", []byte("x")); err == nil {
		t.Fatal("expected write error to propagate")
	}
}

func TestOpenMkdirError(t *testing.T) {
	// Create a regular file, then try to Open a directory *under* it — MkdirAll must fail.
	f := filepath.Join(t.TempDir(), "afile")
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(filepath.Join(f, "sub")); err == nil {
		t.Fatal("expected MkdirAll error when parent is a file")
	}
}

func TestPathExposesStoredBlob(t *testing.T) {
	s, _ := Open(t.TempDir())
	ref, _ := s.Put("dataset", []byte(`{"chunks":[]}`))
	data, err := os.ReadFile(s.Path(ref.Hash))
	if err != nil || string(data) != `{"chunks":[]}` {
		t.Fatalf("Path must point at the stored blob: %v %q", err, data)
	}
}

func TestHexNamePrefixStripping(t *testing.T) {
	// A well-formed sha256: address maps to the bare 64-char hex digest.
	if got := hexName(HashOf([]byte("z"))); len(got) != 64 {
		t.Fatalf("expected 64-char hex name, got %q", got)
	}
	// A short/degenerate hash is used verbatim (no negative slice).
	if got := hexName("short"); got != "short" {
		t.Fatalf("short hash should pass through, got %q", got)
	}
}

package artifact

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
)

// blobMock is an in-memory stand-in for an Azure Blob container: PUT (BlockBlob) stores, GET reads,
// HEAD checks existence — the subset BlobBackend uses. It also asserts the SAS query rides along.
func blobMock(t *testing.T) (*httptest.Server, *sync.Map) {
	t.Helper()
	var store sync.Map
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawQuery == "" {
			t.Errorf("request missing SAS query: %s", r.URL)
		}
		name := strings.TrimPrefix(r.URL.Path, "/artifacts/")
		switch r.Method {
		case http.MethodPut:
			if r.Header.Get("x-ms-blob-type") != "BlockBlob" {
				w.WriteHeader(400)
				return
			}
			body := make([]byte, r.ContentLength)
			r.Body.Read(body)
			store.Store(name, body)
			w.WriteHeader(http.StatusCreated)
		case http.MethodGet:
			if v, ok := store.Load(name); ok {
				w.Write(v.([]byte))
			} else {
				w.WriteHeader(404)
			}
		case http.MethodHead:
			if _, ok := store.Load(name); ok {
				w.WriteHeader(200)
			} else {
				w.WriteHeader(404)
			}
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &store
}

func blobStore(t *testing.T, srv *httptest.Server) *Store {
	t.Helper()
	b := &BlobBackend{Client: srv.Client(), ContainerURL: srv.URL + "/artifacts", SAS: "sv=2023&sig=abc"}
	s, err := OpenWith(b, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// TestBlobRoundTrip: Put -> Has -> Get through the blob backend, with content-addressing + verify.
func TestBlobRoundTrip(t *testing.T) {
	srv, _ := blobMock(t)
	s := blobStore(t, srv)
	ref, err := s.Put("adapter", []byte("weights-bytes"))
	if err != nil {
		t.Fatal(err)
	}
	if !s.Has(ref.Hash) {
		t.Fatal("blob must exist after Put")
	}
	got, err := s.Get(ref.Hash)
	if err != nil || string(got) != "weights-bytes" {
		t.Fatalf("Get roundtrip: %v %q", err, got)
	}
	// Path materializes the remote blob locally (for an external reader) and it hashes back.
	p := s.Path(ref.Hash)
	if p == "" {
		t.Fatal("Path must materialize a remote blob")
	}
}

// TestBlobDedupAndMissing: identical bytes share an address; a missing blob errors + Has is false.
func TestBlobDedupAndMissing(t *testing.T) {
	srv, store := blobMock(t)
	s := blobStore(t, srv)
	a, _ := s.Put("model", []byte("same"))
	b, _ := s.Put("model", []byte("same"))
	if a.Hash != b.Hash {
		t.Fatal("identical bytes share a content address")
	}
	n := 0
	store.Range(func(_, _ any) bool { n++; return true })
	if n != 1 {
		t.Fatalf("dedup: expected 1 stored object, got %d", n)
	}
	if s.Has(HashOf([]byte("nope"))) {
		t.Fatal("missing blob must not exist")
	}
	if _, err := s.Get(HashOf([]byte("nope"))); err == nil {
		t.Fatal("missing blob Get must error")
	}
	if s.Path(HashOf([]byte("nope"))) != "" {
		t.Fatal("Path of a missing remote blob must be empty")
	}
}

// TestBlobTamperDetected: a blob whose stored bytes no longer match its address fails verify-on-read.
func TestBlobTamperDetected(t *testing.T) {
	srv, store := blobMock(t)
	s := blobStore(t, srv)
	ref, _ := s.Put("model", []byte("original"))
	store.Store(hexName(ref.Hash), []byte("tampered")) // corrupt in the "container"
	if _, err := s.Get(ref.Hash); err != ErrHashMismatch {
		t.Fatalf("tampered blob must fail verify-on-read, got %v", err)
	}
}

// TestBlobBackendErrors: transport + status error paths are surfaced.
func TestBlobBackendErrors(t *testing.T) {
	// unreachable endpoint
	down := &BlobBackend{ContainerURL: "http://127.0.0.1:1/c", SAS: "x=1"}
	if err := down.Put("n", []byte("d")); err == nil {
		t.Fatal("unreachable PUT must error")
	}
	if _, err := down.Get("n"); err == nil {
		t.Fatal("unreachable GET must error")
	}
	if down.Has("n") {
		t.Fatal("unreachable HEAD must be false")
	}
	// server returns non-2xx
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(403) }))
	defer bad.Close()
	rb := &BlobBackend{Client: bad.Client(), ContainerURL: bad.URL + "/c", SAS: "x=1"}
	if err := rb.Put("n", []byte("d")); err == nil {
		t.Fatal("403 PUT must error")
	}
	if _, err := rb.Get("n"); err == nil {
		t.Fatal("403 GET must error")
	}
	if rb.Has("n") {
		t.Fatal("403 HEAD must be false")
	}
	// nil client defaults
	if (&BlobBackend{ContainerURL: bad.URL + "/c", SAS: "x=1"}).Has("n") {
		t.Fatal("nil-client default path")
	}
	// LocalPath is never local
	if _, ok := (&BlobBackend{}).LocalPath("n"); ok {
		t.Fatal("blob LocalPath must be non-local")
	}
}

// TestOpenSpec: the store factory dispatches fs / azblob / errors.
func TestOpenSpec(t *testing.T) {
	dir := t.TempDir()
	for _, spec := range []string{"", "fs", "fs:", "fs:" + dir} {
		if _, err := OpenSpec(spec, dir); err != nil {
			t.Fatalf("fs spec %q: %v", spec, err)
		}
	}
	s, err := OpenSpec("azblob:https://acct.blob.core.windows.net/artifacts?sv=2023&sig=abc", dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s.backend.(*BlobBackend); !ok {
		t.Fatalf("azblob spec must yield a BlobBackend, got %T", s.backend)
	}
	for _, bad := range []string{"azblob:https://x/c", "azblob:noquery", "azblob:https://x/c?", "banana:foo"} {
		if _, err := OpenSpec(bad, dir); err == nil {
			t.Fatalf("bad spec %q must error", bad)
		}
	}
}

// TestOpenWithMkdirError: an uncreatable cache dir fails OpenWith.
func TestOpenWithMkdirError(t *testing.T) {
	f := t.TempDir() + "/afile"
	os.WriteFile(f, []byte("x"), 0o600)
	if _, err := OpenWith(&BlobBackend{}, f+"/sub"); err == nil {
		t.Fatal("cache dir under a file must fail")
	}
}

// TestPathMaterializeWriteError: a Path() that cannot write the local cache copy returns "".
func TestPathMaterializeWriteError(t *testing.T) {
	srv, _ := blobMock(t)
	s := blobStore(t, srv)
	ref, _ := s.Put("model", []byte("data"))
	orig := writeFile
	defer func() { writeFile = orig }()
	writeFile = func(string, []byte, os.FileMode) error { return errIO }
	if p := s.Path(ref.Hash); p != "" {
		t.Fatalf("Path must return empty on cache-write failure, got %q", p)
	}
}

// TestBlobNewRequestError: an un-parseable container URL fails at request build (before transport).
func TestBlobNewRequestError(t *testing.T) {
	b := &BlobBackend{ContainerURL: "http://\x7f bad", SAS: "x=1"}
	if err := b.Put("n", []byte("d")); err == nil {
		t.Fatal("bad URL PUT must error at build")
	}
	if _, err := b.Get("n"); err == nil {
		t.Fatal("bad URL GET must error at build")
	}
	if b.Has("n") {
		t.Fatal("bad URL HEAD must be false")
	}
}

var errIO = &os.PathError{Op: "write", Path: "x", Err: os.ErrPermission}

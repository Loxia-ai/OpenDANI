package main

// `dani-agent ingest` core: local extraction batches only TEXT out, doc ids carry the file path,
// the identity header rides along, and the gateway response is surfaced.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIngestCmdPushesExtractedDocs(t *testing.T) {
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "hr"), 0o755)
	os.WriteFile(filepath.Join(root, "hr", "policy.md"), []byte("Leave is 16 weeks."), 0o644)
	os.WriteFile(filepath.Join(root, "notes.html"), []byte("<p>Signatures required.</p>"), 0o644)
	os.WriteFile(filepath.Join(root, "logo.png"), []byte("\x89PNG"), 0o644) // unsupported → skipped

	var got struct {
		Collection     string   `json:"collection"`
		Docs           []string `json:"docs"`
		Classification string   `json:"classification"`
	}
	var user string
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		user = r.Header.Get("X-Dani-User")
		_ = json.NewDecoder(r.Body).Decode(&got)
		rw.Write([]byte(`{"name":"team","chunks":[{},{}]}`))
	}))
	defer srv.Close()

	cmdIngest([]string{"--path", root, "--collection", "team", "--class", "restricted", "--gateway", srv.URL, "--user", "dana"})

	if got.Collection != "team" || got.Classification != "restricted" || user != "dana" {
		t.Fatalf("request: %+v user=%q", got, user)
	}
	if len(got.Docs) != 2 {
		t.Fatalf("docs = %d, want 2 (png skipped): %v", len(got.Docs), got.Docs)
	}
	joined := strings.Join(got.Docs, "|")
	if !strings.Contains(joined, "FILE: hr/policy.md") || !strings.Contains(joined, "Leave is 16 weeks.") {
		t.Fatalf("md doc lost lineage/text: %q", joined)
	}
	if !strings.Contains(joined, "FILE: notes.html") || !strings.Contains(joined, "Signatures required.") {
		t.Fatalf("html not extracted: %q", joined)
	}
	if strings.Contains(joined, "<p>") {
		t.Fatalf("raw html leaked: %q", joined)
	}
}

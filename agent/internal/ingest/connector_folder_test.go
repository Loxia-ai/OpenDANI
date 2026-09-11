package ingest

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func writeFile(t *testing.T, root, rel, content string) {
	t.Helper()
	full := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestFolderConnectorSync(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "hr/leave-policy.md", "Parental leave is 16 weeks.")
	writeFile(t, root, "finance/budget.txt", "The Q3 budget is confidential.")
	writeFile(t, root, "readme.txt", "General notes.")
	writeFile(t, root, "logo.png", "\x89PNG binary")           // unsupported → ignored
	writeFile(t, root, ".hidden/secret.txt", "dot dir")       // hidden dir → skipped
	writeFile(t, root, "web/page.html", "<p>Cap applies</p>") // extraction path

	c := &FolderConnector{Root: root, ClassMap: map[string]string{"hr/": "internal", "finance/": "restricted"}, DefaultClass: "internal"}
	changed, gone, cursor, err := c.Sync(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(changed) != 4 || len(gone) != 0 {
		t.Fatalf("first sync: %d changed %d gone, want 4/0 (%+v)", len(changed), len(gone), ids(changed))
	}
	byID := map[string]ConnectorDoc{}
	for _, d := range changed {
		byID[d.ID] = d
	}
	if byID["finance/budget.txt"].SrcClass != "restricted" || byID["hr/leave-policy.md"].SrcClass != "internal" {
		t.Fatalf("classmap floors wrong: %+v", byID)
	}
	if byID["web/page.html"].Format != "html" || byID["web/page.html"].Text != "Cap applies" {
		t.Fatalf("html extraction: %+v", byID["web/page.html"])
	}

	// second sync with nothing changed → all incremental, nothing re-read
	changed, gone, cursor2, err := c.Sync(context.Background(), cursor)
	if err != nil || len(changed) != 0 || len(gone) != 0 {
		t.Fatalf("no-op sync: %d/%d %v", len(changed), len(gone), err)
	}

	// change one, delete one, add one
	writeFile(t, root, "hr/leave-policy.md", "Parental leave is 20 weeks.") // changed
	os.Remove(filepath.Join(root, "readme.txt"))                           // gone
	writeFile(t, root, "hr/new-hire.md", "Onboarding checklist.")          // new
	changed, gone, _, err = c.Sync(context.Background(), cursor2)
	if err != nil {
		t.Fatal(err)
	}
	if len(changed) != 2 || len(gone) != 1 || gone[0] != "readme.txt" {
		t.Fatalf("delta sync: changed=%v gone=%v", ids(changed), gone)
	}
}

func TestFolderConnectorIntoSubsystem(t *testing.T) {
	// the full path: register → sync → classified, chunked, retrievable collection
	root := t.TempDir()
	writeFile(t, root, "legal/msa.txt", "Liability caps are set by the master agreement. Indemnity survives.")
	s := New()
	c := &FolderConnector{Root: root, DefaultClass: "restricted"}
	if err := s.RegisterConnector("shared-drive", c); err != nil {
		t.Fatal(err)
	}
	nChanged, nGone, col, err := s.SyncConnector(context.Background(), "shared-drive")
	if err != nil || nChanged != 1 || nGone != 0 {
		t.Fatalf("sync: %d/%d %v", nChanged, nGone, err)
	}
	if col.Connector != "folder" || len(col.Chunks) < 1 {
		t.Fatalf("collection: connector=%q chunks=%d", col.Connector, len(col.Chunks))
	}
	for _, ch := range col.Chunks {
		if ch.Classification != "restricted" {
			t.Fatalf("chunk class = %q, want restricted floor", ch.Classification)
		}
	}
	// retrieval works over the synced collection (ceiling filters apply as usual)
	hits, err := s.Retrieve("shared-drive", "liability caps", 3, "restricted")
	if err != nil || len(hits) == 0 {
		t.Fatalf("retrieval over the folder collection returned nothing (%v)", err)
	}
	if none, err := s.Retrieve("shared-drive", "liability caps", 3, "unrestricted"); err != nil || len(none) != 0 {
		t.Fatalf("unrestricted ceiling must filter restricted chunks, got %d (%v)", len(none), err)
	}
}

func ids(docs []ConnectorDoc) []string {
	out := make([]string, len(docs))
	for i, d := range docs {
		out[i] = d.ID
	}
	return out
}

package ingest

// "Connect a source" lifecycle: validate → connect (register + persist + first sync) → status →
// disconnect (data gone) → rehydrate across a restart. Plus the dry-run Probe and redaction.

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func waitSynced(t *testing.T, s *Subsystem, collection string, wantChunks bool) ConnectorStatus {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		for _, st := range s.ListConnectors() {
			if st.Def.Collection == collection && !st.LastSync.IsZero() && !st.Syncing {
				if !wantChunks || st.Chunks > 0 {
					return st
				}
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("connector %q never finished its first sync", collection)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func TestConnectorDefValidate(t *testing.T) {
	bad := []ConnectorDef{
		{Kind: "folder", Collection: "x"},                          // no path
		{Kind: "git", Collection: "x"},                             // no url
		{Kind: "azblob", Collection: "x", URL: "https://a"},        // no SAS
		{Kind: "ftp", Collection: "x"},                             // unknown kind
		{Kind: "folder", Path: "/tmp"},                             // no collection
		{Kind: "folder", Collection: "x", Path: "/tmp", ClassMap: map[string]string{"a/": "topsecret"}}, // bad class
	}
	for i, d := range bad {
		if err := d.Validate(); err == nil {
			t.Errorf("case %d (%+v) must fail validation", i, d)
		}
	}
	ok := ConnectorDef{Kind: "folder", Collection: "x", Path: "/tmp", ClassMap: map[string]string{"hr/": "internal"}}
	if err := ok.Validate(); err != nil {
		t.Errorf("valid def refused: %v", err)
	}
}

func TestConnectAndDisconnectLifecycle(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "policy.md", "Deployments require signatures. The gate must pass.")
	s := New()

	def := ConnectorDef{Kind: "folder", Collection: "team-drive", Path: root, DefaultClass: "internal"}
	if err := s.StartConnector(context.Background(), def); err != nil {
		t.Fatal(err)
	}
	st := waitSynced(t, s, "team-drive", true)
	if st.Docs != 1 || st.Chunks < 1 || st.LastError != "" {
		t.Fatalf("status after first sync: %+v", st)
	}
	// duplicate collection refused
	if err := s.StartConnector(context.Background(), def); err == nil {
		t.Fatal("duplicate connect must fail")
	}
	// disconnect removes the connector AND the collection
	if err := s.RemoveConnector(context.Background(), "team-drive"); err != nil {
		t.Fatal(err)
	}
	if len(s.ListConnectors()) != 0 {
		t.Fatal("connector still listed after disconnect")
	}
	if _, err := s.Retrieve("team-drive", "signatures", 3, "secret"); err == nil {
		t.Fatal("collection must be gone after disconnect")
	}
	// disconnecting a static (flag) connector is refused
	if err := s.StartConnector(context.Background(), ConnectorDef{Kind: "folder", Collection: "flagged", Path: root, Static: true}); err != nil {
		t.Fatal(err)
	}
	if err := s.RemoveConnector(context.Background(), "flagged"); err == nil {
		t.Fatal("static connector removal must be refused")
	}
}

func TestConnectorPersistsAcrossRestart(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "notes.md", "The runbook says restart the hub first.")
	dsn := filepath.Join(t.TempDir(), "ingest.db")

	// first life: connect through the API path (persisted)
	st1, err := OpenStore(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	s1 := New()
	if _, err := s1.WithStore(context.Background(), st1); err != nil {
		t.Fatal(err)
	}
	if err := s1.StartConnector(context.Background(), ConnectorDef{Kind: "folder", Collection: "drive", Path: root}); err != nil {
		t.Fatal(err)
	}
	waitSynced(t, s1, "drive", true)
	_ = st1.Close()

	// second life: rehydrate → the def comes back, resumes its cursor, chunks intact
	st2, err := OpenStore(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer st2.Close()
	s2 := New()
	if _, err := s2.WithStore(context.Background(), st2); err != nil {
		t.Fatal(err)
	}
	n, err := s2.RehydrateConnectors(context.Background())
	if err != nil || n != 1 {
		t.Fatalf("rehydrate: n=%d err=%v", n, err)
	}
	st := waitSynced(t, s2, "drive", true)
	if st.Def.Kind != "folder" || st.Chunks == 0 {
		t.Fatalf("rehydrated status: %+v", st)
	}
	// the incremental cursor survived: the sync after restart re-read nothing
	if st.LastChanged != 0 {
		t.Fatalf("restart sync must be incremental, re-read %d docs", st.LastChanged)
	}
}

func TestRedactionAndProbe(t *testing.T) {
	s := New()
	// a secret never leaves through the list
	root := t.TempDir()
	writeFile(t, root, "a.txt", "text")
	if err := s.StartConnector(context.Background(), ConnectorDef{Kind: "git", Collection: "repo", URL: root, Secret: "tok-supersecret"}); err != nil {
		t.Fatal(err)
	}
	for _, st := range s.ListConnectors() {
		if st.Def.Secret == "tok-supersecret" {
			t.Fatal("secret leaked through ListConnectors")
		}
	}
	// probe: folder counts supported files; a missing dir is a clean error
	files, detail, err := s.Probe(context.Background(), ConnectorDef{Kind: "folder", Collection: "p", Path: root})
	if err != nil || files != 1 || detail == "" {
		t.Fatalf("probe folder: %d %q %v", files, detail, err)
	}
	if _, _, err := s.Probe(context.Background(), ConnectorDef{Kind: "folder", Collection: "p", Path: filepath.Join(root, "missing")}); err == nil {
		t.Fatal("probe of a missing dir must fail")
	}
}

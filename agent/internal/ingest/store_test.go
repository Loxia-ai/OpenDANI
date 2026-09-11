package ingest

// P1-1 durability tests: the whole point is RESTART SURVIVAL, so every test here builds a subsystem,
// writes, then builds a SECOND subsystem on the same DB file and asserts the data (chunks, structured
// messages/tools, and byte-identical embeddings) came back.

import (
	"context"
	"path/filepath"
	"testing"
)

func openTestStore(t *testing.T) (*Store, string) {
	t.Helper()
	dsn := filepath.Join(t.TempDir(), "ingest.db")
	st, err := OpenStore(context.Background(), dsn)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st, dsn
}

// reopen simulates a controller restart: a FRESH subsystem rehydrated from the same DB.
func reopen(t *testing.T, dsn string) *Subsystem {
	t.Helper()
	st, err := OpenStore(context.Background(), dsn)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	s, err := New().WithStore(context.Background(), st)
	if err != nil {
		t.Fatalf("WithStore: %v", err)
	}
	return s
}

func TestCollectionSurvivesRestart(t *testing.T) {
	st, dsn := openTestStore(t)
	s, err := New().WithStore(context.Background(), st)
	if err != nil {
		t.Fatalf("WithStore: %v", err)
	}
	col, err := s.Ingest("legal")
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if len(col.Chunks) == 0 || col.Chunks[0].Vec == nil {
		t.Fatalf("ingest produced no embedded chunks")
	}

	s2 := reopen(t, dsn)
	got, ok := s2.Collection("legal")
	if !ok {
		t.Fatalf("collection did not survive restart")
	}
	if got.Connector != col.Connector || len(got.Chunks) != len(col.Chunks) {
		t.Fatalf("rehydrated collection differs: %d chunks vs %d", len(got.Chunks), len(col.Chunks))
	}
	for i, ch := range got.Chunks {
		want := col.Chunks[i]
		if ch.ID != want.ID || ch.DocID != want.DocID || ch.Text != want.Text ||
			ch.Classification != want.Classification || ch.Source != want.Source || ch.Format != want.Format {
			t.Fatalf("chunk %d differs after restart: %+v vs %+v", i, ch, want)
		}
		if len(ch.Vec) != len(want.Vec) {
			t.Fatalf("chunk %d embedding length differs: %d vs %d", i, len(ch.Vec), len(want.Vec))
		}
		for j := range ch.Vec {
			if ch.Vec[j] != want.Vec[j] { // byte-identical restore — NO re-embed on boot
				t.Fatalf("chunk %d vec[%d] differs: %v vs %v", i, j, ch.Vec[j], want.Vec[j])
			}
		}
	}
}

func TestRetrieveWorksAfterRestartWithoutEmbeddingChunks(t *testing.T) {
	st, dsn := openTestStore(t)
	s, err := New().WithStore(context.Background(), st)
	if err != nil {
		t.Fatalf("WithStore: %v", err)
	}
	if _, err := s.Ingest("hr"); err != nil {
		t.Fatalf("Ingest: %v", err)
	}

	s2 := reopen(t, dsn)
	hits, err := s2.Retrieve("hr", "parental leave weeks", 3, "secret")
	if err != nil {
		t.Fatalf("Retrieve after restart: %v", err)
	}
	if len(hits) == 0 {
		t.Fatalf("no hits after restart — persisted index unusable")
	}
	found := false
	for _, h := range hits {
		if h.DocID == "hr/doc-3" { // the parental-leave doc
			found = true
		}
	}
	if !found {
		t.Fatalf("expected the parental-leave chunk in hits, got %+v", hits)
	}
}

func TestCustomCorpusAndStructuredExamplesSurviveRestart(t *testing.T) {
	st, dsn := openTestStore(t)
	s, err := New().WithStore(context.Background(), st)
	if err != nil {
		t.Fatalf("WithStore: %v", err)
	}
	docs := []string{
		"plain fact about the product",
		`{"prompt":"What is DANI?","completion":"An in-perimeter AI network."}`,
		`{"messages":[{"role":"user","content":"check revenue"},{"role":"assistant","tool_calls":[{"function":{"name":"lookup","arguments":"{\"q\":1}"}}]}],"tools":[{"type":"function","function":{"name":"lookup"}}]}`,
	}
	if _, err := s.AddCustom("acme", docs, "internal"); err != nil {
		t.Fatalf("AddCustom: %v", err)
	}
	if _, err := s.Ingest("acme"); err != nil {
		t.Fatalf("Ingest custom: %v", err)
	}

	s2 := reopen(t, dsn)
	// the uploaded corpus itself survives (re-ingestable) ...
	names := s2.AvailableCorpora()
	found := false
	for _, n := range names {
		if n == "acme" {
			found = true
		}
	}
	if !found {
		t.Fatalf("custom corpus lost on restart: %v", names)
	}
	// ... and the ingested collection carries the structured payloads through the restart.
	col, ok := s2.Collection("acme")
	if !ok {
		t.Fatalf("custom collection lost on restart")
	}
	var chat, tool int
	for _, ch := range col.Chunks {
		if ch.Format == "chat" {
			chat++
			if len(ch.Messages) == 0 {
				t.Fatalf("chat chunk lost its messages: %+v", ch)
			}
		}
		if len(ch.Tools) > 0 {
			tool++
		}
	}
	if chat != 2 || tool != 1 {
		t.Fatalf("structured examples corrupted after restart: chat=%d tool=%d", chat, tool)
	}
	// re-ingesting the SURVIVED corpus works (fresh embeddings, replace-all row semantics)
	if _, err := s2.Ingest("acme"); err != nil {
		t.Fatalf("re-Ingest after restart: %v", err)
	}
}

func TestReIngestReplacesRows(t *testing.T) {
	st, dsn := openTestStore(t)
	s, err := New().WithStore(context.Background(), st)
	if err != nil {
		t.Fatalf("WithStore: %v", err)
	}
	if _, err := s.AddCustom("v", []string{"one"}, "internal"); err != nil {
		t.Fatalf("AddCustom: %v", err)
	}
	if _, err := s.Ingest("v"); err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	// replace the corpus with a bigger one and re-ingest — no stale rows may remain
	if _, err := s.AddCustom("v", []string{"one", "two"}, "internal"); err != nil {
		t.Fatalf("AddCustom v2: %v", err)
	}
	if _, err := s.Ingest("v"); err != nil {
		t.Fatalf("re-Ingest: %v", err)
	}
	s2 := reopen(t, dsn)
	col, ok := s2.Collection("v")
	if !ok || len(col.Chunks) != 2 {
		t.Fatalf("replace-all failed: ok=%v chunks=%d (want 2)", ok, len(col.Chunks))
	}
}

func TestUploadRefusedWhenStoreClosed(t *testing.T) {
	st, _ := openTestStore(t)
	s, err := New().WithStore(context.Background(), st)
	if err != nil {
		t.Fatalf("WithStore: %v", err)
	}
	_ = st.Close()
	// durable-first: with the store broken, the upload must FAIL (not silently stay in-memory)
	if _, err := s.AddCustom("ghost", []string{"doc"}, "internal"); err == nil {
		t.Fatalf("AddCustom succeeded with a closed store — durability contract broken")
	}
	if _, err := s.Ingest("legal"); err == nil {
		t.Fatalf("Ingest succeeded with a closed store — durability contract broken")
	}
}

func TestOpenStoreErrors(t *testing.T) {
	// unreachable postgres fails at Open (dbx pings)
	if _, err := OpenStore(context.Background(), "postgres://u:p@127.0.0.1:1/db"); err == nil {
		t.Fatalf("OpenStore succeeded against an unreachable postgres")
	}
	// unwritable sqlite path fails at schema/open
	if _, err := OpenStore(context.Background(), filepath.Join(t.TempDir(), "no", "such", "dir", "x.db")); err == nil {
		t.Fatalf("OpenStore succeeded on an unwritable path")
	}
}

func TestWithStoreLoadError(t *testing.T) {
	st, _ := openTestStore(t)
	_ = st.Close()
	if _, err := New().WithStore(context.Background(), st); err == nil {
		t.Fatalf("WithStore succeeded on a closed store")
	}
}

func TestVecCodecRoundTripAndCorruptTail(t *testing.T) {
	v := []float32{1.5, -2.25, 0, 3.14159}
	b := encodeVec(v)
	got := decodeVec(b)
	if len(got) != len(v) {
		t.Fatalf("roundtrip length %d != %d", len(got), len(v))
	}
	for i := range v {
		if got[i] != v[i] {
			t.Fatalf("roundtrip [%d] %v != %v", i, got[i], v[i])
		}
	}
	if encodeVec(nil) != nil {
		t.Fatalf("encodeVec(nil) should be nil")
	}
	if decodeVec(nil) != nil {
		t.Fatalf("decodeVec(nil) should be nil")
	}
	// a corrupt trailing partial word truncates, never panics
	if got := decodeVec(b[:len(b)-2]); len(got) != len(v)-1 {
		t.Fatalf("corrupt tail: want %d floats, got %d", len(v)-1, len(got))
	}
}

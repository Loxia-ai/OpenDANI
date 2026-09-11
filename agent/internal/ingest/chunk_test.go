package ingest

// Structure-aware chunking + hybrid retrieval + incremental embedding — the legal-RAG upgrade.

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

func TestSplitSentencesSafeLegalAbbreviations(t *testing.T) {
	text := "The holding in Roe v. Wade governs. See 42 U.S.C. § 1983 for the cause of action. " +
		"Acme Inc. filed on 1.2 grounds. This is a second sentence."
	got := splitSentencesSafe(text)
	if len(got) != 4 {
		t.Fatalf("want 4 sentences, got %d: %q", len(got), got)
	}
	if !strings.Contains(got[0], "v. Wade") {
		t.Fatalf("split broke 'v.': %q", got[0])
	}
	if !strings.Contains(got[1], "U.S.C. § 1983") {
		t.Fatalf("split broke 'U.S.C.': %q", got[1])
	}
	if !strings.Contains(got[2], "Inc. filed") {
		t.Fatalf("split broke 'Inc.': %q", got[2])
	}
}

func TestChunkDocBoundsOverlapAndSections(t *testing.T) {
	var b strings.Builder
	b.WriteString("title: MASTER SERVICES AGREEMENT\n")
	b.WriteString("ARTICLE I DEFINITIONS\n")
	for i := 0; i < 120; i++ {
		fmt.Fprintf(&b, "Definition clause number %d covers a defined term used throughout this agreement. ", i)
	}
	b.WriteString("\n12.3 Termination\n")
	b.WriteString("Either party may terminate this agreement upon thirty days written notice. ")
	b.WriteString("Termination for cause requires a material breach that remains uncured.\n")
	chunks := chunkDoc("CUAD-0001", b.String())
	if len(chunks) < 3 {
		t.Fatalf("long doc should split into several chunks, got %d", len(chunks))
	}
	for i, c := range chunks {
		if w := len(strings.Fields(c.Text)); w > chunkMaxWords+chunkOverlapWords+24 {
			t.Fatalf("chunk %d exceeds budget: %d words", i, w)
		}
		if !strings.HasPrefix(c.Text, "[CUAD-0001") {
			t.Fatalf("chunk %d missing context header: %q", i, c.Text[:60])
		}
	}
	last := chunks[len(chunks)-1]
	if !strings.Contains(last.Section, "12.3") {
		t.Fatalf("termination chunk should carry its section anchor, got %q", last.Section)
	}
	if !strings.Contains(last.Text, "thirty days") {
		t.Fatalf("termination clause lost: %q", last.Text)
	}
	// overlap: an intra-section CONTINUATION chunk starts with the previous chunk's tail (a chunk
	// opened by a section break correctly gets none — the heading is its context)
	overlapped := 0
	for _, c := range chunks {
		if strings.Contains(c.Text, "\n… ") {
			overlapped++
		}
	}
	if overlapped == 0 {
		t.Fatalf("no continuation chunk carries an overlap tail (chunks=%d)", len(chunks))
	}
}

func TestChunkDocTinyAndEmpty(t *testing.T) {
	if got := chunkDoc("D-1", "   \n  "); got != nil {
		t.Fatalf("empty doc must yield no chunks, got %d", len(got))
	}
	got := chunkDoc("D-1", "One short line.")
	if len(got) != 1 || !strings.Contains(got[0].Text, "One short line.") {
		t.Fatalf("tiny doc must yield exactly its one chunk: %+v", got)
	}
}

func TestHybridRetrievalExactTermBeatsBoWCollisions(t *testing.T) {
	s := New()
	docs := map[string]ConnectorDoc{}
	// 40 filler sections + one gold section holding a distinctive term and section number
	for i := 0; i < 40; i++ {
		docs[fmt.Sprintf("CFR-%d", i)] = ConnectorDoc{
			ID:   fmt.Sprintf("CFR-%d", i),
			Text: fmt.Sprintf("title: Section %d\nGeneral administrative requirements apply to covered entities under this part number %d.", i, i),
		}
	}
	docs["CFR-164.312"] = ConnectorDoc{
		ID:   "CFR-164.312",
		Text: "title: 164.312 Technical safeguards\nA covered entity must implement audit controls that record and examine activity in information systems containing electronic protected health information.",
	}
	if err := s.RegisterConnector("cfr", &fakeMapConnector{docs: docs}); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := s.SyncConnector(t.Context(), "cfr"); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"sparse", "hybrid"} {
		hits, err := s.RetrieveMode("cfr", "audit controls for electronic protected health information 164.312", 3, "secret", mode)
		if err != nil {
			t.Fatal(err)
		}
		if len(hits) == 0 || hits[0].DocID != "cfr/CFR-164.312" {
			t.Fatalf("%s: gold section must rank first, got %+v", mode, hits)
		}
	}
	// ceiling still enforced in every mode
	s.mu.Lock()
	col := s.collections["cfr"]
	for i := range col.Chunks {
		col.Chunks[i].Classification = "secret"
	}
	s.collections["cfr"] = col
	s.mu.Unlock()
	hits, err := s.RetrieveMode("cfr", "audit controls", 3, "internal", "hybrid")
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) != 0 {
		t.Fatalf("clearance ceiling must hide secret chunks in hybrid mode, got %d hits", len(hits))
	}
}

// countingEmbedder wraps BoW and counts how many texts were embedded — proves incrementality.
type countingEmbedder struct {
	n int
}

func (c *countingEmbedder) Embed(texts []string) ([][]float32, error) {
	c.n += len(texts)
	return BoWEmbedder{}.Embed(texts)
}

// fakeMapConnector serves a fixed doc map (test connector).
type fakeMapConnector struct {
	docs map[string]ConnectorDoc
}

func (f *fakeMapConnector) Name() string { return "fake" }
func (f *fakeMapConnector) Sync(_ context.Context, _ map[string]string) ([]ConnectorDoc, []string, map[string]string, error) {
	var out []ConnectorDoc
	for _, d := range f.docs {
		out = append(out, d)
	}
	return out, nil, map[string]string{}, nil
}

func TestIncrementalEmbeddingOnlyChangedChunks(t *testing.T) {
	ce := &countingEmbedder{}
	s := New().WithEmbedder(ce)
	docs := map[string]ConnectorDoc{
		"a": {ID: "a", Text: "alpha document body with several words of content here"},
		"b": {ID: "b", Text: "bravo document body with several words of content here"},
	}
	conn := &fakeMapConnector{docs: docs}
	if err := s.RegisterConnector("inc", conn); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := s.SyncConnector(t.Context(), "inc"); err != nil {
		t.Fatal(err)
	}
	first := ce.n
	if first == 0 {
		t.Fatal("first sync must embed something")
	}
	// second sync, nothing changed → only the dimension probe (1 embed), not a full re-embed
	if _, _, _, err := s.SyncConnector(t.Context(), "inc"); err != nil {
		t.Fatal(err)
	}
	if ce.n != first+1 {
		t.Fatalf("unchanged sync must cost exactly the 1-text dim probe, embedded %d more", ce.n-first)
	}
	// change one doc → only its chunks re-embed (plus nothing else)
	docs["b"] = ConnectorDoc{ID: "b", Text: "bravo document body has CHANGED with different words now"}
	before := ce.n
	if _, _, _, err := s.SyncConnector(t.Context(), "inc"); err != nil {
		t.Fatal(err)
	}
	delta := ce.n - before
	if delta < 1 || delta > 2 {
		t.Fatalf("changed-doc sync should embed only b's chunk(s), embedded %d", delta)
	}
}
func TestClassifyTradeSecretCarveOut(t *testing.T) {
	if got := classify("Each party shall protect the other's trade secrets and confidential information.", "internal"); got != "internal" {
		t.Fatalf("'trade secrets' boilerplate must not raise, got %q", got)
	}
	if got := classify("This document is classified secret by the security office.", "internal"); got != "secret" {
		t.Fatalf("real secret marker must still raise, got %q", got)
	}
}

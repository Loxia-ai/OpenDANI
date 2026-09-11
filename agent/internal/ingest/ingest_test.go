package ingest

import "testing"

func TestIngestLegal(t *testing.T) {
	s := New()
	col, err := s.Ingest("legal")
	if err != nil {
		t.Fatal(err)
	}
	if col.Connector != "confluence" || len(col.Chunks) == 0 {
		t.Fatalf("bad collection %+v", col)
	}
	// Every legal chunk is at least the source-mapped restricted; lineage points at its doc.
	for _, c := range col.Chunks {
		if c.Classification != "restricted" && c.Classification != "secret" {
			t.Fatalf("chunk %s classified %s (below source class)", c.ID, c.Classification)
		}
		if c.DocID == "" || c.Source != "confluence" {
			t.Fatalf("lineage missing on %+v", c)
		}
	}
	got, ok := s.Collection("legal")
	if !ok || got.Name != "legal" {
		t.Fatal("Collection lookup failed")
	}
	if _, ok := s.Collection("nope"); ok {
		t.Fatal("unknown collection must miss")
	}
}

func TestIngestUnknownCorpus(t *testing.T) {
	s := New()
	if _, err := s.Ingest("area51"); err == nil {
		t.Fatal("unknown corpus must error")
	}
}

func TestClassifyBumps(t *testing.T) {
	// content scan can only raise, never lower (§6.17.9 step 5: max of source + content)
	if c := classify("the launch codes are classified", "internal"); c != "secret" {
		t.Fatalf("secret bump failed: %s", c)
	}
	if c := classify("quarterly revenue and risk report", "unrestricted"); c != "restricted" {
		t.Fatalf("restricted bump failed: %s", c)
	}
	if c := classify("nothing sensitive here", "internal"); c != "internal" {
		t.Fatalf("no-bump case wrong: %s", c)
	}
	if c := classify("mentions revenue", "secret"); c != "secret" {
		t.Fatalf("content scan must not lower a secret source: %s", c)
	}
	if rank("bogus") != 1 {
		t.Fatal("unknown class ranks as internal")
	}
}

func TestListAndCorpora(t *testing.T) {
	s := New()
	s.Ingest("hr")
	s.Ingest("finance")
	list := s.List()
	if len(list) != 2 || list[0].Name != "finance" || list[1].Name != "hr" {
		t.Fatalf("List must be name-ordered, got %v", []string{list[0].Name, list[1].Name})
	}
	c := Corpora()
	if len(c) != 3 || c[0] != "finance" || c[1] != "hr" || c[2] != "legal" {
		t.Fatalf("Corpora wrong: %v", c)
	}
}

func TestSplitSentences(t *testing.T) {
	out := splitSentences("First sentence. Second sentence.")
	if len(out) != 2 || out[0] != "First sentence." || out[1] != "Second sentence." {
		t.Fatalf("split wrong: %v", out)
	}
	if got := splitSentences("One only."); len(got) != 1 {
		t.Fatalf("single: %v", got)
	}
}

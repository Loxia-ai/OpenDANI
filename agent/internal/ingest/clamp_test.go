package ingest
import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)
func TestClampPathological(t *testing.T) {
	table := ""
	for i := 0; i < 400; i++ { table += "1,234.56 | " }
	if got := estTokens(clampForEmbedding(table)); got > embedTokenBudget {
		t.Fatalf("numeric table not clamped: est %d", got)
	}
	dashes := ""
	for i := 0; i < 2000; i++ { dashes += "-" }
	if got := estTokens(clampForEmbedding(dashes)); got > embedTokenBudget {
		t.Fatalf("ruler line not clamped: est %d", got)
	}
	normal := "This agreement shall be governed by the laws of the State of Delaware without regard to conflicts."
	if clampForEmbedding(normal) != normal {
		t.Fatal("normal prose must pass untouched")
	}
}

func TestEmbedBackgroundSingleInFlight(t *testing.T) {
	var sizes []int
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		var req struct {
			Input []string `json:"input"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		sizes = append(sizes, len(req.Input))
		type d struct {
			Index     int       `json:"index"`
			Embedding []float32 `json:"embedding"`
		}
		out := struct {
			Data []d `json:"data"`
		}{}
		for i := range req.Input {
			out.Data = append(out.Data, d{Index: i, Embedding: []float32{1, 2, 3}})
		}
		_ = json.NewEncoder(rw).Encode(out)
	}))
	defer srv.Close()
	e := OpenAIEmbedder{BaseURL: srv.URL, Model: "m"}
	vecs, err := e.EmbedBackground([]string{"a", "b", "c"})
	if err != nil || len(vecs) != 3 {
		t.Fatalf("background embed: %v %d", err, len(vecs))
	}
	for _, n := range sizes {
		if n != 1 { // ONE text per request — the second serving slot stays free for live queries
			t.Fatalf("background embed must be single-in-flight, saw request of %d texts", n)
		}
	}
}

func TestZeroVectorSelfHeal(t *testing.T) {
	ce := &countingEmbedder{}
	s := New().WithEmbedder(ce)
	docs := map[string]ConnectorDoc{"a": {ID: "a", Text: "alpha body with some words"}}
	if err := s.RegisterConnector("heal", &fakeMapConnector{docs: docs}); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := s.SyncConnector(t.Context(), "heal"); err != nil {
		t.Fatal(err)
	}
	// simulate a degraded run: zero out the stored vector (the resilience ladder's fallback)
	s.mu.Lock()
	col := s.collections["heal"]
	for i := range col.Chunks {
		col.Chunks[i].Vec = make([]float32, 32)
	}
	s.collections["heal"] = col
	s.mu.Unlock()
	before := ce.n
	if _, _, _, err := s.SyncConnector(t.Context(), "heal"); err != nil {
		t.Fatal(err)
	}
	if ce.n <= before { // the zeroed chunk must be RE-embedded, not reused
		t.Fatalf("zero-vector chunk was reused instead of healed (embeds %d -> %d)", before, ce.n)
	}
	s.mu.Lock()
	healed := !isZeroVec(s.collections["heal"].Chunks[0].Vec)
	s.mu.Unlock()
	if !healed {
		t.Fatal("vector still zero after heal sync")
	}
}

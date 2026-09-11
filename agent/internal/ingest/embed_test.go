package ingest

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestBoWDeterministicAndRelevant(t *testing.T) {
	e := BoWEmbedder{}
	a, err := e.Embed([]string{"liability caps and indemnification", "liability caps and indemnification", "parental leave policy"})
	if err != nil {
		t.Fatal(err)
	}
	if cosine(a[0], a[1]) < 0.999 {
		t.Fatal("identical texts must embed identically")
	}
	q, _ := e.Embed([]string{"what are the liability caps?"})
	if cosine(q[0], a[0]) <= cosine(q[0], a[2]) {
		t.Fatal("cosine must rank the overlapping text higher")
	}
}

func TestNormalizeAndCosineEdges(t *testing.T) {
	if v := normalize(make([]float32, 4)); v[0] != 0 {
		t.Fatal("zero vector normalizes to itself")
	}
	if cosine([]float32{1}, []float32{1, 0}) != 0 {
		t.Fatal("dimension mismatch scores 0")
	}
	if got := tokenize("Hello, WORLD-42!"); len(got) != 3 || got[2] != "42" {
		t.Fatalf("tokenize wrong: %v", got)
	}
}

func TestOpenAIEmbedder(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Content-Type", "application/json")
		// out-of-order indices must still land correctly
		rw.Write([]byte(`{"data":[{"index":1,"embedding":[0,1]},{"index":0,"embedding":[1,0]}]}`))
	}))
	defer ts.Close()
	e := OpenAIEmbedder{BaseURL: ts.URL, Model: "nomic-embed-text"}
	vs, err := e.Embed([]string{"a", "b"})
	if err != nil {
		t.Fatal(err)
	}
	if vs[0][0] != 1 || vs[1][1] != 1 {
		t.Fatalf("index mapping wrong: %v", vs)
	}
}

func TestOpenAIEmbedderErrors(t *testing.T) {
	cases := map[string]http.HandlerFunc{
		"non-200":  func(rw http.ResponseWriter, _ *http.Request) { http.Error(rw, "nope", 500) },
		"bad json": func(rw http.ResponseWriter, _ *http.Request) { rw.Write([]byte("{not json")) },
		"count":    func(rw http.ResponseWriter, _ *http.Request) { rw.Write([]byte(`{"data":[]}`)) },
		"index":    func(rw http.ResponseWriter, _ *http.Request) { rw.Write([]byte(`{"data":[{"index":9,"embedding":[1]}]}`)) },
	}
	for name, h := range cases {
		t.Run(name, func(t *testing.T) {
			ts := httptest.NewServer(h)
			defer ts.Close()
			if _, err := (OpenAIEmbedder{BaseURL: ts.URL, Client: ts.Client()}).Embed([]string{"x"}); err == nil {
				t.Fatalf("%s should error", name)
			}
		})
	}
	// unreachable upstream
	if _, err := (OpenAIEmbedder{BaseURL: "http://127.0.0.1:1"}).Embed([]string{"x"}); err == nil {
		t.Fatal("dial failure should error")
	}
}

type failEmbedder struct{}

func (failEmbedder) Embed([]string) ([][]float32, error) { return nil, errors.New("embed down") }

func TestRetrieveClassificationFilter(t *testing.T) {
	s := New()
	if _, err := s.Ingest("legal"); err != nil { // legal chunks are restricted+
		t.Fatal(err)
	}
	// alice (restricted ceiling) retrieves; carol (internal ceiling) sees nothing from legal
	hits, err := s.Retrieve("legal", "what does the data processing addendum require", 3, "restricted")
	if err != nil || len(hits) == 0 {
		t.Fatalf("restricted ceiling should retrieve: %v %d", err, len(hits))
	}
	if hits[0].DocID == "" || hits[0].Score <= 0 {
		t.Fatalf("hit missing lineage/score: %+v", hits[0])
	}
	// ranked: the DPA chunk should be first for this query
	if !strings.Contains(hits[0].Text, "Data processing addendum") {
		t.Fatalf("ranking wrong, top hit: %q", hits[0].Text)
	}
	none, err := s.Retrieve("legal", "what does the data processing addendum require", 3, "internal")
	if err != nil || len(none) != 0 {
		t.Fatalf("internal ceiling must see no restricted chunks, got %d", len(none))
	}
	// topK caps and default
	one, _ := s.Retrieve("legal", "agreement requirements policy risk", 1, "secret")
	if len(one) != 1 {
		t.Fatalf("topK=1 must cap, got %d", len(one))
	}
	def, _ := s.Retrieve("legal", "agreement requirements policy risk", 0, "secret")
	if len(def) > 3 {
		t.Fatalf("default topK is 3, got %d", len(def))
	}
}

// orthoEmbedder makes every chunk orthogonal to every query, deterministically: chunks embed to
// [0,1], queries (detected by prefix) to [1,0] — cosine is exactly 0, exercising the score>0 filter.
type orthoEmbedder struct{}

func (orthoEmbedder) Embed(texts []string) ([][]float32, error) {
	out := make([][]float32, len(texts))
	for i, t := range texts {
		if strings.HasPrefix(t, "QUERY:") {
			out[i] = []float32{1, 0}
		} else {
			out[i] = []float32{0, 1}
		}
	}
	return out, nil
}

func TestRetrieveZeroScoreFiltered(t *testing.T) {
	s := New().WithEmbedder(orthoEmbedder{})
	if _, err := s.Ingest("hr"); err != nil {
		t.Fatal(err)
	}
	hits, err := s.Retrieve("hr", "QUERY: anything", 3, "secret")
	if err != nil || len(hits) != 0 {
		t.Fatalf("orthogonal vectors must score 0 and be filtered: %v %d", err, len(hits))
	}
}

func TestRetrieveErrors(t *testing.T) {
	s := New()
	if _, err := s.Retrieve("ghost", "q", 3, "secret"); err == nil {
		t.Fatal("unknown collection must error")
	}
	s.Ingest("hr")
	s.WithEmbedder(failEmbedder{})
	if _, err := s.Retrieve("hr", "q", 3, "secret"); err == nil {
		t.Fatal("query embed failure must error")
	}
	if _, err := s.Ingest("hr"); err == nil {
		t.Fatal("ingest embed failure must error")
	}
}

func TestClassifyContent(t *testing.T) {
	if ClassifyContent("hello world") != "unrestricted" {
		t.Fatal("benign content is unrestricted")
	}
	if ClassifyContent("quarterly revenue and risk") != "restricted" {
		t.Fatal("financial keywords scan restricted")
	}
	if ClassifyContent("the classified launch codes") != "secret" {
		t.Fatal("secret keywords scan secret")
	}
}

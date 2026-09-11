package ingest

// Embedder is the one AI seam in ingest (project convention: AI behind an interface). BoWEmbedder
// is the deterministic CI default — the sim's verified pseudo-embedding, where cosine reflects real
// word overlap. OpenAIEmbedder is the real thing against any OpenAI-compatible /v1/embeddings
// upstream (Ollama nomic-embed-text, llama.cpp --embedding).

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"strings"
	"time"
	"unicode"
)

// Embedder produces one vector per input text (all vectors the same dimension).
type Embedder interface {
	Embed(texts []string) ([][]float32, error)
}

// BoWEmbedder is the sim's deterministic 32-dim bag-of-words pseudo-embedding (SIM-14): each word
// hashes to a bucket, counts are L2-normalized. Cosine similarity over it reflects word overlap, so
// retrieval ranks genuinely relevant chunks — with zero model weights and full reproducibility.
type BoWEmbedder struct{}

// Embed hashes words into 32 buckets and normalizes.
func (BoWEmbedder) Embed(texts []string) ([][]float32, error) {
	out := make([][]float32, len(texts))
	for i, text := range texts {
		v := make([]float32, 32)
		for _, w := range tokenize(text) {
			h := uint32(0)
			for _, c := range w {
				h = h*31 + uint32(c)
			}
			v[h%32]++
		}
		out[i] = normalize(v)
	}
	return out, nil
}

// tokenize lowercases and splits on non-alphanumerics (the sim's [a-z0-9]+ match).
func tokenize(s string) []string {
	return strings.FieldsFunc(strings.ToLower(s), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	})
}

func normalize(v []float32) []float32 {
	var sum float64
	for _, x := range v {
		sum += float64(x) * float64(x)
	}
	n := math.Sqrt(sum)
	if n == 0 {
		return v
	}
	for i := range v {
		v[i] = float32(float64(v[i]) / n)
	}
	return v
}

// cosine of two normalized vectors (dot product; 0 when dimensions mismatch).
func cosine(a, b []float32) float32 {
	if len(a) != len(b) {
		return 0
	}
	var d float32
	for i := range a {
		d += a[i] * b[i]
	}
	return d
}

// OpenAIEmbedder calls an OpenAI-compatible /v1/embeddings endpoint — REAL vectors from a real
// embedding model, in-perimeter (Ollama or llama.cpp on a node you own).
type OpenAIEmbedder struct {
	BaseURL string // e.g. http://127.0.0.1:11434/v1
	Model   string // e.g. nomic-embed-text
	Client  *http.Client
}

const (
	embedBatchSize   = 16  // texts per upstream request — small batches keep the upstream queue shallow
	embedTokenBudget = 440 // estimated wordpiece tokens per input — inside a 512-token embedding slot
)

// estTokens over-approximates a wordpiece token count: every digit/punctuation/symbol char is a
// token, letter runs cost ~1 token per 4 letters. A BYTE cap cannot bound tokens — 1200 chars of a
// numeric table or a dashed ruler line tokenizes to 500+ — and one such chunk used to 500-fail an
// entire 36k-chunk sync.
func estTokens(s string) int {
	n, run := 0, 0
	for _, r := range s {
		if unicode.IsLetter(r) {
			run++
			continue
		}
		n += (run + 3) / 4
		run = 0
		if !unicode.IsSpace(r) {
			n++
		}
	}
	return n + (run+3)/4
}

// clampForEmbedding trims a text (embedding input ONLY — the stored chunk is untouched) to the
// token budget.
func clampForEmbedding(s string) string {
	if estTokens(s) <= embedTokenBudget {
		return s
	}
	lo, hi := 0, len(s)
	for lo < hi { // binary-search the longest prefix inside budget
		mid := (lo + hi + 1) / 2
		if estTokens(s[:mid]) <= embedTokenBudget {
			lo = mid
		} else {
			hi = mid - 1
		}
	}
	return s[:lo]
}

// Embed batches the inputs through the upstream (one giant request would blow its context/timeout)
// and reassembles the vectors in input order. Resilience ladder: a failed batch is retried once,
// then embedded text-by-text; a text that STILL fails gets a zero vector — invisible to dense
// retrieval but still fully searchable via BM25 (hybrid degrades, never poisons the sync).
func (e OpenAIEmbedder) Embed(texts []string) ([][]float32, error) {
	out := make([][]float32, 0, len(texts))
	dim := 0
	for start := 0; start < len(texts); start += embedBatchSize {
		end := start + embedBatchSize
		if end > len(texts) {
			end = len(texts)
		}
		part, err := e.embedBatch(texts[start:end])
		if err != nil { // one retry — a warming/preempted upstream shouldn't fail a whole sync
			part, err = e.embedBatch(texts[start:end])
		}
		if err != nil { // batch still failing — isolate the poison text(s) one by one
			part = make([][]float32, 0, end-start)
			for _, t := range texts[start:end] {
				one, oerr := e.embedBatch([]string{t})
				if oerr != nil {
					part = append(part, nil) // placeholder; sized to dim below
					continue
				}
				part = append(part, one[0])
			}
		}
		for _, v := range part {
			if len(v) > 0 {
				dim = len(v)
			}
		}
		out = append(out, part...)
	}
	if dim == 0 {
		return nil, fmt.Errorf("ingest: embeddings upstream rejected every input")
	}
	for i, v := range out {
		if len(v) == 0 {
			out[i] = make([]float32, dim) // zero vector: dense-invisible, BM25 still finds the chunk
		}
	}
	return out, nil
}

// EmbedBackground is the batch path with INVERTED priority: one text per upstream request,
// strictly sequential. With --parallel 2 serving slots, background embedding then occupies exactly
// ONE slot and the second stays free for interactive query embeds — a multi-hour corpus re-embed
// no longer starves live RAG traffic (measured live: a 2-word query embed queued 51 SECONDS behind
// 16-text batch requests; with this path it lands in the free slot immediately). The resilience
// ladder still applies: retry once, then a zero vector (dense-invisible, BM25 still finds it).
func (e OpenAIEmbedder) EmbedBackground(texts []string) ([][]float32, error) {
	out := make([][]float32, 0, len(texts))
	dim := 0
	for _, t := range texts {
		part, err := e.embedBatch([]string{t})
		if err != nil {
			part, err = e.embedBatch([]string{t})
		}
		if err != nil || len(part) == 0 {
			part = [][]float32{nil}
		}
		if len(part[0]) > 0 {
			dim = len(part[0])
		}
		out = append(out, part[0])
	}
	if dim == 0 {
		return nil, fmt.Errorf("ingest: embeddings upstream rejected every input")
	}
	for i, v := range out {
		if len(v) == 0 {
			out[i] = make([]float32, dim)
		}
	}
	return out, nil
}

// embedBatch posts one batch and unpacks the vectors in input order.
func (e OpenAIEmbedder) embedBatch(texts []string) ([][]float32, error) {
	in := make([]string, len(texts))
	for i, t := range texts {
		in[i] = clampForEmbedding(t)
	}
	body, _ := json.Marshal(map[string]any{"model": e.Model, "input": in})
	client := e.Client
	if client == nil {
		client = &http.Client{Timeout: 180 * time.Second} // CPU embedding of a full batch is slow, not broken
	}
	resp, err := client.Post(e.BaseURL+"/embeddings", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ingest: embeddings upstream HTTP %d", resp.StatusCode)
	}
	var parsed struct {
		Data []struct {
			Index     int       `json:"index"`
			Embedding []float32 `json:"embedding"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, fmt.Errorf("ingest: bad embeddings response: %w", err)
	}
	if len(parsed.Data) != len(texts) {
		return nil, fmt.Errorf("ingest: embeddings count mismatch: got %d want %d", len(parsed.Data), len(texts))
	}
	out := make([][]float32, len(texts))
	for _, d := range parsed.Data {
		if d.Index < 0 || d.Index >= len(out) {
			return nil, fmt.Errorf("ingest: embeddings index %d out of range", d.Index)
		}
		out[d.Index] = normalize(d.Embedding)
	}
	return out, nil
}

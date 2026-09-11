package ingest

// Sparse retrieval (BM25) + hybrid fusion. Legal queries are half exact-lookup — a section number,
// a defined term, a party name — where lexical match beats any dense embedding; dense wins on
// paraphrase. Hybrid fuses both rankings with Reciprocal Rank Fusion (RRF), the standard
// score-free fusion (rankings from different scorers aren't calibrated against each other).
//
// The index is built lazily per collection and cached against a cheap fingerprint (chunk count +
// boundary ids + total text length), so ingest/sync/boot paths don't each need to remember to
// rebuild it. One useful robustness property: if a collection's stored vectors predate an embedder
// change (dimension mismatch → cosine 0), hybrid retrieval degrades to pure BM25 instead of
// returning nothing.

import (
	"fmt"
	"math"
	"sort"
	"sync"
)

const (
	bm25K1 = 1.2
	bm25B  = 0.75
	rrfK   = 60.0 // standard RRF constant
)

type bm25Index struct {
	fingerprint string
	toks        [][]string // per-chunk lowercase tokens (built once; scoring scans these)
	df          map[string]int
	avgLen      float64
}

type bm25Cache struct {
	mu  sync.Mutex
	ixs map[string]*bm25Index
}

func colFingerprint(col Collection) string {
	total := 0
	for _, ch := range col.Chunks {
		total += len(ch.Text)
	}
	first, last := "", ""
	if n := len(col.Chunks); n > 0 {
		first, last = col.Chunks[0].ID, col.Chunks[n-1].ID
	}
	return fmt.Sprintf("%d|%s|%s|%d", len(col.Chunks), first, last, total)
}

// index returns the cached BM25 index for a collection, rebuilding when the fingerprint moved.
func (c *bm25Cache) index(col Collection) *bm25Index {
	fp := colFingerprint(col)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ixs == nil {
		c.ixs = map[string]*bm25Index{}
	}
	if ix, ok := c.ixs[col.Name]; ok && ix.fingerprint == fp {
		return ix
	}
	ix := &bm25Index{fingerprint: fp, df: map[string]int{}}
	totalLen := 0
	for _, ch := range col.Chunks {
		t := tokenize(ch.Text)
		ix.toks = append(ix.toks, t)
		totalLen += len(t)
		seen := map[string]bool{}
		for _, w := range t {
			if !seen[w] {
				seen[w] = true
				ix.df[w]++
			}
		}
	}
	if n := len(col.Chunks); n > 0 {
		ix.avgLen = float64(totalLen) / float64(n)
	}
	c.ixs[col.Name] = ix
	return ix
}

// scores computes the BM25 score of every chunk for a query (0 for no term overlap).
func (ix *bm25Index) scores(query string) []float64 {
	terms := map[string]int{} // term -> slot
	var idf []float64
	n := float64(len(ix.toks))
	for _, w := range tokenize(query) {
		if _, ok := terms[w]; ok {
			continue
		}
		df := float64(ix.df[w])
		if df == 0 {
			continue // term absent from the corpus — contributes nothing
		}
		terms[w] = len(idf)
		idf = append(idf, math.Log(1+(n-df+0.5)/(df+0.5)))
	}
	out := make([]float64, len(ix.toks))
	if len(terms) == 0 {
		return out
	}
	tf := make([]float64, len(idf))
	for i, toks := range ix.toks {
		for j := range tf {
			tf[j] = 0
		}
		for _, w := range toks {
			if slot, ok := terms[w]; ok {
				tf[slot]++
			}
		}
		dl := float64(len(toks))
		var s float64
		for j, f := range tf {
			if f > 0 {
				s += idf[j] * (f * (bm25K1 + 1)) / (f + bm25K1*(1-bm25B+bm25B*dl/ix.avgLen))
			}
		}
		out[i] = s
	}
	return out
}

// fuseRRF merges rankings (each a slice of chunk indices, best first) into RRF scores per chunk,
// normalized so a chunk ranked first in every ranking scores 1.0.
func fuseRRF(nChunks int, rankings ...[]int) []float64 {
	out := make([]float64, nChunks)
	for _, ranking := range rankings {
		for rank, idx := range ranking {
			out[idx] += 1.0 / (rrfK + float64(rank+1))
		}
	}
	max := float64(len(rankings)) / (rrfK + 1)
	if max > 0 {
		for i := range out {
			out[i] /= max
		}
	}
	return out
}

// rankDesc returns eligible indices sorted by score descending, positive scores only.
func rankDesc(scores []float64, eligible []int) []int {
	var idx []int
	for _, i := range eligible {
		if scores[i] > 0 {
			idx = append(idx, i)
		}
	}
	sort.SliceStable(idx, func(a, b int) bool { return scores[idx[a]] > scores[idx[b]] })
	return idx
}

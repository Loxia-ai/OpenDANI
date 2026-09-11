package serving

// Multi-document retrieval + packing — how a SMALL model answers questions that span N documents.
// Run 29b measured the failure: a single fused query drops one side of a cross-document comparison
// half the time (one entity dominates the ranking), and the old rank-order packer physically fit
// only ~3 full chunks in the 820-word excerpt budget — an N=5 question was unanswerable by
// construction. Three fixes, all deterministic (no extra model calls — latency and small-model
// budgets stay flat):
//
//  1. QUERY DECOMPOSITION: comparison/enumeration phrasings ("compare X with Y", "across A, B and
//     C") are split into per-entity sub-queries; each retrieves independently and the results join
//     the candidate pool. An agent can also pass explicit "subqueries" in the chat body.
//  2. DOC-DIVERSITY PACKING: rank-order packing with a per-document chunk cap, and excerpt
//     TRIMMING that scales down as the number of documents-to-represent grows — N documents share
//     the budget instead of the top document eating it.
//  3. MUST-REPRESENT: each sub-query's top document (plus the primary query's leaders) is
//     guaranteed a seat in the packed context, force-appended trimmed if rank-order packing
//     skipped it.

import (
	"regexp"
	"strings"

	"dani.local/agent/internal/ingest"
)

const (
	ragPoolK          = 24  // primary retrieval pool (deeper than the packed set — diversity needs candidates)
	ragSubqK          = 8   // per-sub-query retrieval depth
	ragMaxSubqs       = 8   // decomposition ceiling — agentic map-reduce takes N=5..8; single-shot seats ≤5
	ctxWordBudget     = 820 // ≈1100 tokens of excerpts; question + answer fit the 2048/slot window
	ragTrimWords      = 150 // per-excerpt cap once ≥3 documents must share the budget
	ragForceTrimWords = 120 // tighter cap for force-appended representatives
)

var (
	reDecompKey  = regexp.MustCompile(`(?i)\b(compare|between|among|across|versus)\b`)
	reDecompTail = regexp.MustCompile(`(?i),?\s+(which|what|how|who|whose|is|are|do|does|and how|and which)\b.*$`)
)

// decomposeQuery splits a comparison/enumeration question into per-entity sub-queries — the
// deterministic slice of query decomposition (an LLM decomposer is a documented upgrade; this one
// costs zero model calls and covers the phrasing lawyers actually use). Returns nil when the query
// doesn't confidently decompose — retrieval then proceeds single-shot.
func decomposeQuery(query string) []string {
	loc := reDecompKey.FindStringIndex(query)
	if loc == nil {
		return nil
	}
	seg := query[loc[1]:]
	for _, stop := range []string{"?", ". ", ";", ":", " — "} { // cut the trailing clause
		if i := strings.Index(seg, stop); i >= 0 {
			seg = seg[:i]
		}
	}
	seg = reDecompTail.ReplaceAllString(seg, "")
	// entity list: split on the connectors comparison phrasing uses
	for _, conn := range []string{" with ", " versus ", " vs ", " and "} {
		seg = strings.ReplaceAll(seg, conn, ",")
	}
	var entities []string
	for _, part := range strings.Split(seg, ",") {
		p := strings.TrimSpace(strings.Trim(part, ".,;:"))
		p = strings.TrimPrefix(p, "the ")
		if w := len(strings.Fields(p)); w >= 1 && w <= 10 && strings.IndexFunc(p, isLetterRune) >= 0 {
			entities = append(entities, p)
		}
	}
	if len(entities) < 2 {
		return nil
	}
	if len(entities) > ragMaxSubqs {
		entities = entities[:ragMaxSubqs]
	}
	subqs := make([]string, len(entities))
	for i, e := range entities {
		// each sub-query sees the question WITHOUT its rival entities — leaving them in polluted
		// per-entity retrieval badly (every rival's tokens weighed against this entity's)
		q := query
		for j, o := range entities {
			if j != i {
				q = strings.ReplaceAll(q, o, "")
			}
		}
		q = strings.Join(strings.Fields(q), " ")
		if len(q) > 300 {
			q = q[:300]
		}
		subqs[i] = e + " — " + q // the entity leads: its tokens dominate both BM25 and the embedding
	}
	return subqs
}

func isLetterRune(r rune) bool { return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') }

// unionPool merges the primary ranking with each sub-query's ranking: primary order first, then
// unseen sub-hits round-robin by rank (each entity's best evidence enters before anyone's third).
func unionPool(primary []ingest.Hit, subHits [][]ingest.Hit) []ingest.Hit {
	seen := map[string]bool{}
	out := make([]ingest.Hit, 0, len(primary)+8)
	for _, h := range primary {
		if !seen[h.ID] {
			seen[h.ID] = true
			out = append(out, h)
		}
	}
	for round := 0; round < ragSubqK; round++ {
		for _, sh := range subHits {
			if round < len(sh) && !seen[sh[round].ID] {
				seen[sh[round].ID] = true
				out = append(out, sh[round])
			}
		}
	}
	return out
}

// mustRepresent returns the documents guaranteed a seat in the packed context. Each sub-query
// (one per entity the question names) seats the FIRST doc in its ranking not already seated by an
// earlier sub-query — two entities whose rankings share a leader would otherwise collapse into one
// seat and the second entity's document would lose its place. The primary ranking's leaders fill
// the remaining seats.
func mustRepresent(primary []ingest.Hit, subHits [][]ingest.Hit) []string {
	seen := map[string]bool{}
	var out []string
	add := func(d string) bool {
		if d == "" || seen[d] || len(out) >= 8 {
			return false
		}
		seen[d] = true
		out = append(out, d)
		return true
	}
	for _, sh := range subHits {
		for _, h := range sh { // first doc this entity's ranking offers that nobody else has seated
			if add(h.DocID) {
				break
			}
		}
	}
	for i := 0; i < len(primary) && i < 4; i++ {
		add(primary[i].DocID)
	}
	return out
}

func trimHit(h ingest.Hit, maxWords int) ingest.Hit {
	if maxWords <= 0 {
		return h
	}
	f := strings.Fields(h.Text)
	if len(f) <= maxWords {
		return h
	}
	h.Text = strings.Join(f[:maxWords], " ") + " …"
	return h
}

// packDiverse selects what actually enters the model's context. classic=true reproduces the old
// behavior (pure rank order over the top 8, no caps — the measured baseline). Otherwise:
// rank-order packing with a per-doc cap and N-aware trimming, then force-append a trimmed best
// chunk for every must-represent document the rank pass skipped (allowed to overflow the budget by
// ~17% — the engine window has that headroom).
func packDiverse(pool []ingest.Hit, must []string, budget int, classic bool) []ingest.Hit {
	if classic {
		packed := make([]ingest.Hit, 0, 8)
		left := budget
		for i, h := range pool {
			if i >= 8 {
				break
			}
			w := len(strings.Fields(h.Text))
			if len(packed) >= 3 && w > left {
				break
			}
			packed = append(packed, h)
			left -= w
			if left <= 0 {
				break
			}
		}
		return packed
	}
	perDocCap := 2
	if len(must) >= 5 {
		perDocCap = 1
	}
	trim := 0
	switch {
	case len(must) >= 5: // N≥5 docs share 820 words — everyone gets a tight excerpt
		trim = ragForceTrimWords
	case len(must) >= 3:
		trim = ragTrimWords
	}
	used := 0
	counts := map[string]int{}
	var packed []ingest.Hit
	ceiling := budget + budget/6 // engine-window headroom (~17%)
	if len(must) >= 4 {
		// REPRESENTATION-FIRST: at high N the seats ARE the answer — rank-order filling would eat
		// the budget before the last entities get theirs. Seat every named document's best chunk
		// first, then let rank order spend what remains.
		for _, d := range must {
			for _, h := range pool {
				if h.DocID != d {
					continue
				}
				th := trimHit(h, ragForceTrimWords)
				w := len(strings.Fields(th.Text))
				if used+w > ceiling {
					break
				}
				packed = append(packed, th)
				counts[d]++
				used += w
				break
			}
		}
	}
	for _, h := range pool {
		if counts[h.DocID] >= perDocCap {
			continue
		}
		th := trimHit(h, trim)
		w := len(strings.Fields(th.Text))
		if len(packed) >= 3 && used+w > budget {
			break
		}
		packed = append(packed, th)
		counts[h.DocID]++
		used += w
		if used >= budget {
			break
		}
	}
	for _, d := range must { // representation pass: any named document still missing gets its seat
		if counts[d] > 0 {
			continue
		}
		for _, h := range pool {
			if h.DocID != d {
				continue
			}
			th := trimHit(h, ragForceTrimWords)
			w := len(strings.Fields(th.Text))
			if used+w > ceiling {
				break
			}
			packed = append(packed, th)
			counts[d]++
			used += w
			break
		}
	}
	return packed
}

// retrievePacked is the full multi-doc retrieval pipeline shared by the chat path and the search
// endpoint's pack mode: retrieve deep, decompose + union, pack diverse.
func (t *TrainingAPI) retrievePacked(collection, query, ceiling string, explicitSubqs []string, noDecomp, classic bool, aux ...[]ingest.Hit) ([]ingest.Hit, []string, error) {
	primary, err := t.Ingest.Retrieve(collection, query, ragPoolK, ceiling)
	if err != nil {
		return nil, nil, err
	}
	subqs := explicitSubqs
	if len(subqs) == 0 && !noDecomp {
		subqs = decomposeQuery(query)
	}
	if len(subqs) > 5 { // the single-shot window seats at most ~5 documents; agentic owns larger N
		subqs = subqs[:5]
	}
	var subHits [][]ingest.Hit
	if len(subqs) >= 2 && !classic {
		for _, sq := range subqs {
			sh, serr := t.Ingest.Retrieve(collection, sq, ragSubqK, ceiling)
			if serr == nil {
				subHits = append(subHits, sh)
			}
		}
	}
	// auxiliary rankings (the multilingual bridge's native-language dense leg) fuse like sub-queries:
	// they join the pool AND earn a must-represent seat — a term-of-art mistranslation in the primary
	// query cannot lose a document the original-language ranking found.
	for _, a := range aux {
		if len(a) > 0 && !classic {
			subHits = append(subHits, a)
		}
	}
	pool := primary
	if len(subHits) > 0 {
		pool = unionPool(primary, subHits)
	}
	must := mustRepresent(primary, subHits)
	return packDiverse(pool, must, ctxWordBudget, classic), subqs, nil
}

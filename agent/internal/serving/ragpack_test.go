package serving

// Multi-document retrieval mechanics: decomposition of comparison/enumeration phrasing,
// doc-diverse packing with per-doc caps and must-represent seats, budget discipline.

import (
	"fmt"
	"strings"
	"testing"

	"dani.local/agent/internal/ingest"
)

func TestDecomposeQuery(t *testing.T) {
	subs := decomposeQuery("Compare the cap on liability in the ALPHA license agreement with the BETA services agreement. How do they differ?")
	if len(subs) != 2 || !strings.Contains(subs[0], "ALPHA") || !strings.Contains(subs[1], "BETA") {
		t.Fatalf("pair decomposition wrong: %q", subs)
	}
	subs = decomposeQuery("Across the ACME reseller agreement, the ZEN hosting agreement and the NOVA co-branding agreement, which grants audit rights?")
	if len(subs) != 3 {
		t.Fatalf("3-way enumeration wrong: %q", subs)
	}
	if subs = decomposeQuery("What is the governing law of this agreement?"); subs != nil {
		t.Fatalf("plain question must not decompose: %q", subs)
	}
	// N=5 enumeration caps at ragMaxSubqs
	subs = decomposeQuery("Across A corp, B corp, C corp, D corp, E corp and F corp, compare insurance.")
	if len(subs) > ragMaxSubqs {
		t.Fatalf("subquery ceiling breached: %d", len(subs))
	}
}

func mkHit(doc string, i, words int) ingest.Hit {
	return ingest.Hit{ID: fmt.Sprintf("%s#%d", doc, i), DocID: doc,
		Text: strings.Repeat("word ", words), Classification: "internal"}
}

func TestPackDiverseRepresentsEveryNamedDoc(t *testing.T) {
	// pool: docA dominates the ranking with huge chunks; docB..docE trail far behind
	var pool []ingest.Hit
	for i := 0; i < 8; i++ {
		pool = append(pool, mkHit("docA", i, 250))
	}
	for _, d := range []string{"docB", "docC", "docD", "docE"} {
		pool = append(pool, mkHit(d, 0, 250))
	}
	must := []string{"docA", "docB", "docC", "docD", "docE"}

	// classic packer: rank order — docA eats the whole budget, N=5 is structurally impossible
	classic := packDiverse(pool, must, ctxWordBudget, true)
	classicDocs := map[string]bool{}
	for _, h := range classic {
		classicDocs[h.DocID] = true
	}
	if len(classicDocs) != 1 {
		t.Fatalf("classic baseline should collapse to one doc here, got %d", len(classicDocs))
	}

	// diverse packer: every must-represent doc gets a seat, budget respected within the ceiling
	packed := packDiverse(pool, must, ctxWordBudget, false)
	got := map[string]bool{}
	used := 0
	for _, h := range packed {
		got[h.DocID] = true
		used += len(strings.Fields(h.Text))
	}
	for _, d := range must {
		if !got[d] {
			t.Fatalf("must-represent doc %s missing from packed set (%v)", d, got)
		}
	}
	if used > ctxWordBudget+ctxWordBudget/6 {
		t.Fatalf("budget overflow ceiling breached: %d words", used)
	}
}

func TestPackDiverseSingleDocUnharmed(t *testing.T) {
	// single-doc question shape: gold doc's chunks lead the ranking — they must still lead the pack
	pool := []ingest.Hit{mkHit("gold", 0, 200), mkHit("gold", 1, 200), mkHit("other", 0, 200), mkHit("noise", 0, 200)}
	packed := packDiverse(pool, []string{"gold", "other"}, ctxWordBudget, false)
	if len(packed) < 3 || packed[0].DocID != "gold" || packed[1].DocID != "gold" {
		t.Fatalf("gold doc's leading chunks demoted: %+v", packed)
	}
}

func TestUnionPoolRoundRobin(t *testing.T) {
	primary := []ingest.Hit{mkHit("p", 0, 10)}
	subA := []ingest.Hit{mkHit("a", 0, 10), mkHit("a", 1, 10)}
	subB := []ingest.Hit{mkHit("b", 0, 10), mkHit("b", 1, 10)}
	pool := unionPool(primary, [][]ingest.Hit{subA, subB})
	if len(pool) != 5 || pool[1].DocID != "a" || pool[2].DocID != "b" || pool[3].DocID != "a" {
		t.Fatalf("round-robin union wrong: %+v", pool)
	}
}

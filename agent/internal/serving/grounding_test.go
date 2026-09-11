package serving

// The deterministic groundedness verifier: invented numbers, section refs, and quotes are caught;
// faithful answers pass.

import (
	"strings"
	"testing"
)

func TestVerifyGroundingCatchesFabrication(t *testing.T) {
	excerpts := []string{
		"[CFR45-164.312 · Technical safeguards]\nA covered entity must implement audit controls. " +
			"Access is terminated upon thirty (30) days written notice per Section 12.3 of the agreement.",
	}
	// faithful: everything checkable appears in the excerpts
	g := verifyGrounding(`Termination requires 30 days notice under Section 12.3 (see CFR45-164.312).`, excerpts)
	if g.Score != 1.0 || len(g.Unsupported) != 0 {
		t.Fatalf("faithful answer flagged: %+v", g)
	}
	if g.Checked < 3 {
		t.Fatalf("should have checked number+section+id, checked %d", g.Checked)
	}
	// fabricated: 45 days and Section 99.9 appear nowhere
	g = verifyGrounding(`Termination requires 45 days notice under Section 99.9.`, excerpts)
	if g.Score >= 1.0 || len(g.Unsupported) == 0 {
		t.Fatalf("fabricated answer NOT flagged: %+v", g)
	}
	found := strings.Join(g.Unsupported, " ")
	if !strings.Contains(found, "45") || !strings.Contains(found, "99.9") {
		t.Fatalf("unsupported list should name the inventions: %v", g.Unsupported)
	}
	// invented quote
	g = verifyGrounding(`The contract states "time is of the essence in all matters".`, excerpts)
	if g.Score >= 1.0 {
		t.Fatalf("invented quote NOT flagged: %+v", g)
	}
	// § notation in the answer matches "Section"/§ text via the bare-core fallback
	g = verifyGrounding(`Audit controls are required by § 164.312.`, excerpts)
	if g.Score != 1.0 {
		t.Fatalf("§-vs-plain-section equivalence failed: %+v", g)
	}
	// nothing checkable → trivially grounded with zero checks
	g = verifyGrounding(`The excerpts describe safeguards obligations.`, excerpts)
	if g.Score != 1.0 || g.Checked != 0 {
		t.Fatalf("prose-only answer should be 1.0 with 0 checks: %+v", g)
	}
}

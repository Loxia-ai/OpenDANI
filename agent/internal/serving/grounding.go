package serving

// Deterministic groundedness verification for RAG answers — the safety net a legal/compliance
// deployment cannot go without. A small model WILL sometimes invent a number, a date, a section
// reference, or a "quote" that is in none of the retrieved sources. This verifier extracts every
// checkable artifact from the answer — numbers, §/section/article references, control-style
// identifiers, quoted spans — and checks each appears verbatim in the retrieved excerpts. It runs
// in microseconds with zero model calls and cannot be sweet-talked. It does NOT prove an answer
// true (that needs an NLI judge — documented follow-up); it catches the classic fabrication
// failure deterministically, which is the highest-value slice of verification.
//
// The result travels as X-Dani-Rag-Grounding (0..1) + X-Dani-Rag-Ungrounded (what failed), and an
// audit event fires when anything is unsupported — a flagged answer is visible, attributable
// evidence, not a silent hope.

import (
	"regexp"
	"strings"
)

var (
	reGroundNumber = regexp.MustCompile(`\d[\d,]*\.?\d*%?`)
	reGroundRef    = regexp.MustCompile(`(?i)(§+\s?[\w.\-()]+|(section|article|clause|part|exhibit|schedule)\s+[\w.\-()]+)`)
	reGroundID     = regexp.MustCompile(`\b[A-Z]{2,}[\d]*[-:][\w.\-]*\d[\w.\-]*\b`)
	reGroundQuote  = regexp.MustCompile(`[“"]([^”"]{8,160})[”"]`)
)

func normGround(s string) string {
	s = strings.ToLower(strings.ReplaceAll(s, ",", ""))
	return strings.Join(strings.Fields(s), " ")
}

// groundingResult is one verified answer's verdict.
type groundingResult struct {
	Score       float64  // supported / checked (1.0 when nothing checkable)
	Checked     int      // artifacts extracted from the answer
	Unsupported []string // artifacts absent from every retrieved excerpt
}

// verifyGrounding checks every checkable artifact of answer against the retrieved excerpts.
// Multiword artifacts (refs, quotes) are substring-matched; bare numbers are TOKEN-matched — "45"
// inside "CFR45-164.312" is not support for a "45 days" claim.
func verifyGrounding(answer string, excerpts []string) groundingResult {
	var hay strings.Builder
	tokens := map[string]bool{}
	for _, e := range excerpts {
		n := normGround(e)
		hay.WriteString(n)
		hay.WriteByte(' ')
		for _, tok := range strings.Fields(n) {
			t := strings.Trim(tok, `.,;:()[]"'“”‘’`)
			tokens[t] = true
			// composite identifiers ("cfr45-164.312", "164.312/164.314") also support their parts
			for _, part := range strings.FieldsFunc(t, func(r rune) bool { return r == '-' || r == '/' }) {
				tokens[part] = true
			}
		}
	}
	h := hay.String()

	type item struct {
		text    string
		numeric bool
	}
	seen := map[string]bool{}
	var items []item
	add := func(raw string, numeric bool) {
		n := strings.Trim(normGround(raw), `.,;:`)
		if n == "" || seen[n] {
			return
		}
		seen[n] = true
		items = append(items, item{n, numeric})
	}
	isWordy := func(b byte) bool {
		return b == '-' || b == '_' || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
	}
	for _, loc := range reGroundNumber.FindAllStringIndex(answer, -1) {
		// a number embedded in an identifier ("CFR45-164.312") is not a standalone numeric claim —
		// the identifier itself is checked whole by the ID matcher
		if loc[0] > 0 && isWordy(answer[loc[0]-1]) {
			continue
		}
		if loc[1] < len(answer) && isWordy(answer[loc[1]]) {
			continue
		}
		if m := answer[loc[0]:loc[1]]; len(strings.Trim(m, ".,%")) >= 2 { // single digits are list markers, not claims
			add(m, true)
		}
	}
	for _, m := range reGroundRef.FindAllString(answer, -1) {
		add(m, false)
	}
	for _, m := range reGroundID.FindAllString(answer, -1) {
		add(m, false)
	}
	for _, m := range reGroundQuote.FindAllStringSubmatch(answer, -1) {
		add(m[1], false)
	}

	res := groundingResult{Score: 1.0, Checked: len(items)}
	if len(items) == 0 {
		return res
	}
	supported := 0
	for _, it := range items {
		var ok bool
		if it.numeric {
			ok = tokens[it.text]
		} else {
			ok = strings.Contains(h, it.text)
			if !ok { // a "Section 164.312" claim is satisfied by "§ 164.312" — retry the bare core token
				f := strings.Fields(it.text)
				if last := strings.Trim(f[len(f)-1], `.,;:`); len(f) > 1 && strings.ContainsAny(last, "0123456789") {
					ok = tokens[last]
				}
			}
		}
		if ok {
			supported++
		} else if len(res.Unsupported) < 8 {
			res.Unsupported = append(res.Unsupported, it.text)
		}
	}
	res.Score = float64(supported) / float64(len(items))
	return res
}

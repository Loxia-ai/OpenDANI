package ingest

// Structure-aware chunking — the retrieval-grade replacement for naive sentence splitting.
// A chunk is token-bounded (~350 tokens ≈ 260 words: sized for a 512-token embedding window and a
// ~1100-token generation context budget), overlapped (~15%, so a clause straddling a boundary
// appears whole in one of the two chunks), and STRUCTURE-AWARE: legal/regulatory headings
// (§ 164.312, "ARTICLE IV", "12.3 Termination", ALL-CAPS titles, markdown #) start a new chunk and
// label every chunk cut from that section — the label travels to citations as the pinpoint anchor.
//
// Sentence boundaries are abbreviation-safe: a period after "v.", "U.S.C.", "No.", "Inc." or a
// list marker ("1.", "(a).") is NOT a sentence end — the naive ". " split shredded exactly the
// citations legal text is full of.
//
// Every chunk is prefixed with a compact context line "[<doc> · <title> · <section>]" so both
// sparse (BM25) and dense retrieval can match a document-scoped query ("in the Acme license
// agreement, ...") against ANY chunk of that document, not only the first — and so a cited excerpt
// is self-describing when a lawyer reads it.

import (
	"regexp"
	"strings"
	"unicode"
)

const (
	chunkMaxWords     = 260 // ≈350 tokens
	chunkOverlapWords = 36  // ~15%
	chunkMinWords     = 20  // fragments below this merge into the neighbouring chunk
)

// docChunk is one packed chunk before it becomes an indexed Chunk.
type docChunk struct {
	Text    string // "[context]\n" + body
	Section string // the heading this chunk falls under ("" before the first heading)
}

// legalAbbrev: a period after these (case-insensitive, trailing period stripped) never ends a
// sentence. Covers reporters, statutes, courts, honorifics, and drafting shorthand.
var legalAbbrev = map[string]bool{
	"v": true, "vs": true, "no": true, "nos": true, "art": true, "arts": true, "sec": true,
	"secs": true, "para": true, "paras": true, "inc": true, "corp": true, "co": true, "ltd": true,
	"llc": true, "llp": true, "u.s.c": true, "c.f.r": true, "u.s": true, "s.ct": true, "stat": true,
	"fed": true, "cir": true, "dist": true, "supp": true, "f.2d": true, "f.3d": true, "f.4th": true,
	"e.g": true, "i.e": true, "etc": true, "cf": true, "id": true, "seq": true, "al": true,
	"mr": true, "mrs": true, "ms": true, "dr": true, "jr": true, "sr": true, "st": true,
	"dept": true, "div": true, "ex": true, "fig": true, "reg": true, "rev": true, "approx": true,
}

var (
	// § 164.312 · ARTICLE IV · Section 12(b) · 12.3(.4) · Exhibit A …
	reHeadingNum = regexp.MustCompile(`^(§+\s?[\dA-Za-z.\-()]+|(ARTICLE|Article|SECTION|Section|PART|Part|EXHIBIT|Exhibit|SCHEDULE|Schedule|APPENDIX|Appendix|CLAUSE|Clause)\s+[\dIVXLCivxlc]+|\d+(\.\d+)+[.)]?)(\s|$)`)
	reNumberish  = regexp.MustCompile(`^[\d.()\-]+$`)
)

// looksLikeHeading reports whether a line starts a new section.
func looksLikeHeading(line string) bool {
	n := len(line)
	if n == 0 || n > 110 || len(strings.Fields(line)) > 14 {
		return false
	}
	if strings.HasPrefix(line, "# ") || strings.HasPrefix(line, "## ") ||
		strings.HasPrefix(line, "### ") || strings.HasPrefix(line, "#### ") {
		return true
	}
	if reHeadingNum.MatchString(line) {
		return true
	}
	// ALL-CAPS title line ("GOVERNING LAW AND DISPUTE RESOLUTION")
	if n >= 12 && strings.IndexFunc(line, unicode.IsLower) < 0 &&
		strings.IndexFunc(line, unicode.IsLetter) >= 0 {
		return true
	}
	return false
}

// splitSentencesSafe splits prose into sentences without breaking on legal abbreviations or
// numbered-list markers.
func splitSentencesSafe(text string) []string {
	var out []string
	start := 0
	for i := 0; i+1 < len(text); i++ {
		c := text[i]
		if (c != '.' && c != '!' && c != '?') || (text[i+1] != ' ' && text[i+1] != '\n') {
			continue
		}
		if c == '.' {
			// the token before the period decides: abbreviation / initial / list marker → no split
			j := i - 1
			for j >= 0 && text[j] != ' ' && text[j] != '\n' && text[j] != '(' {
				j--
			}
			w := strings.ToLower(strings.Trim(text[j+1:i], `."'()“”‘’`))
			if legalAbbrev[w] || len(w) <= 1 || reNumberish.MatchString(w) {
				continue
			}
		}
		if seg := strings.TrimSpace(text[start : i+1]); seg != "" {
			out = append(out, seg)
		}
		start = i + 1
	}
	if seg := strings.TrimSpace(text[start:]); seg != "" {
		out = append(out, seg)
	}
	return out
}

// hardSplitWords cuts a monster run (no sentence boundaries) into ≤max-word pieces.
func hardSplitWords(words []string, max int) []string {
	var out []string
	for len(words) > 0 {
		n := max
		if n > len(words) {
			n = len(words)
		}
		out = append(out, strings.Join(words[:n], " "))
		words = words[n:]
	}
	return out
}

// docContext derives the compact per-chunk context header: the doc id plus a title gleaned from
// leading metadata lines (a JDBC row renders "title: …"; an extracted file often opens with one).
func docContext(docID, text string) string {
	title := ""
	lines := strings.SplitN(text, "\n", 8)
	for i, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		low := strings.ToLower(l)
		for _, k := range []string{"title:", "name:", "subject:", "head:"} {
			if strings.HasPrefix(low, k) {
				title = strings.TrimSpace(l[len(k):])
			}
		}
		if title == "" && i == 0 && len(l) <= 90 && !strings.Contains(low, "text:") {
			title = l // a short opening line is usually the document's own title
		}
	}
	h := docID
	if title != "" && !strings.EqualFold(title, docID) {
		h += " · " + truncateWords(title, 12)
	}
	return h
}

func truncateWords(s string, n int) string {
	f := strings.Fields(s)
	if len(f) > n {
		return strings.Join(f[:n], " ") + "…"
	}
	return s
}

// chunkDoc splits one document into labelled, overlapped, token-bounded chunks.
func chunkDoc(docID, text string) []docChunk {
	if strings.TrimSpace(text) == "" {
		return nil
	}
	header := docContext(docID, text)

	// 1) lines → units (a unit is a heading, a paragraph, or a sentence-piece of a long paragraph)
	type unit struct {
		text    string
		section string
		words   int
	}
	var units []unit
	section := ""
	for _, raw := range strings.Split(text, "\n") {
		l := strings.TrimSpace(raw)
		if l == "" {
			continue
		}
		if looksLikeHeading(l) {
			section = truncateWords(l, 10)
		}
		w := len(strings.Fields(l))
		if w <= chunkMaxWords {
			units = append(units, unit{l, section, w})
			continue
		}
		for _, s := range splitSentencesSafe(l) { // long paragraph → sentences
			sw := strings.Fields(s)
			if len(sw) <= chunkMaxWords {
				units = append(units, unit{s, section, len(sw)})
				continue
			}
			for _, piece := range hardSplitWords(sw, chunkMaxWords) { // run-on → hard split
				units = append(units, unit{piece, section, len(strings.Fields(piece))})
			}
		}
	}
	if len(units) == 0 {
		return nil
	}

	// 2) pack units into chunks: a section change or the word budget flushes; an intra-section
	//    flush carries an overlap tail so boundary-straddling clauses survive whole somewhere.
	var out []docChunk
	var buf []string
	bufWords := 0
	bufSection := units[0].section
	emit := func() {
		if bufWords == 0 {
			return
		}
		h := header
		if bufSection != "" {
			h += " · " + bufSection
		}
		out = append(out, docChunk{Text: "[" + h + "]\n" + strings.Join(buf, "\n"), Section: bufSection})
	}
	for _, u := range units {
		sectionBreak := u.section != bufSection && bufWords >= chunkMinWords
		if bufWords > 0 && (sectionBreak || bufWords+u.words > chunkMaxWords) {
			prev := strings.Fields(strings.Join(buf, " "))
			emit()
			buf, bufWords = nil, 0
			if !sectionBreak && len(prev) > chunkOverlapWords { // overlap only inside a section
				tail := strings.Join(prev[len(prev)-chunkOverlapWords:], " ")
				buf, bufWords = []string{"… " + tail}, chunkOverlapWords
			}
		}
		if bufWords == 0 {
			bufSection = u.section
		}
		buf = append(buf, u.text)
		bufWords += u.words
	}
	// a tiny tail merges back into the previous chunk rather than standing alone
	if bufWords > 0 && bufWords < chunkMinWords && len(out) > 0 && out[len(out)-1].Section == bufSection {
		out[len(out)-1].Text += "\n" + strings.Join(buf, "\n")
	} else {
		emit()
	}
	return out
}

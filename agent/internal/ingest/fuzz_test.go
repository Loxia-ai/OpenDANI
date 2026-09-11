package ingest

// P2-2 parser fuzzing: parseExample and ClassifyContent take OPERATOR-SUPPLIED bytes (console
// uploads) — they must never panic and must keep their invariants on arbitrary input. Seeds run as
// unit tests on every `go test`; `go test -fuzz=FuzzParseExample ./internal/ingest` explores.

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"
)

func FuzzParseExample(f *testing.F) {
	for _, seed := range []string{
		"",
		"plain sentence about nothing",
		`{"text":"hello"}`,
		`{"prompt":"q","completion":"a"}`,
		`{"prompt":"q","completion":"a","system":"s"}`,
		`{"messages":[{"role":"user","content":"hi"}]}`,
		`{"messages":[{"role":"assistant","tool_calls":[{"function":{"name":"f","arguments":"{}"}}]}],"tools":[{"type":"function"}]}`,
		`{"messages":"not-an-array"}`,
		`{"messages":[{"role":1}]}`,
		"{", "}", `{"prompt":123}`, "\x00\xff\xfe", strings.Repeat("a", 10000),
		`{"text":""}`, `{"prompt":"","completion":""}`,
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, line string) {
		ex, ok := parseExample(line)
		if !ok {
			if strings.TrimSpace(line) != "" {
				t.Fatalf("non-empty line rejected entirely: %q", line)
			}
			return
		}
		// invariants: a parsed example always has flattened text and a known format
		if ex.format != "text" && ex.format != "chat" {
			t.Fatalf("unknown format %q for %q", ex.format, line)
		}
		if ex.format == "chat" && len(ex.messages) > 0 && !json.Valid(ex.messages) {
			t.Fatalf("chat example carries invalid messages JSON for %q", line)
		}
		// classification of the flattened text must never panic and must return a known class
		c := ClassifyContent(ex.text)
		if _, known := classRank[c]; !known {
			t.Fatalf("unknown classification %q", c)
		}
		_ = utf8.ValidString(ex.text) // exercising; no invariant — classify is byte-safe
	})
}

func FuzzSplitSentences(f *testing.F) {
	f.Add("One. Two. Three.")
	f.Add("")
	f.Add(". . .")
	f.Add(strings.Repeat("x. ", 5000))
	f.Fuzz(func(t *testing.T, doc string) {
		for _, s := range splitSentences(doc) {
			if strings.TrimSpace(s) == "" {
				t.Fatalf("empty sentence emitted from %q", doc)
			}
		}
	})
}

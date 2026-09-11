package ingest

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestStructuredExamples proves the four training formats parse, classify, and carry their raw
// OpenAI JSON through ingest — instruction (Q&A), multi-turn, and tool-calling, plus plain text.
func TestStructuredExamples(t *testing.T) {
	s := New()
	docs := []string{
		"Refunds are allowed within 30 days.",                                           // plain text
		`{"prompt":"How long is parental leave?","completion":"26 weeks, fully paid."}`, // Q&A
		`{"messages":[{"role":"user","content":"hi"},{"role":"assistant","content":"hello, how can I help?"},{"role":"user","content":"bye"},{"role":"assistant","content":"take care"}]}`, // multi-turn
		`{"messages":[{"role":"user","content":"weather in Paris?"},{"role":"assistant","tool_calls":[{"id":"c1","type":"function","function":{"name":"get_weather","arguments":"{\"city\":\"Paris\"}"}}]},{"role":"tool","tool_call_id":"c1","content":"18C sunny"},{"role":"assistant","content":"It's 18C and sunny in Paris."}],"tools":[{"type":"function","function":{"name":"get_weather","description":"look up weather","parameters":{"type":"object","properties":{"city":{"type":"string"}}}}}]}`, // tool-calling
	}
	if _, err := s.AddCustom("mixed", docs, "internal"); err != nil {
		t.Fatal(err)
	}
	col, err := s.Ingest("mixed")
	if err != nil {
		t.Fatal(err)
	}
	if len(col.Chunks) != 4 {
		t.Fatalf("want 4 examples (one per line, no sentence-splitting), got %d", len(col.Chunks))
	}
	byFormat := map[string]int{}
	var toolChunk *Chunk
	for i := range col.Chunks {
		byFormat[col.Chunks[i].Format]++
		if col.Chunks[i].Tools != nil {
			toolChunk = &col.Chunks[i]
		}
	}
	if byFormat["text"] != 1 || byFormat["chat"] != 3 {
		t.Fatalf("format split wrong: %+v", byFormat)
	}
	// the tool example carries its messages AND tools schema through verbatim
	if toolChunk == nil {
		t.Fatal("tool-calling chunk lost its tools schema")
	}
	var tools []map[string]any
	if err := json.Unmarshal(toolChunk.Tools, &tools); err != nil || len(tools) != 1 {
		t.Fatalf("tools schema didn't round-trip: %v", err)
	}
	var msgs []map[string]any
	if err := json.Unmarshal(toolChunk.Messages, &msgs); err != nil || len(msgs) != 4 {
		t.Fatalf("messages didn't round-trip: %v %d", err, len(msgs))
	}
	// classification scans the FLATTENED content of a structured example, not just plain text
	s2 := New()
	s2.AddCustom("sensitive", []string{
		`{"messages":[{"role":"user","content":"what was Q3 revenue?"},{"role":"assistant","content":"Revenue grew 14 percent."}]}`,
	}, "internal")
	col2, _ := s2.Ingest("sensitive")
	if col2.Chunks[0].Classification != "restricted" {
		t.Fatalf("content scan must raise a Q&A mentioning revenue to restricted, got %q", col2.Chunks[0].Classification)
	}
	if col2.Chunks[0].Text == "" || strings.Contains(col2.Chunks[0].Text, "\n") {
		t.Fatalf("flattened text should be clean single-line: %q", col2.Chunks[0].Text)
	}
}

// TestParseExampleForms exercises each accepted line shape + the forgiving fallbacks.
func TestParseExampleForms(t *testing.T) {
	cases := []struct {
		in         string
		wantFormat string
		wantOK     bool
	}{
		{"plain sentence", "text", true},
		{`{"text":"json text form"}`, "text", true},
		{`{"prompt":"q","completion":"a"}`, "chat", true},
		{`{"messages":[{"role":"user","content":"hi"}]}`, "chat", true},
		{`{"messages":"not-an-array"}`, "text", true}, // malformed -> raw treated as text
		{`{not valid json`, "text", true},             // starts with { but broken -> text
		{"   ", "", false},                            // blank -> dropped
	}
	for _, c := range cases {
		got, ok := parseExample(c.in)
		if ok != c.wantOK || (ok && got.format != c.wantFormat) {
			t.Fatalf("parseExample(%q) = (%+v, %v), want format %q ok %v", c.in, got, ok, c.wantFormat, c.wantOK)
		}
	}
}

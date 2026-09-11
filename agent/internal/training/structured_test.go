package training

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// structData is a DataSource that returns chunks carrying structured OpenAI messages/tools — the
// shape ingest produces for Q&A / multi-turn / tool-calling uploads.
type structData struct{}

func (structData) Collection(name string) (Collection, bool) {
	if name != "agentic" {
		return Collection{}, false
	}
	return Collection{Chunks: []Chunk{
		{Text: "plain fact", Classification: "internal", Format: "text"},
		{Text: "weather Paris get_weather", Classification: "internal", Format: "chat",
			Messages: json.RawMessage(`[{"role":"user","content":"weather?"},{"role":"assistant","tool_calls":[{"id":"c1","type":"function","function":{"name":"get_weather","arguments":"{}"}}]}]`),
			Tools:    json.RawMessage(`[{"type":"function","function":{"name":"get_weather"}}]`)},
	}}, true
}

// captureTrainer reads the STAGED dataset file (what a real GPU trainer opens) so the test can assert
// the structured examples actually reached it — proving the messages/tools survive staging.
type captureTrainer struct{ staged []byte }

func (c *captureTrainer) Run(_ context.Context, spec Spec, onCkpt func(int, int)) (Result, error) {
	b, err := os.ReadFile(spec.DatasetFile)
	if err != nil {
		return Result{}, err
	}
	c.staged = b
	onCkpt(1, 1)
	return Result{Bytes: []byte("adapter"), Evals: map[string]float64{"task": 0.9, "safety": 1}}, nil
}

// TestStructuredDataReachesTrainer: a Q&A/tool-calling dataset stages with its messages + tool_calls
// intact in the file the trainer reads — the agentic fine-tune contract.
func TestStructuredDataReachesTrainer(t *testing.T) {
	cap := &captureTrainer{}
	sub, _ := newSub(t, stubIdent{"alice": "restricted"}, nil, stubFleet{uuid: "trainer-1"}, cap)
	sub.data = structData{}
	if _, err := sub.Submit(context.Background(), Request{BaseModelID: "qwen", Collection: "agentic", Engineer: "alice", Method: "lora"}); err != nil {
		t.Fatalf("submit: %v", err)
	}
	if cap.staged == nil {
		t.Fatal("trainer never received a staged dataset")
	}
	var staged struct {
		Chunks []struct {
			Format   string          `json:"format"`
			Messages json.RawMessage `json:"messages"`
			Tools    json.RawMessage `json:"tools"`
		} `json:"chunks"`
	}
	if err := json.Unmarshal(cap.staged, &staged); err != nil {
		t.Fatalf("staged dataset is not valid JSON: %v", err)
	}
	if len(staged.Chunks) != 2 {
		t.Fatalf("want 2 staged chunks, got %d", len(staged.Chunks))
	}
	// the structured chunk kept its OpenAI messages (incl. tool_calls) and its tools schema
	var chat *int
	for i, c := range staged.Chunks {
		if c.Format == "chat" {
			idx := i
			chat = &idx
		}
	}
	if chat == nil {
		t.Fatal("no chat-format chunk survived staging")
	}
	c := staged.Chunks[*chat]
	if !strings.Contains(string(c.Messages), "tool_calls") || !strings.Contains(string(c.Messages), "get_weather") {
		t.Fatalf("tool-calling messages didn't reach the trainer: %s", c.Messages)
	}
	if !strings.Contains(string(c.Tools), "get_weather") {
		t.Fatalf("tools schema didn't reach the trainer: %s", c.Tools)
	}
}

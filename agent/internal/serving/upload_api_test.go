package serving

// The console's dataset-upload path: POST /dani/ingest with docs registers + ingests a custom
// collection; it becomes trainable like any connector corpus.

import (
	"net/http"
	"testing"
	"time"
)

func TestIngestUploadEndToEnd(t *testing.T) {
	api := newTrainingAPI(t, "trainer-1")
	mux := serveTraining(api)

	// upload + ingest in one call
	rec := postJSON(t, mux, "/dani/ingest", map[string]any{
		"collection":     "deals",
		"docs":           []string{"The pilot contract covers 40 seats.", "Renewal risk is priced into Q4."},
		"classification": "internal",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("upload ingest: %d %s", rec.Code, rec.Body)
	}
	// listed among collections + corpora
	var cols struct {
		Collections []struct {
			Name      string `json:"name"`
			Connector string `json:"connector"`
			Class     string `json:"classification"`
		} `json:"collections"`
		Corpora []string `json:"corpora"`
	}
	getJSON(t, mux, "/dani/collections", &cols)
	haveCol, haveCorpus := false, false
	for _, c := range cols.Collections {
		if c.Name == "deals" && c.Connector == "upload" && c.Class == "restricted" { // "risk" raised it
			haveCol = true
		}
	}
	for _, n := range cols.Corpora {
		if n == "deals" {
			haveCorpus = true
		}
	}
	if !haveCol || !haveCorpus {
		t.Fatalf("upload must appear in collections+corpora: %+v", cols)
	}
	// and it TRAINS like any dataset (alice restricted >= deals restricted)
	rec = postJSON(t, mux, "/dani/train/submit", map[string]string{
		"engineer": "alice", "base": "qwen2.5-0.5b", "collection": "deals", "method": "lora"})
	if rec.Code != http.StatusAccepted {
		t.Fatalf("train on upload: %d %s", rec.Code, rec.Body)
	}
	// wait for the async Execute to reach a terminal state — otherwise it keeps writing staged
	// datasets/artifacts inside the test's temp store while t.TempDir cleanup runs (a live-caught
	// Windows unlinkat flake).
	deadline := time.Now().Add(5 * time.Second)
	for {
		var jobs struct {
			Jobs []struct {
				State string `json:"state"`
			} `json:"jobs"`
		}
		getJSON(t, mux, "/dani/train/jobs", &jobs)
		if len(jobs.Jobs) == 1 && (jobs.Jobs[0].State == "completed" || jobs.Jobs[0].State == "failed") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("training job never reached a terminal state")
		}
		time.Sleep(50 * time.Millisecond)
	}
	// a bad upload is refused with the ingest error surfaced
	if rec := postJSON(t, mux, "/dani/ingest", map[string]any{"collection": "legal", "docs": []string{"x"}}); rec.Code != http.StatusBadRequest {
		t.Fatalf("built-in name clash must 400: %d", rec.Code)
	}
}

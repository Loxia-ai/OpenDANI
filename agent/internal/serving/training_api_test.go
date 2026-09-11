package serving

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"dani.local/agent/internal/artifact"
	"dani.local/agent/internal/audit"
	"dani.local/agent/internal/identity"
	"dani.local/agent/internal/ingest"
	"dani.local/agent/internal/kms"
	"dani.local/agent/internal/modelreg"
	"dani.local/agent/internal/policy"
	"dani.local/agent/internal/training"
)

// fixedFleet satisfies training.Fleet without a Node Registry (local execution: no addr).
type fixedFleet struct{ uuid string }

func (f fixedFleet) ActiveTrainer() (string, string, bool) { return f.uuid, "", f.uuid != "" }

func newTrainingAPI(t *testing.T, trainerNode string) *TrainingAPI {
	t.Helper()
	ks, err := kms.NewSoftware()
	if err != nil {
		t.Fatal(err)
	}
	store, err := artifact.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	models := modelreg.New(ks, store)
	if err := models.InitSigners(context.Background()); err != nil {
		t.Fatal(err)
	}
	ident := identity.New("entra-id")
	ing := ingest.New()
	sub := training.New(training.Deps{
		Identity: IdentAdapter{B: ident}, Data: IngestAdapter{S: ing},
		Fleet: fixedFleet{trainerNode}, Registry: models, Store: store, Trainer: training.StubTrainer{},
	})
	return &TrainingAPI{Ident: ident, Ingest: ing, Models: models, Training: sub, Store: store, Policy: policy.New(0, 0)}
}

// serveTraining builds a mux with the training routes attached via the Plane path (EnableTraining +
// registerTrainingRoutes), so the wiring itself is covered.
func serveTraining(api *TrainingAPI) *http.ServeMux {
	p := &Plane{workers: map[string]*workerState{}, inflight: map[string]int{}, stale: time.Minute}
	p.EnableTraining(api)
	mux := http.NewServeMux()
	p.registerTrainingRoutes(mux)
	return mux
}

func postJSON(t *testing.T, mux *http.ServeMux, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(b))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func getJSON(t *testing.T, mux *http.ServeMux, path string, into any) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if into != nil {
		if err := json.Unmarshal(rec.Body.Bytes(), into); err != nil {
			t.Fatalf("bad JSON from %s: %v", path, err)
		}
	}
	return rec
}

func TestRegisterTrainingRoutesNoop(t *testing.T) {
	p := &Plane{} // EnableTraining never called
	mux := http.NewServeMux()
	p.registerTrainingRoutes(mux)
	req := httptest.NewRequest(http.MethodGet, "/dani/train/jobs", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("routes must not exist without EnableTraining, got %d", rec.Code)
	}
}

// TestTrainSignServeStory drives the whole console flow over the HTTP surface:
// ingest -> submit -> job completes -> candidate draft -> 3 signs -> available —
// with the audit chain recording (and verifying) every step.
func TestTrainSignServeStory(t *testing.T) {
	api := newTrainingAPI(t, "trainer-1")
	ks, _ := kms.NewSoftware()
	aud, err := audit.Open(context.Background(), ":memory:", ks)
	if err != nil {
		t.Fatal(err)
	}
	api.Audit = aud
	mux := serveTraining(api)

	// principals + empty collections up front
	var pr struct {
		Principals []identity.Principal `json:"principals"`
	}
	getJSON(t, mux, "/dani/principals", &pr)
	if len(pr.Principals) != 4 {
		t.Fatalf("expected 4 seeded principals, got %d", len(pr.Principals))
	}
	var cols struct {
		Collections []map[string]any `json:"collections"`
		Corpora     []string         `json:"corpora"`
	}
	getJSON(t, mux, "/dani/collections", &cols)
	if len(cols.Collections) != 0 || len(cols.Corpora) != 3 {
		t.Fatalf("fresh state wrong: %+v", cols)
	}

	// ingest legal (classify-at-ingest)
	if rec := postJSON(t, mux, "/dani/ingest", map[string]string{"collection": "legal"}); rec.Code != http.StatusOK {
		t.Fatalf("ingest: %d %s", rec.Code, rec.Body)
	}
	getJSON(t, mux, "/dani/collections", &cols)
	if len(cols.Collections) != 1 || cols.Collections[0]["classification"] != "restricted" {
		t.Fatalf("collection classification wrong: %+v", cols.Collections)
	}

	// submit as alice (clearance restricted — exactly the data class)
	rec := postJSON(t, mux, "/dani/train/submit", map[string]string{
		"engineer": "alice", "base": "qwen2.5-1.5b", "collection": "legal", "method": "lora",
	})
	if rec.Code != http.StatusAccepted {
		t.Fatalf("submit: %d %s", rec.Code, rec.Body)
	}
	var job training.Job
	_ = json.Unmarshal(rec.Body.Bytes(), &job)

	// the async Execute finishes fast with the stub; poll the jobs endpoint
	deadline := time.Now().Add(5 * time.Second)
	var jobs struct {
		Jobs []training.Job `json:"jobs"`
	}
	for {
		getJSON(t, mux, "/dani/train/jobs", &jobs)
		if len(jobs.Jobs) == 1 && jobs.Jobs[0].State == "completed" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("job did not complete: %+v", jobs.Jobs)
		}
		time.Sleep(10 * time.Millisecond)
	}
	cand := jobs.Jobs[0].Candidate

	// candidate is a draft; sign with all three roles over HTTP
	var models struct {
		Models []struct {
			ID         string   `json:"id"`
			State      string   `json:"state"`
			Base       string   `json:"base"`
			Signatures []string `json:"signatures"`
		} `json:"models"`
	}
	getJSON(t, mux, "/dani/models", &models)
	if len(models.Models) != 1 || models.Models[0].State != "draft" || models.Models[0].Base != "qwen2.5-1.5b" {
		t.Fatalf("candidate wrong: %+v", models.Models)
	}
	for _, role := range []string{"security-officer", "governance-officer", "administrator"} {
		if rec := postJSON(t, mux, "/dani/models/sign", map[string]string{"model": cand, "role": role}); rec.Code != http.StatusOK {
			t.Fatalf("sign %s: %d %s", role, rec.Code, rec.Body)
		}
	}
	getJSON(t, mux, "/dani/models", &models)
	if models.Models[0].State != "available" || len(models.Models[0].Signatures) != 3 {
		t.Fatalf("promotion failed: %+v", models.Models[0])
	}
	if api.Models.Resolve(cand) == nil {
		t.Fatal("promoted model must resolve (routable)")
	}

	// the audit chain recorded the story and VERIFIES
	var audresp struct {
		Records   int64 `json:"records"`
		Integrity struct {
			OK bool `json:"ok"`
		} `json:"integrity"`
		Recent []struct {
			Type string `json:"type"`
		} `json:"recent"`
	}
	getJSON(t, mux, "/dani/audit", &audresp)
	if !audresp.Integrity.OK || audresp.Records < 5 {
		t.Fatalf("audit chain unhealthy: %+v", audresp)
	}
	types := map[string]bool{}
	for _, e := range audresp.Recent {
		types[e.Type] = true
	}
	for _, want := range []string{"ingest.complete", "training.start", "model.signed", "model.approved"} {
		if !types[want] {
			t.Fatalf("audit missing %q; got %v", want, types)
		}
	}
}

func TestAuditEndpointWithoutChain(t *testing.T) {
	api := newTrainingAPI(t, "trainer-1") // no Audit wired
	mux := serveTraining(api)
	if rec := getJSON(t, mux, "/dani/audit", nil); rec.Code != http.StatusNotFound {
		t.Fatalf("audit endpoint without a chain must 404, got %d", rec.Code)
	}
}

func TestAuditEndpointStoreError(t *testing.T) {
	api := newTrainingAPI(t, "trainer-1")
	ks, _ := kms.NewSoftware()
	aud, err := audit.Open(context.Background(), ":memory:", ks)
	if err != nil {
		t.Fatal(err)
	}
	aud.Emit("a", nil)
	aud.Close() // Verify will fail against the closed store
	api.Audit = aud
	mux := serveTraining(api)
	if rec := getJSON(t, mux, "/dani/audit", nil); rec.Code != http.StatusInternalServerError {
		t.Fatalf("closed audit store must 500, got %d", rec.Code)
	}
}

func TestArtifactPullGatedByVerifyOnUse(t *testing.T) {
	api := newTrainingAPI(t, "trainer-1")
	mux := serveTraining(api)
	postJSON(t, mux, "/dani/ingest", map[string]string{"collection": "hr"})
	rec := postJSON(t, mux, "/dani/train/submit", map[string]string{
		"engineer": "bob", "base": "m", "collection": "hr", "method": "lora",
	})
	if rec.Code != http.StatusAccepted {
		t.Fatalf("submit: %d %s", rec.Code, rec.Body)
	}
	// wait for the async job, get the candidate id
	deadline := time.Now().Add(5 * time.Second)
	var cand string
	for cand == "" {
		var jobs struct {
			Jobs []training.Job `json:"jobs"`
		}
		getJSON(t, mux, "/dani/train/jobs", &jobs)
		if len(jobs.Jobs) == 1 && jobs.Jobs[0].State == "completed" {
			cand = jobs.Jobs[0].Candidate
		}
		if time.Now().After(deadline) {
			t.Fatal("job never completed")
		}
		time.Sleep(10 * time.Millisecond)
	}
	// DRAFT: pull refused (DP13 — not routable, not pullable)
	if rec := getJSON(t, mux, "/dani/models/artifact?id="+cand, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("draft pull must be refused, got %d", rec.Code)
	}
	// unknown model: refused
	if rec := getJSON(t, mux, "/dani/models/artifact?id=ghost", nil); rec.Code != http.StatusForbidden {
		t.Fatal("unknown model pull must be refused")
	}
	// promote, then the pull serves the exact bytes with the content hash
	for _, role := range []string{"security-officer", "governance-officer", "administrator"} {
		postJSON(t, mux, "/dani/models/sign", map[string]string{"model": cand, "role": role})
	}
	rec2 := getJSON(t, mux, "/dani/models/artifact?id="+cand, nil)
	if rec2.Code != http.StatusOK {
		t.Fatalf("promoted pull failed: %d %s", rec2.Code, rec2.Body)
	}
	hash := rec2.Header().Get("X-Dani-Artifact-Hash")
	if artifact.HashOf(rec2.Body.Bytes()) != hash {
		t.Fatal("served bytes must match the advertised content hash")
	}
	if rec2.Header().Get("X-Dani-Model-Base") != "m" {
		t.Fatal("base header missing")
	}
	// corrupt the stored blob: Resolve still passes (hash unchanged in the entry) but the store's
	// verify-on-read catches it
	e := api.Models.Get(cand)
	os.WriteFile(api.Store.Path(e.Artifact.Hash), []byte("tampered"), 0o600)
	if rec := getJSON(t, mux, "/dani/models/artifact?id="+cand, nil); rec.Code != http.StatusInternalServerError {
		t.Fatalf("corrupted blob must fail verify-on-read, got %d", rec.Code)
	}
}

func TestSubmitAuthZDeniedOverHTTP(t *testing.T) {
	api := newTrainingAPI(t, "trainer-1")
	mux := serveTraining(api)
	postJSON(t, mux, "/dani/ingest", map[string]string{"collection": "legal"}) // restricted data
	// carol has clearance internal < restricted
	rec := postJSON(t, mux, "/dani/train/submit", map[string]string{
		"engineer": "carol", "base": "m", "collection": "legal",
	})
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "AuthZ denied") {
		t.Fatalf("expected 403 AuthZ denial, got %d %s", rec.Code, rec.Body)
	}
}

func TestSubmitNoTrainerOverHTTP(t *testing.T) {
	api := newTrainingAPI(t, "") // no trainer hardware
	mux := serveTraining(api)
	postJSON(t, mux, "/dani/ingest", map[string]string{"collection": "hr"})
	rec := postJSON(t, mux, "/dani/train/submit", map[string]string{
		"engineer": "bob", "base": "m", "collection": "hr",
	})
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "D17") {
		t.Fatalf("expected D17 no-trainer denial, got %d %s", rec.Code, rec.Body)
	}
}

func TestTrainingEndpointErrors(t *testing.T) {
	api := newTrainingAPI(t, "trainer-1")
	mux := serveTraining(api)

	// method guards
	for _, path := range []string{"/dani/ingest", "/dani/train/submit", "/dani/models/sign"} {
		rec := getJSON(t, mux, path, nil)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("GET %s should be 405, got %d", path, rec.Code)
		}
	}
	// bad bodies
	for _, path := range []string{"/dani/ingest", "/dani/train/submit", "/dani/models/sign"} {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader("{not json"))
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("POST %s bad body should be 400, got %d", path, rec.Code)
		}
	}
	// unknown corpus
	if rec := postJSON(t, mux, "/dani/ingest", map[string]string{"collection": "area51"}); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown corpus should 404, got %d", rec.Code)
	}
	// sign unknown model
	if rec := postJSON(t, mux, "/dani/models/sign", map[string]string{"model": "ghost", "role": "administrator"}); rec.Code != http.StatusBadRequest {
		t.Fatalf("sign unknown model should 400, got %d", rec.Code)
	}
}

func TestAdapters(t *testing.T) {
	ident := identity.New("entra-id")
	ia := IdentAdapter{B: ident}
	if p, ok := ia.Resolve("bob"); !ok || p.Clearance != "secret" || p.Name != "bob" {
		t.Fatalf("IdentAdapter: %+v ok=%v", p, ok)
	}
	if _, ok := ia.Resolve("mallory"); ok {
		t.Fatal("unknown engineer must not resolve")
	}
	ing := ingest.New()
	ing.Ingest("hr")
	ga := IngestAdapter{S: ing}
	col, ok := ga.Collection("hr")
	if !ok || len(col.Chunks) == 0 || col.Chunks[0].Classification == "" {
		t.Fatalf("IngestAdapter: %+v ok=%v", col, ok)
	}
	if _, ok := ga.Collection("nope"); ok {
		t.Fatal("unknown collection must not resolve")
	}
}

func TestShortHash(t *testing.T) {
	if got := shortHash("sha256:0123456789abcdef0123"); !strings.HasPrefix(got, "sha256:0123") || !strings.HasSuffix(got, "…") {
		t.Fatalf("shortHash long: %q", got)
	}
	if got := shortHash("tiny"); got != "tiny" {
		t.Fatalf("shortHash short: %q", got)
	}
}

// TestAuditExportEndpoint: the Compliance-tier export returns a signed bundle that verifies offline.
func TestAuditExportEndpoint(t *testing.T) {
	api := newTrainingAPI(t, "trainer-1")
	ks, _ := kms.NewSoftware()
	aud, err := audit.Open(context.Background(), ":memory:", ks)
	if err != nil {
		t.Fatal(err)
	}
	api.Audit = aud
	mux := serveTraining(api)
	// generate a couple of events
	postJSON(t, mux, "/dani/ingest", map[string]string{"collection": "legal"})

	var out struct {
		Deployment    string          `json:"deployment"`
		Events        int             `json:"events"`
		OfflineVerify audit.Integrity `json:"offlineVerify"`
		Bundle        audit.ComplianceBundle `json:"bundle"`
	}
	getJSON(t, mux, "/dani/audit/export?deployment=dep-42", &out)
	if out.Deployment != "dep-42" || out.Events == 0 || !out.OfflineVerify.OK {
		t.Fatalf("export must return a verifiable bundle: %+v", out)
	}
	// the returned bundle itself re-verifies offline (independent of the endpoint's self-check)
	if integ, _ := audit.VerifyBundle(&out.Bundle); !integ.OK {
		t.Fatalf("returned bundle must verify standalone: %+v", integ)
	}
}

// TestAuditExportNoChain: export with no audit chain enabled -> 404.
func TestAuditExportNoChain(t *testing.T) {
	api := newTrainingAPI(t, "trainer-1")
	api.Audit = nil
	mux := serveTraining(api)
	rec := getJSON(t, mux, "/dani/audit/export", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("no chain -> 404, got %d", rec.Code)
	}
}

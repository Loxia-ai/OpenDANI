package serving

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"dani.local/agent/internal/modelreg"
	"dani.local/agent/internal/policy"
)

// promoteACandidate runs a training job to completion and fully signs it, returning the model id.
func promoteACandidate(t *testing.T, api *TrainingAPI, mux *http.ServeMux) string {
	t.Helper()
	postJSON(t, mux, "/dani/ingest", map[string]string{"collection": "hr"}) // internal data
	rec := postJSON(t, mux, "/dani/train/submit", map[string]string{
		"engineer": "bob", "base": "m", "collection": "hr", "method": "lora",
	})
	if rec.Code != http.StatusAccepted {
		t.Fatalf("submit: %d %s", rec.Code, rec.Body)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		var jobs struct {
			Jobs []struct{ State, Candidate string } `json:"jobs"`
		}
		getJSON(t, mux, "/dani/train/jobs", &jobs)
		if len(jobs.Jobs) > 0 && jobs.Jobs[len(jobs.Jobs)-1].State == "completed" {
			cand := jobs.Jobs[len(jobs.Jobs)-1].Candidate
			for _, role := range []string{"security-officer", "governance-officer", "administrator"} {
				postJSON(t, mux, "/dani/models/sign", map[string]string{"model": cand, "role": role})
			}
			return cand
		}
		if time.Now().After(deadline) {
			t.Fatal("job never completed")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestDeploymentAssignmentAndReport(t *testing.T) {
	api := newTrainingAPI(t, "trainer-1")
	api.Live = func(string) bool { return true } // liveness is exercised by the re-assignment test
	mux := serveTraining(api)
	cand := promoteACandidate(t, api, mux) // classification internal (hr data)

	// an under-cleared poller gets nothing (D-09: its clearance does not dominate the model)
	var out struct {
		Deployments []Deployment `json:"deployments"`
	}
	getJSON(t, mux, "/dani/deployments?node=low-node&class=unrestricted", &out)
	if len(out.Deployments) != 0 {
		t.Fatalf("under-cleared node must not be assigned: %+v", out.Deployments)
	}
	// a capable poller claims it
	getJSON(t, mux, "/dani/deployments?node=worker-a&class=restricted", &out)
	if len(out.Deployments) != 1 || out.Deployments[0].Model != cand || out.Deployments[0].State != "assigned" {
		t.Fatalf("assignment wrong: %+v", out.Deployments)
	}
	// a second poller does NOT get the same model (already placed), and the first still sees it
	getJSON(t, mux, "/dani/deployments?node=worker-b&class=secret", &out)
	if len(out.Deployments) != 0 {
		t.Fatal("model must be assigned to exactly one node")
	}
	getJSON(t, mux, "/dani/deployments?node=worker-a&class=restricted", &out)
	if len(out.Deployments) != 1 {
		t.Fatal("assignee must keep seeing its placement")
	}
	// report loaded
	rec := postJSON(t, mux, "/dani/deployments/report", map[string]string{"node": "worker-a", "model": cand})
	if rec.Code != http.StatusOK {
		t.Fatalf("report: %d %s", rec.Code, rec.Body)
	}
	if ds := api.deploymentsOf(cand); len(ds) != 1 || ds[0].State != "loaded" {
		t.Fatalf("placement not marked loaded: %+v", ds)
	}
	// the model list carries the placement (console renders it)
	var models struct {
		Models []struct {
			ID         string      `json:"id"`
			Deployment *Deployment `json:"deployment"`
		} `json:"models"`
	}
	getJSON(t, mux, "/dani/models", &models)
	if models.Models[0].Deployment == nil || models.Models[0].Deployment.Node != "worker-a" {
		t.Fatalf("model row missing deployment: %+v", models.Models[0])
	}
}

func TestDeploymentEndpointErrors(t *testing.T) {
	api := newTrainingAPI(t, "trainer-1")
	mux := serveTraining(api)
	if rec := getJSON(t, mux, "/dani/deployments", nil); rec.Code != http.StatusBadRequest {
		t.Fatal("missing node must 400")
	}
	if rec := getJSON(t, mux, "/dani/deployments/report", nil); rec.Code != http.StatusMethodNotAllowed {
		t.Fatal("GET report must 405")
	}
	if rec := postJSON(t, mux, "/dani/deployments/report", "{bad"); rec.Code != http.StatusBadRequest {
		t.Fatal("bad body must 400")
	}
	if rec := postJSON(t, mux, "/dani/deployments/report", map[string]string{"node": "x", "model": "ghost"}); rec.Code != http.StatusNotFound {
		t.Fatal("unknown assignment must 404")
	}
	// admin-registered bases (no lineage) never auto-deploy
	api.Models.Register(context.Background(), modelreg.RegisterMeta{ID: "base-x", Name: "base-x", Version: "1", Engine: "e"}, []byte("w"))
	var out struct {
		Deployments []Deployment `json:"deployments"`
	}
	getJSON(t, mux, "/dani/deployments?node=n&class=secret", &out)
	for _, d := range out.Deployments {
		if d.Model == "base-x" {
			t.Fatal("bases must not auto-deploy")
		}
	}
}

func httptestNewRecorder() *httptest.ResponseRecorder { return httptest.NewRecorder() }

func TestRouterMatchesHotLoadedModels(t *testing.T) {
	p := newTestPlane("site-hq",
		workerState{Heartbeat: Heartbeat{NodeUUID: "w1", DispatchAddr: "w1:9443", ModelID: "base",
			Class: "restricted", MaxConcurrent: 2, QueueDepth: 4, Health: "healthy",
			Loaded: []string{"base-ft-hr-v1"}, HotLoad: true}},
	)
	// the hot-loaded model routes
	c, ok := p.reserve("base-ft-hr-v1", "unrestricted", "", nil)
	if !ok || c.uuid != "w1" {
		t.Fatalf("hot-loaded model must route: %v %v", c, ok)
	}
	p.release("w1")
	// unknown model still refused
	if _, ok := p.reserve("nope", "unrestricted", "", nil); ok {
		t.Fatal("unknown model must not route")
	}
	// ETA sees it too
	if _, any := p.fleetETA("base-ft-hr-v1", "unrestricted"); !any {
		t.Fatal("fleetETA must match hot-loaded models")
	}
	// /v1/models lists it
	req, _ := http.NewRequest(http.MethodGet, "/v1/models", nil)
	rec := httptestNewRecorder()
	p.handleModels(rec, req)
	var ml struct {
		Data []struct{ ID string } `json:"data"`
	}
	json.Unmarshal(rec.Body.Bytes(), &ml)
	found := false
	for _, m := range ml.Data {
		if m.ID == "base-ft-hr-v1" {
			found = true
		}
	}
	if !found {
		t.Fatalf("hot-loaded model missing from /v1/models: %+v", ml.Data)
	}
}

func TestDeploymentReassignsFromDeadNode(t *testing.T) {
	api := newTrainingAPI(t, "trainer-1")
	alive := map[string]bool{"worker-a": true, "worker-b": true}
	api.Live = func(node string) bool { return alive[node] }
	mux := serveTraining(api)
	cand := promoteACandidate(t, api, mux)

	var out struct {
		Deployments []Deployment `json:"deployments"`
	}
	// worker-a claims it and loads it
	getJSON(t, mux, "/dani/deployments?node=worker-a&class=secret", &out)
	if len(out.Deployments) != 1 {
		t.Fatalf("claim failed: %+v", out.Deployments)
	}
	postJSON(t, mux, "/dani/deployments/report", map[string]string{"node": "worker-a", "model": cand})
	// while worker-a is ALIVE, worker-b gets nothing
	getJSON(t, mux, "/dani/deployments?node=worker-b&class=secret", &out)
	if len(out.Deployments) != 0 {
		t.Fatal("live placement must not be stolen")
	}
	// worker-a dies -> worker-b's next poll takes the placement over
	alive["worker-a"] = false
	getJSON(t, mux, "/dani/deployments?node=worker-b&class=secret", &out)
	if len(out.Deployments) != 1 || out.Deployments[0].State != "assigned" || out.Deployments[0].Node != "worker-b" {
		t.Fatalf("dead-node placement must re-assign: %+v", out.Deployments)
	}
	// an under-cleared poller cannot take it even from a corpse
	alive["worker-b"] = false
	getJSON(t, mux, "/dani/deployments?node=low&class=unrestricted", &out)
	if len(out.Deployments) != 0 {
		t.Fatal("re-assignment must still respect clearance dominance")
	}
	if ds := api.deploymentsOf(cand); len(ds) != 1 || ds[0].Node != "worker-b" {
		t.Fatalf("placement moved to an ineligible node: %+v", ds)
	}
}

func TestSignHandlerReportsGateFailure(t *testing.T) {
	api := newTrainingAPI(t, "trainer-1")
	api.Models.SetGate(modelreg.EvalGate{MinTask: 0.9}) // stub trainer emits task ~0.7-0.85 < 0.9
	mux := serveTraining(api)
	postJSON(t, mux, "/dani/ingest", map[string]string{"collection": "hr"})
	rec := postJSON(t, mux, "/dani/train/submit", map[string]string{
		"engineer": "bob", "base": "m", "collection": "hr", "method": "lora"})
	if rec.Code != http.StatusAccepted {
		t.Fatalf("submit: %d", rec.Code)
	}
	deadline := time.Now().Add(5 * time.Second)
	var cand string
	for cand == "" {
		var jobs struct {
			Jobs []struct{ State, Candidate string } `json:"jobs"`
		}
		getJSON(t, mux, "/dani/train/jobs", &jobs)
		if len(jobs.Jobs) > 0 && jobs.Jobs[0].State == "completed" {
			cand = jobs.Jobs[0].Candidate
		}
		if time.Now().After(deadline) {
			t.Fatal("job never completed")
		}
		time.Sleep(10 * time.Millisecond)
	}
	// sign all three; the promoting signature reports the gate failure, model stays draft
	var last struct {
		State      string `json:"state"`
		GateFailed string `json:"gate_failed"`
	}
	for _, role := range []string{"security-officer", "governance-officer", "administrator"} {
		r := postJSON(t, mux, "/dani/models/sign", map[string]string{"model": cand, "role": role})
		json.Unmarshal(r.Body.Bytes(), &last)
	}
	if last.State != "draft" || last.GateFailed == "" {
		t.Fatalf("gate must hold a low-quality candidate at draft: %+v", last)
	}
	if api.Models.Resolve(cand) != nil {
		t.Fatal("gate-held model must not route")
	}
	// it is NOT offered for auto-deploy either (Resolve is nil)
	var out struct {
		Deployments []Deployment `json:"deployments"`
	}
	getJSON(t, mux, "/dani/deployments?node=w&class=secret", &out)
	for _, d := range out.Deployments {
		if d.Model == cand {
			t.Fatal("gate-held model must not auto-deploy")
		}
	}
}

func TestGatewayPlainPathPolicy(t *testing.T) {
	api := newTrainingAPI(t, "trainer-1")
	api.Policy = policy.New(0, 0)
	p := newTestPlane("site-hq", hb("w", "qwen2.5-0.5b", "secret", "site-hq", 100))
	p.EnableTraining(api)

	// carol (internal) on restricted content -> policy 403 BEFORE any routing
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions",
		strings.NewReader(`{"model":"qwen2.5-0.5b","messages":[{"role":"user","content":"show me patient diagnosis records"}]}`))
	req.Header.Set("X-Dani-User", "carol")
	rec := httptest.NewRecorder()
	p.handleGateway(rec, req)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "policy") {
		t.Fatalf("plain-path policy must deny, got %d %s", rec.Code, rec.Body)
	}
	// banned content -> denied for anyone
	req2 := httptest.NewRequest(http.MethodPost, "/v1/chat/completions",
		strings.NewReader(`{"model":"qwen2.5-0.5b","messages":[{"role":"user","content":"disable audit now"}]}`))
	req2.Header.Set("X-Dani-User", "bob")
	rec2 := httptest.NewRecorder()
	p.handleGateway(rec2, req2)
	if rec2.Code != http.StatusForbidden {
		t.Fatalf("banned content must be denied, got %d", rec2.Code)
	}
	// unknown attributed user -> best-effort pass-through (no worker to serve -> 503, not 403)
	req3 := httptest.NewRequest(http.MethodPost, "/v1/chat/completions",
		strings.NewReader(`{"model":"nomodel","messages":[{"role":"user","content":"hi"}]}`))
	req3.Header.Set("X-Dani-User", "mallory")
	rec3 := httptest.NewRecorder()
	p.handleGateway(rec3, req3)
	if rec3.Code == http.StatusForbidden {
		t.Fatal("unknown attribution must not be policy-denied (best-effort)")
	}
}

func TestApplyPolicyClassificationPassthrough(t *testing.T) {
	api := newTrainingAPI(t, "trainer-1")
	api.Policy = policy.New(0, 0)
	p := newTestPlane("site")
	p.EnableTraining(api)
	rec := httptest.NewRecorder()
	// alice (restricted) benign prompt -> allowed, classification unrestricted (content-only)
	cls, ok := p.applyPolicy(rec, "alice", []byte(`{"messages":[{"role":"user","content":"hello"}]}`))
	if !ok || cls != "unrestricted" {
		t.Fatalf("benign prompt: ok=%v cls=%q", ok, cls)
	}
	// alice restricted content -> allowed, classification restricted
	cls2, ok2 := p.applyPolicy(rec, "alice", []byte(`{"messages":[{"role":"user","content":"the risk report"}]}`))
	if !ok2 || cls2 != "restricted" {
		t.Fatalf("restricted content: ok=%v cls=%q", ok2, cls2)
	}
}

// TestDurableDeployments: placements survive a controller restart — a fresh table over the same
// snapshot rehydrates the placement instead of re-assigning it; loaded-state changes persist too.
func TestDurableDeployments(t *testing.T) {
	snap := filepath.Join(t.TempDir(), "deployments.json")
	api := newTrainingAPI(t, "trainer-1")
	api.Live = func(string) bool { return true }
	api.Deploys = NewDurableDeployments(snap)
	mux := serveTraining(api)
	cand := promoteACandidate(t, api, mux)

	var out struct {
		Deployments []Deployment `json:"deployments"`
	}
	getJSON(t, mux, "/dani/deployments?node=worker-a&class=secret", &out)
	if len(out.Deployments) != 1 {
		t.Fatalf("assignment expected, got %d", len(out.Deployments))
	}
	postJSON(t, mux, "/dani/deployments/report", map[string]string{"node": "worker-a", "model": cand})

	// "restart": fresh table over the same snapshot
	re := NewDurableDeployments(snap)
	ds := re.byMod[cand]
	if len(ds) != 1 || ds[0].Node != "worker-a" || ds[0].State != "loaded" {
		t.Fatalf("placement must survive the restart: %+v", ds)
	}
	// and the rehydrated table prevents a duplicate assignment: another poller gets nothing
	api.Deploys = re
	var out2 struct {
		Deployments []Deployment `json:"deployments"`
	}
	getJSON(t, mux, "/dani/deployments?node=worker-b&class=secret", &out2)
	if len(out2.Deployments) != 0 {
		t.Fatalf("rehydrated placement must not be re-assigned: %+v", out2.Deployments)
	}

	// corrupt snapshot is LENIENT (placements are reconstructible): starts empty, no error
	bad := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(bad, []byte("{nope"), 0o600); err != nil {
		t.Fatal(err)
	}
	if fresh := NewDurableDeployments(bad); len(fresh.byMod) != 0 {
		t.Fatal("corrupt placement snapshot must start empty")
	}
}

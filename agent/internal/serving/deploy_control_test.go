package serving

// Operator distribution control (console "distribute models"): replica scaling, node pinning,
// undeploy, and the durable v2 snapshot (placements + desired counts).

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

// getJSONBody decodes a recorded response body.
func getJSONBody(t *testing.T, body []byte, into any) {
	t.Helper()
	if err := json.Unmarshal(body, into); err != nil {
		t.Fatalf("bad JSON body: %v (%s)", err, body)
	}
}

func TestReplicaScaleUpAssignsMultipleNodes(t *testing.T) {
	api := newTrainingAPI(t, "trainer-1")
	api.Live = func(string) bool { return true }
	mux := serveTraining(api)
	cand := promoteACandidate(t, api, mux)

	// scale to 2 replicas
	rec := postJSON(t, mux, "/dani/models/deploy", map[string]any{"model": cand, "replicas": 2})
	if rec.Code != http.StatusOK {
		t.Fatalf("scale: %d %s", rec.Code, rec.Body)
	}
	var out struct {
		Deployments []Deployment `json:"deployments"`
	}
	// two capable pollers each get a placement; a third gets nothing
	getJSON(t, mux, "/dani/deployments?node=worker-a&class=secret", &out)
	if len(out.Deployments) != 1 {
		t.Fatalf("worker-a claim: %+v", out.Deployments)
	}
	getJSON(t, mux, "/dani/deployments?node=worker-b&class=secret", &out)
	if len(out.Deployments) != 1 {
		t.Fatalf("worker-b claim: %+v", out.Deployments)
	}
	getJSON(t, mux, "/dani/deployments?node=worker-c&class=secret", &out)
	if len(out.Deployments) != 0 {
		t.Fatal("third node must not exceed replicas=2")
	}
	if ds := api.deploymentsOf(cand); len(ds) != 2 {
		t.Fatalf("want 2 placements, got %+v", ds)
	}
	// model list carries replicas + all placements
	var models struct {
		Models []struct {
			ID          string        `json:"id"`
			Replicas    int           `json:"replicas"`
			Deployments []*Deployment `json:"deployments"`
		} `json:"models"`
	}
	getJSON(t, mux, "/dani/models", &models)
	for _, m := range models.Models {
		if m.ID == cand && (m.Replicas != 2 || len(m.Deployments) != 2) {
			t.Fatalf("model row replicas wrong: %+v", m)
		}
	}
}

func TestReplicaScaleDownReleasesHolder(t *testing.T) {
	api := newTrainingAPI(t, "trainer-1")
	api.Live = func(string) bool { return true }
	mux := serveTraining(api)
	cand := promoteACandidate(t, api, mux)
	postJSON(t, mux, "/dani/models/deploy", map[string]any{"model": cand, "replicas": 2})
	var out struct {
		Deployments []Deployment `json:"deployments"`
	}
	getJSON(t, mux, "/dani/deployments?node=worker-a&class=secret", &out)
	getJSON(t, mux, "/dani/deployments?node=worker-b&class=secret", &out)
	// scale down to 1: the next poller HOLDING a placement gets released (its poll omits the model)
	postJSON(t, mux, "/dani/models/deploy", map[string]any{"model": cand, "replicas": 1})
	getJSON(t, mux, "/dani/deployments?node=worker-a&class=secret", &out)
	if len(out.Deployments) != 0 {
		t.Fatalf("scaled-down holder must be released: %+v", out.Deployments)
	}
	// the remaining holder keeps it
	getJSON(t, mux, "/dani/deployments?node=worker-b&class=secret", &out)
	if len(out.Deployments) != 1 {
		t.Fatalf("remaining holder must keep the placement: %+v", out.Deployments)
	}
	if ds := api.deploymentsOf(cand); len(ds) != 1 || ds[0].Node != "worker-b" {
		t.Fatalf("placement table after scale-down: %+v", ds)
	}
}

func TestPinToNodeAndUndeploy(t *testing.T) {
	api := newTrainingAPI(t, "trainer-1")
	live := map[string]bool{"worker-x": true}
	api.Live = func(n string) bool { return live[n] }
	mux := serveTraining(api)
	cand := promoteACandidate(t, api, mux)

	// pin to a live node -> placement appears without the node polling first
	rec := postJSON(t, mux, "/dani/models/deploy", map[string]any{"model": cand, "node": "worker-x"})
	if rec.Code != http.StatusOK {
		t.Fatalf("pin: %d %s", rec.Code, rec.Body)
	}
	if ds := api.deploymentsOf(cand); len(ds) != 1 || ds[0].Node != "worker-x" {
		t.Fatalf("pin must place: %+v", ds)
	}
	// pinning is idempotent
	postJSON(t, mux, "/dani/models/deploy", map[string]any{"model": cand, "node": "worker-x"})
	if ds := api.deploymentsOf(cand); len(ds) != 1 {
		t.Fatalf("pin must be idempotent: %+v", ds)
	}
	// pinning a SECOND node grows the desired replica count so auto-assign won't fight it
	live["worker-y"] = true
	rec = postJSON(t, mux, "/dani/models/deploy", map[string]any{"model": cand, "node": "worker-y"})
	var grew struct {
		Replicas int `json:"replicas"`
	}
	getJSONBody(t, rec.Body.Bytes(), &grew)
	if grew.Replicas != 2 || len(api.deploymentsOf(cand)) != 2 {
		t.Fatalf("second pin must grow replicas to 2: %+v", grew)
	}
	postJSON(t, mux, "/dani/models/undeploy", map[string]any{"model": cand, "node": "worker-y"})
	// pin to a dead node refused
	if rec := postJSON(t, mux, "/dani/models/deploy", map[string]any{"model": cand, "node": "ghost"}); rec.Code != http.StatusBadRequest {
		t.Fatalf("pin to dead node must 400: %d", rec.Code)
	}
	// undeploy the specific node
	if rec := postJSON(t, mux, "/dani/models/undeploy", map[string]any{"model": cand, "node": "worker-x"}); rec.Code != http.StatusOK {
		t.Fatalf("undeploy node: %d %s", rec.Code, rec.Body)
	}
	if ds := api.deploymentsOf(cand); len(ds) != 0 {
		t.Fatalf("undeploy must remove the placement: %+v", ds)
	}
	// want shrank with the removal, so a poll does NOT re-assign
	var out struct {
		Deployments []Deployment `json:"deployments"`
	}
	getJSON(t, mux, "/dani/deployments?node=worker-x&class=secret", &out)
	if len(out.Deployments) != 0 {
		t.Fatalf("undeployed model must not auto-refill: %+v", out.Deployments)
	}
	// undeploy of a non-existent placement 404s
	if rec := postJSON(t, mux, "/dani/models/undeploy", map[string]any{"model": cand, "node": "worker-x"}); rec.Code != http.StatusNotFound {
		t.Fatalf("undeploy of nothing must 404: %d", rec.Code)
	}
}

func TestUndeployAllParksModel(t *testing.T) {
	api := newTrainingAPI(t, "trainer-1")
	api.Live = func(string) bool { return true }
	mux := serveTraining(api)
	cand := promoteACandidate(t, api, mux)
	var out struct {
		Deployments []Deployment `json:"deployments"`
	}
	getJSON(t, mux, "/dani/deployments?node=worker-a&class=secret", &out)
	if len(out.Deployments) != 1 {
		t.Fatal("setup: claim failed")
	}
	// park it everywhere
	if rec := postJSON(t, mux, "/dani/models/undeploy", map[string]any{"model": cand}); rec.Code != http.StatusOK {
		t.Fatalf("park: %d", rec.Code)
	}
	// no poller gets it while parked (replicas 0)
	getJSON(t, mux, "/dani/deployments?node=worker-a&class=secret", &out)
	if len(out.Deployments) != 0 {
		t.Fatalf("parked model must not assign: %+v", out.Deployments)
	}
	// scale back up -> assignable again
	postJSON(t, mux, "/dani/models/deploy", map[string]any{"model": cand, "replicas": 1})
	getJSON(t, mux, "/dani/deployments?node=worker-a&class=secret", &out)
	if len(out.Deployments) != 1 {
		t.Fatalf("un-parked model must assign again: %+v", out.Deployments)
	}
}

func TestModelDeployEndpointGuards(t *testing.T) {
	api := newTrainingAPI(t, "trainer-1")
	mux := serveTraining(api)
	for _, path := range []string{"/dani/models/deploy", "/dani/models/undeploy"} {
		if rec := getJSON(t, mux, path, nil); rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("GET %s must 405: %d", path, rec.Code)
		}
		if rec := postJSON(t, mux, path, "{bad"); rec.Code != http.StatusBadRequest {
			t.Fatalf("bad body %s must 400: %d", path, rec.Code)
		}
	}
	// deploy of an unknown / unpromoted model refused (verify-on-use)
	if rec := postJSON(t, mux, "/dani/models/deploy", map[string]any{"model": "ghost", "replicas": 2}); rec.Code != http.StatusNotFound {
		t.Fatalf("deploy of unknown model must 404: %d", rec.Code)
	}
	// negative replicas clamp to 0
	cand := promoteACandidate(t, api, mux)
	neg := -3
	rec := postJSON(t, mux, "/dani/models/deploy", map[string]any{"model": cand, "replicas": neg})
	if rec.Code != http.StatusOK {
		t.Fatalf("negative replicas: %d", rec.Code)
	}
	var out struct {
		Replicas int `json:"replicas"`
	}
	getJSONBody(t, rec.Body.Bytes(), &out)
	if out.Replicas != 0 {
		t.Fatalf("negative replicas must clamp to 0: %+v", out)
	}
}

func TestDurableDeploymentsV2AndLegacy(t *testing.T) {
	dir := t.TempDir()
	// v2 round-trip: placements + want
	snap := filepath.Join(dir, "v2.json")
	d := NewDurableDeployments(snap)
	d.mu.Lock()
	d.byMod["m"] = []*Deployment{{Model: "m", Node: "n1", State: "loaded"}, {Model: "m", Node: "n2", State: "assigned"}}
	d.want["m"] = 2
	d.save()
	d.mu.Unlock()
	re := NewDurableDeployments(snap)
	if len(re.byMod["m"]) != 2 || re.wantOf("m") != 2 {
		t.Fatalf("v2 snapshot must round-trip: %+v want=%d", re.byMod["m"], re.wantOf("m"))
	}
	// legacy v1 snapshot (model -> single placement) loads transparently
	legacy := filepath.Join(dir, "v1.json")
	os.WriteFile(legacy, []byte(`{"m":{"model":"m","node":"n1","state":"loaded","at":"2026-01-01T00:00:00Z"}}`), 0o600)
	lv := NewDurableDeployments(legacy)
	if ds := lv.byMod["m"]; len(ds) != 1 || ds[0].Node != "n1" || ds[0].State != "loaded" {
		t.Fatalf("legacy snapshot must migrate: %+v", ds)
	}
	// missing want key defaults to 1; explicit 0 parks
	if lv.wantOf("m") != 1 {
		t.Fatal("missing want must default to 1")
	}
	lv.want["m"] = 0
	if lv.wantOf("m") != 0 {
		t.Fatal("explicit 0 must park")
	}
}

package serving

// P1-7 serving tests: the gateway config surface (list/set/delete/validation-refusal/audit
// attribution), the Link resolve endpoint, and the LIVE proof — a running worker picks up a
// fleet-scope value, then a node-scope override, and applies them to its admission knobs without
// a restart.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"dani.local/agent/internal/config"
	"dani.local/agent/internal/engine"
)

func configPlane(t *testing.T) (*Plane, *config.Store, *[]map[string]any) {
	t.Helper()
	p := &Plane{workers: map[string]*workerState{}, inflight: map[string]int{}, stale: time.Minute}
	st, err := config.Open(context.Background(), filepath.Join(t.TempDir(), "config.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	var audits []map[string]any
	p.EnableConfig(st, func(typ string, payload map[string]any) {
		payload["type"] = typ
		audits = append(audits, payload)
	})
	return p, st, &audits
}

func configMux(p *Plane) *http.ServeMux {
	mux := http.NewServeMux()
	p.registerConfigRoutes(mux)
	mux.HandleFunc("/link/config", p.handleLinkConfig)
	return mux
}

func TestConfigAPISurface(t *testing.T) {
	p, _, audits := configPlane(t)
	mux := configMux(p)

	// set fleet + node entries
	if rec := postJSON(t, mux, "/dani/config", map[string]any{"scope": "fleet", "key": "worker.queue-depth", "value": "8"}); rec.Code != http.StatusOK {
		t.Fatalf("set fleet: %d %s", rec.Code, rec.Body)
	}
	if rec := postJSON(t, mux, "/dani/config", map[string]any{"scope": "node", "scopeVal": "w-2", "key": "worker.queue-depth", "value": "1"}); rec.Code != http.StatusOK {
		t.Fatalf("set node: %d %s", rec.Code, rec.Body)
	}
	// a bad value is refused AT THE CONSOLE (write-time validation)
	if rec := postJSON(t, mux, "/dani/config", map[string]any{"scope": "fleet", "key": "worker.queue-depth", "value": "banana"}); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad value must 400: %d", rec.Code)
	}
	if rec := postJSON(t, mux, "/dani/config", map[string]any{"scope": "fleet", "key": "worker.qeue-depth", "value": "4"}); rec.Code != http.StatusBadRequest {
		t.Fatalf("typo'd key must 400: %d", rec.Code)
	}

	// list shows both entries + known keys + version
	var list struct {
		Version   int64             `json:"version"`
		Entries   []config.Entry    `json:"entries"`
		KnownKeys map[string]string `json:"knownKeys"`
	}
	getJSON(t, mux, "/dani/config", &list)
	if list.Version != 2 || len(list.Entries) != 2 || len(list.KnownKeys) == 0 {
		t.Fatalf("list wrong: %+v", list)
	}

	// resolve: node override wins for w-2, fleet for w-1
	var res struct {
		Version   int64                      `json:"version"`
		Effective map[string]config.Resolved `json:"effective"`
	}
	getJSON(t, mux, "/dani/config/resolve?uuid=w-2&site=s&roles=worker", &res)
	if r := res.Effective["worker.queue-depth"]; r.Value != "1" || r.Scope != "node" {
		t.Fatalf("w-2 resolve: %+v", r)
	}
	getJSON(t, mux, "/link/config?uuid=w-1&site=s&roles=worker", &res)
	if r := res.Effective["worker.queue-depth"]; r.Value != "8" || r.Scope != "fleet" {
		t.Fatalf("w-1 resolve: %+v", r)
	}

	// delete + audit trail (attributed writes)
	if rec := postJSON(t, mux, "/dani/config", map[string]any{"scope": "node", "scopeVal": "w-2", "key": "worker.queue-depth", "delete": true}); rec.Code != http.StatusOK {
		t.Fatalf("delete: %d %s", rec.Code, rec.Body)
	}
	if len(*audits) != 3 { // 2 sets + 1 delete (refused writes are NOT audited as updates)
		t.Fatalf("audit events: %d", len(*audits))
	}
	if (*audits)[2]["deleted"] != true || (*audits)[0]["by"] != "anonymous" {
		t.Fatalf("audit payloads: %+v", *audits)
	}

	// method guard + disabled-store guard
	req := httptest.NewRequest(http.MethodPut, "/dani/config", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("PUT must 405, got %d", rec.Code)
	}
	bare := &Plane{}
	rec2 := httptest.NewRecorder()
	bare.handleConfigResolve(rec2, httptest.NewRequest(http.MethodGet, "/dani/config/resolve", nil))
	if rec2.Code != http.StatusServiceUnavailable {
		t.Fatalf("resolve without a store must 503, got %d", rec2.Code)
	}
	// routes are absent entirely without EnableConfig
	bareMux := http.NewServeMux()
	bare.registerConfigRoutes(bareMux)
	rec3 := httptest.NewRecorder()
	bareMux.ServeHTTP(rec3, httptest.NewRequest(http.MethodGet, "/dani/config", nil))
	if rec3.Code != http.StatusNotFound {
		t.Fatalf("routes must not exist without EnableConfig, got %d", rec3.Code)
	}
}

func TestConfigAPIStoreErrors(t *testing.T) {
	p, st, _ := configPlane(t)
	mux := configMux(p)
	_ = st.Close() // break the store under the handlers
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/dani/config", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("list on broken store must 500, got %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/dani/config/resolve?uuid=w", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("resolve on broken store must 500, got %d", rec.Code)
	}
	if r := postJSON(t, mux, "/dani/config", map[string]any{"scope": "fleet", "key": "x-a", "value": "1"}); r.Code != http.StatusBadRequest {
		t.Fatalf("set on broken store must surface, got %d", r.Code)
	}
	// bad body
	req := httptest.NewRequest(http.MethodPost, "/dani/config", strings.NewReader("{nope"))
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad body must 400, got %d", rec.Code)
	}
}

// TestWorkerLiveAppliesConfig is the P1-7 live proof: a running worker's admission knobs change
// within one config poll of an operator write — fleet scope first, then a node override.
func TestWorkerLiveAppliesConfig(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	auth := newAuthority(t)
	p, err := NewPlane(auth.identity("ctrl-cfg"), "site-t")
	if err != nil {
		t.Fatal(err)
	}
	st, err := config.Open(ctx, filepath.Join(t.TempDir(), "config.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	p.EnableConfig(st, nil)
	linkAddr, err := p.ServeLink("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gw, err := p.ServeGateway("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	w := NewWorker(WorkerConfig{
		Identity: auth.identity("w-cfg"), Engine: engine.NewStub("m-cfg"), ModelID: "m-cfg",
		Class: "restricted", Site: "site-t", AdvertiseHost: "127.0.0.1",
		ControllerURLs: []string{"https://" + linkAddr}, MaxConcurrent: 2, QueueDepth: 4,
		SLOBudget: 20 * time.Second, HeartbeatEvery: 100 * time.Millisecond,
	})
	w.cfgEvery = 100 * time.Millisecond
	go func() { _ = w.Serve(ctx, "127.0.0.1:0") }()
	waitLiveFleet(t, gw, 1)
	if w.qDepth() != 4 || w.slo() != 20*time.Second {
		t.Fatalf("boot knobs wrong: %d %s", w.qDepth(), w.slo())
	}

	// fleet-scope change lands live
	if err := st.Set(ctx, config.Entry{Scope: config.ScopeFleet, Key: "worker.queue-depth", Value: "9"}); err != nil {
		t.Fatal(err)
	}
	if err := st.Set(ctx, config.Entry{Scope: config.ScopeFleet, Key: "worker.slo-budget", Value: "5s"}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 5*time.Second, func() bool { return w.qDepth() == 9 && w.slo() == 5*time.Second })

	// node-scope override beats it — and the heartbeat advertises the new depth to the router
	if err := st.Set(ctx, config.Entry{Scope: config.ScopeNode, ScopeVal: "w-cfg", Key: "worker.queue-depth", Value: "1"}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, 5*time.Second, func() bool { return w.qDepth() == 1 })
	waitFor(t, 5*time.Second, func() bool {
		p.mu.RLock()
		defer p.mu.RUnlock()
		ws := p.workers["w-cfg"]
		return ws != nil && ws.QueueDepth == 1
	})
}

func waitFor(t *testing.T, d time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition never became true")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// applyConfig guards: malformed values from a hostile/buggy store are skipped, not applied.
func TestApplyConfigGuards(t *testing.T) {
	w := NewWorker(WorkerConfig{Identity: Identity{UUID: "w-g"}, Engine: engine.NewStub("m"), ModelID: "m", QueueDepth: 4, SLOBudget: 20 * time.Second})
	w.applyConfig(map[string]config.Resolved{
		"worker.queue-depth": {Value: "banana", Scope: "fleet"},
		"worker.slo-budget":  {Value: "-5s", Scope: "fleet"},
	})
	if w.qDepth() != 4 || w.slo() != 20*time.Second {
		t.Fatalf("malformed values must be skipped: %d %s", w.qDepth(), w.slo())
	}
	w.applyConfig(map[string]config.Resolved{
		"worker.queue-depth": {Value: "0", Scope: "fleet"},
		"worker.slo-budget":  {Value: "300ms", Scope: "fleet"},
	})
	if w.qDepth() != 0 || w.slo() != 300*time.Millisecond {
		t.Fatalf("valid values must apply: %d %s", w.qDepth(), w.slo())
	}
}

// TestApplyConfigResourceCaps: a live worker.max-cores / worker.max-model-mem-mb change re-resolves
// the budget and reports it on the next heartbeat (single- and group-scope drive the same path).
func TestApplyConfigResourceCaps(t *testing.T) {
	w := NewWorker(WorkerConfig{Identity: Identity{UUID: "w-cap"}, Engine: engine.NewStub("m"), ModelID: "m"})

	// a node-scope core cap → custom mode, advertised on the heartbeat
	w.applyConfig(map[string]config.Resolved{
		"worker.max-cores": {Value: "1", Scope: "node", ScopeVal: "w-cap"},
	})
	if hb := w.heartbeat("healthy"); hb.CapMode != "custom" || hb.MaxCores != 1 {
		t.Fatalf("core cap not applied: mode=%q cores=%d", hb.CapMode, hb.MaxCores)
	}

	// a fleet-scope memory budget lands too (group operation)
	w.applyConfig(map[string]config.Resolved{
		"worker.max-cores":        {Value: "1", Scope: "node", ScopeVal: "w-cap"},
		"worker.max-model-mem-mb": {Value: "2048", Scope: "fleet"},
	})
	if hb := w.heartbeat("healthy"); hb.MemBudgetMB != 2048 {
		t.Fatalf("mem budget not applied: %d", hb.MemBudgetMB)
	}

	// a malformed value from a buggy store is skipped → falls back to the flag baseline (auto)
	w.applyConfig(map[string]config.Resolved{"worker.max-cores": {Value: "banana", Scope: "fleet"}})
	if hb := w.heartbeat("healthy"); hb.CapMode == "custom" && hb.MaxCores == 1 {
		t.Fatalf("malformed cap must not keep the stale override: mode=%q cores=%d", hb.CapMode, hb.MaxCores)
	}

	// "all" = dedicated → every core, mode full
	w.applyConfig(map[string]config.Resolved{"worker.max-cores": {Value: "all", Scope: "node", ScopeVal: "w-cap"}})
	if hb := w.heartbeat("healthy"); hb.CapMode != "full" || hb.MaxCores < 1 {
		t.Fatalf("'all' not applied: mode=%q cores=%d", hb.CapMode, hb.MaxCores)
	}

	// DELETING the override (key absent from the effective map) reverts to the flag baseline —
	// this worker had no flags, so back to auto (polite/full by host). The console Reset path.
	w.applyConfig(map[string]config.Resolved{})
	if hb := w.heartbeat("healthy"); hb.CapMode == "custom" || hb.CapMode == "" {
		t.Fatalf("deleted override must revert to baseline, got mode=%q", hb.CapMode)
	}
}

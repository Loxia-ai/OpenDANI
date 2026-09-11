package serving

// P1-2 observability tests: unit coverage for the label/status plumbing, gauge classification and
// readiness semantics, a live end-to-end scrape (real mTLS worker + instrumented gateway), and the
// training-jobs gauge over a real completed job.

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"dani.local/agent/internal/engine"
)

func TestRouteLabelBoundsCardinality(t *testing.T) {
	cases := map[string]string{
		"/":                        "/",
		"/healthz":                 "/healthz",
		"/readyz":                  "/readyz",
		"/metrics":                 "/metrics",
		"/v1/chat/completions":     "/v1/chat/completions",
		"/v1/models":               "/v1/models",
		"/dani/fleet":              "/dani/fleet",
		"/dani/train/jobs":         "/dani/train/jobs",
		"/auth/login":              "/auth/login",
		"/console":                 "/console",
		"/console/assets/x-9f.js":  "/console",
		"/wp-admin/setup.php":      "other", // scanners don't mint series
		"/v1/chat/completions/..%": "other",
	}
	for path, want := range cases {
		if got := routeLabel(path); got != want {
			t.Fatalf("routeLabel(%q) = %q, want %q", path, got, want)
		}
	}
}

func TestItoa3(t *testing.T) {
	for code, want := range map[int]string{200: "200", 404: "404", 503: "503", 99: "200", 1000: "200"} {
		if got := itoa3(code); got != want {
			t.Fatalf("itoa3(%d) = %q, want %q", code, got, want)
		}
	}
}

func TestFleetGaugeAndReadyz(t *testing.T) {
	p := &Plane{workers: map[string]*workerState{}, inflight: map[string]int{}, drained: map[string]bool{}, revoked: map[string]bool{}, stale: time.Minute}
	reg := p.EnableMetrics()

	// empty fleet: not ready, all-zero gauge
	rec := getJSON(t, muxWithReadyz(p), "/readyz", nil)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("empty fleet must be unready, got %d", rec.Code)
	}
	if out := reg.Render(); !strings.Contains(out, `dani_fleet_workers{state="healthy"} 0`) {
		t.Fatalf("empty gauge wrong:\n%s", out)
	}

	// one of each state
	now := time.Now()
	p.workers["w-ok"] = &workerState{Heartbeat: Heartbeat{NodeUUID: "w-ok", Health: "healthy", MaxConcurrent: 4}, LastSeen: now}
	p.workers["w-stale"] = &workerState{Heartbeat: Heartbeat{NodeUUID: "w-stale", Health: "healthy"}, LastSeen: now.Add(-time.Hour)}
	p.workers["w-drained"] = &workerState{Heartbeat: Heartbeat{NodeUUID: "w-drained", Health: "healthy"}, LastSeen: now}
	p.workers["w-trainer"] = &workerState{Heartbeat: Heartbeat{NodeUUID: "w-trainer", Health: "healthy", Trainer: true}, LastSeen: now}
	p.workers["w-degraded"] = &workerState{Heartbeat: Heartbeat{NodeUUID: "w-degraded", Health: "degraded"}, LastSeen: now}
	p.drained["w-drained"] = true
	p.inflight["w-ok"] = 2

	out := reg.Render()
	for _, want := range []string{
		`dani_fleet_workers{state="healthy"} 1`,
		`dani_fleet_workers{state="stale"} 1`,
		`dani_fleet_workers{state="drained"} 1`,
		`dani_fleet_workers{state="trainer"} 1`,
		`dani_fleet_workers{state="degraded"} 1`,
		`dani_gateway_inflight 2`,
		`dani_fleet_capacity 4`, // only w-ok counts (healthy, fresh, not trainer)
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
	// one healthy routable worker -> ready
	rec = getJSON(t, muxWithReadyz(p), "/readyz", nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"ready":true`) {
		t.Fatalf("fleet with a healthy worker must be ready: %d %s", rec.Code, rec.Body)
	}
}

func muxWithReadyz(p *Plane) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/readyz", p.handleReadyz)
	return mux
}

func TestTrainingJobsGauge(t *testing.T) {
	api := newTrainingAPI(t, "trainer-1") // D17 allocation satisfied; StubTrainer executes locally
	p := &Plane{workers: map[string]*workerState{}, inflight: map[string]int{}, stale: time.Minute}
	p.EnableTraining(api)
	reg := p.EnableMetrics()
	mux := http.NewServeMux()
	p.registerTrainingRoutes(mux)

	if rec := postJSON(t, mux, "/dani/ingest", map[string]string{"collection": "legal"}); rec.Code != http.StatusOK {
		t.Fatalf("ingest: %d %s", rec.Code, rec.Body)
	}
	if rec := postJSON(t, mux, "/dani/train/submit", map[string]string{
		"engineer": "alice", "base": "qwen2.5-1.5b", "collection": "legal", "method": "lora",
	}); rec.Code != http.StatusAccepted {
		t.Fatalf("submit: %d %s", rec.Code, rec.Body)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if strings.Contains(reg.Render(), `dani_training_jobs{state="completed"} 1`) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("training gauge never reported the completed job:\n%s", reg.Render())
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// TestLiveObservability drives the instrumented gateway + a real mTLS worker: readiness flips when
// the worker joins, request/latency/unrouted series appear, and the worker's own /metrics scrapes
// over mTLS.
func TestLiveObservability(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	auth := newAuthority(t)
	p, err := NewPlane(auth.identity("ctrl-obs"), "site-t")
	if err != nil {
		t.Fatal(err)
	}
	p.EnableMetrics() // BEFORE ServeGateway, like the real controller wiring
	linkAddr, err := p.ServeLink("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gw, err := p.ServeGateway("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	// not ready before any worker
	r0, err := http.Get("http://" + gw + "/readyz")
	if err != nil {
		t.Fatal(err)
	}
	r0.Body.Close()
	if r0.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("gateway must be unready with no workers, got %d", r0.StatusCode)
	}

	w := NewWorker(WorkerConfig{
		Identity: auth.identity("w-obs"), Engine: engine.NewStub("m-obs"), ModelID: "m-obs",
		Class: "restricted", Site: "site-t", AdvertiseHost: "127.0.0.1",
		ControllerURLs: []string{"https://" + linkAddr}, MaxConcurrent: 2,
		HeartbeatEvery: 100 * time.Millisecond,
	})
	go func() { _ = w.Serve(ctx, "127.0.0.1:0") }()
	waitLiveFleet(t, gw, 1)

	// ready now
	r1, err := http.Get("http://" + gw + "/readyz")
	if err != nil {
		t.Fatal(err)
	}
	r1.Body.Close()
	if r1.StatusCode != http.StatusOK {
		t.Fatalf("gateway with a live worker must be ready, got %d", r1.StatusCode)
	}

	// one served chat + one no-route
	body, _ := json.Marshal(map[string]any{"model": "m-obs",
		"messages": []engine.Message{{Role: "user", Content: "observe me"}}, "max_tokens": 8})
	cr, err := http.Post("http://"+gw+"/v1/chat/completions", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, cr.Body)
	cr.Body.Close()
	if cr.StatusCode != http.StatusOK {
		t.Fatalf("chat failed: %d", cr.StatusCode)
	}
	nb, _ := json.Marshal(map[string]any{"model": "ghost", "messages": []engine.Message{{Role: "user", Content: "x"}}})
	nr, _ := http.Post("http://"+gw+"/v1/chat/completions", "application/json", bytes.NewReader(nb))
	nr.Body.Close()

	// gateway scrape
	mr, err := http.Get("http://" + gw + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	mb, _ := io.ReadAll(mr.Body)
	mr.Body.Close()
	scrape := string(mb)
	for _, want := range []string{
		`dani_gateway_requests_total{route="/v1/chat/completions",code="200"} 1`,
		`dani_gateway_requests_total{route="/v1/chat/completions",code="503"} 1`,
		`dani_gateway_unrouted_total{reason="no_route"} 1`,
		`dani_fleet_workers{state="healthy"} 1`,
		`dani_fleet_capacity 2`,
		`dani_gateway_request_duration_seconds_count{route="/v1/chat/completions"} 2`,
	} {
		if !strings.Contains(scrape, want) {
			t.Fatalf("gateway scrape missing %q:\n%s", want, scrape)
		}
	}

	// worker scrape over mTLS (the controller's dialer presents a fleet identity)
	wr, err := p.Dialer().Get("https://" + w.dispatchAddr + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	wb, _ := io.ReadAll(wr.Body)
	wr.Body.Close()
	wscrape := string(wb)
	for _, want := range []string{
		`dani_worker_requests_total{code="200"} 1`,
		`dani_worker_slots 2`,
		`dani_worker_served_total 1`,
	} {
		if !strings.Contains(wscrape, want) {
			t.Fatalf("worker scrape missing %q:\n%s", want, wscrape)
		}
	}
	// worker readiness (bound listener == started engine)
	rr, err := p.Dialer().Get("https://" + w.dispatchAddr + "/readyz")
	if err != nil {
		t.Fatal(err)
	}
	rb, _ := io.ReadAll(rr.Body)
	rr.Body.Close()
	if rr.StatusCode != http.StatusOK || !strings.Contains(string(rb), `"ready":true`) {
		t.Fatalf("worker readyz wrong: %d %s", rr.StatusCode, rb)
	}
}

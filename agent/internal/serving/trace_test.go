package serving

// P2-A3 tests: the bounded trace ring (order, overwrite, limit), id honor/generate, and the LIVE
// proof — a fan-out of concurrent requests across a multi-worker fleet produces one trace each,
// each attributed to the node + site that served it (the demo's fan-out view).

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"dani.local/agent/internal/engine"
)

func TestTraceRing(t *testing.T) {
	tr := newTracer(3)
	if got := tr.recent(10); len(got) != 0 {
		t.Fatalf("empty ring: %d", len(got))
	}
	for i, id := range []string{"a", "b", "c", "d", "e"} {
		tr.record(Trace{ID: id, DurationMs: int64(i)})
	}
	// capacity 3 -> only the last 3, newest first
	got := tr.recent(0)
	if len(got) != 3 || got[0].ID != "e" || got[1].ID != "d" || got[2].ID != "c" {
		t.Fatalf("ring order/overwrite wrong: %+v", got)
	}
	// limit caps
	if g := tr.recent(2); len(g) != 2 || g[0].ID != "e" {
		t.Fatalf("limit: %+v", g)
	}
	// default capacity
	if newTracer(0) == nil || len(newTracer(-5).ring) != 512 {
		t.Fatal("default capacity wrong")
	}
}

func TestTraceIDHonorAndGenerate(t *testing.T) {
	r := httptest.NewRequest("POST", "/", nil)
	if id := traceID(r); len(id) < 4 || id[:3] != "tr-" {
		t.Fatalf("generated id wrong: %q", id)
	}
	r.Header.Set("X-Dani-Trace-Id", "tr-inbound")
	if id := traceID(r); id != "tr-inbound" {
		t.Fatalf("inbound id not honored: %q", id)
	}
}

func TestHandleTracesDisabled(t *testing.T) {
	p := &Plane{}
	rec := httptest.NewRecorder()
	p.handleTraces(rec, httptest.NewRequest("GET", "/dani/traces", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("disabled tracer must 200 empty, got %d", rec.Code)
	}
}

func TestLiveFanOutTraces(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	auth := newAuthority(t)
	p, err := NewPlane(auth.identity("ctrl-tr"), "site-t")
	if err != nil {
		t.Fatal(err)
	}
	p.EnableTracing(256)
	p.EnableMetrics()
	linkAddr, err := p.ServeLink("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gw, err := p.ServeGateway("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	// three workers, same model/site — the router spreads a fan-out across them
	for _, uuid := range []string{"w-1", "w-2", "w-3"} {
		w := NewWorker(WorkerConfig{
			Identity: auth.identity(uuid), Engine: engine.NewStub("m-fan"), ModelID: "m-fan",
			Class: "restricted", Site: "site-t", AdvertiseHost: "127.0.0.1",
			ControllerURLs: []string{"https://" + linkAddr}, MaxConcurrent: 2,
			HeartbeatEvery: 80 * time.Millisecond,
		})
		go func() { _ = w.Serve(ctx, "127.0.0.1:0") }()
	}
	waitLiveFleet(t, gw, 3)

	// fan out 12 concurrent chat requests (the "one per function" pattern)
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			body, _ := json.Marshal(map[string]any{"model": "m-fan",
				"messages": []engine.Message{{Role: "user", Content: "implement fn"}}, "max_tokens": 8})
			resp, err := http.Post("http://"+gw+"/v1/chat/completions", "application/json", bytes.NewReader(body))
			if err != nil {
				return
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}()
	}
	wg.Wait()

	// /dani/traces shows the fan-out, each attributed to the node+site that served it
	resp, err := http.Get("http://" + gw + "/dani/traces?limit=100")
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		Traces []Trace `json:"traces"`
		Count  int     `json:"count"`
	}
	json.NewDecoder(resp.Body).Decode(&out)
	resp.Body.Close()

	served := 0
	nodes := map[string]bool{}
	for _, tr := range out.Traces {
		if tr.ID == "" || tr.StartUnixMs == 0 {
			t.Fatalf("malformed trace: %+v", tr)
		}
		if tr.Status == "served" {
			served++
			nodes[tr.ServedBy] = true
			if tr.Site != "site-t" {
				t.Fatalf("trace missing site: %+v", tr)
			}
		}
	}
	if served < 10 {
		t.Fatalf("expected most of 12 fan-out requests served+traced, got %d (traces=%d)", served, out.Count)
	}
	if len(nodes) < 2 {
		t.Fatalf("fan-out should spread across >=2 nodes, hit %d: %v", len(nodes), nodes)
	}
}

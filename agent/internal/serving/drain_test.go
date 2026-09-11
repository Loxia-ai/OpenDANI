package serving

// P1-3 graceful-shutdown tests: a SIGTERM'd worker announces "draining" (router stops sending it
// work immediately — no staleness wait), finishes what's in flight, and only then exits; the
// controller's Plane.Shutdown drains its servers the same way.

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"dani.local/agent/internal/engine"
)

func TestWorkerDrainFinishesInFlight(t *testing.T) {
	auth := newAuthority(t)
	p, linkAddr, gw := livePlane(t, auth)

	ctx, cancel := context.WithCancel(context.Background())
	w := NewWorker(WorkerConfig{
		Identity: auth.identity("w-drain"), Engine: engine.NewStub("m-drain"), ModelID: "m-drain",
		Class: "restricted", Site: "site-t", AdvertiseHost: "127.0.0.1",
		ControllerURLs: []string{"https://" + linkAddr}, MaxConcurrent: 2,
		HeartbeatEvery: 100 * time.Millisecond, DrainTimeout: 10 * time.Second,
	})
	served := make(chan error, 1)
	go func() { served <- w.Serve(ctx, "127.0.0.1:0") }()
	waitLiveFleet(t, gw, 1)

	// start a SLOW request (the stub paces by output size), then SIGTERM mid-flight
	var status atomic.Int64
	reqDone := make(chan struct{})
	go func() {
		defer close(reqDone)
		body, _ := json.Marshal(map[string]any{"model": "m-drain",
			"messages": []engine.Message{{Role: "user", Content: "long slow answer please"}}, "max_tokens": 128})
		resp, err := http.Post("http://"+gw+"/v1/chat/completions", "application/json", bytes.NewReader(body))
		if err != nil {
			return
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		status.Store(int64(resp.StatusCode))
	}()
	time.Sleep(300 * time.Millisecond) // let it be dispatched and in flight
	cancel()                           // the SIGTERM

	// the in-flight request must COMPLETE (200), not be cut off
	select {
	case <-reqDone:
	case <-time.After(15 * time.Second):
		t.Fatal("in-flight request never finished during drain")
	}
	if status.Load() != http.StatusOK {
		t.Fatalf("in-flight request was dropped during drain: status %d", status.Load())
	}
	select {
	case <-served:
	case <-time.After(5 * time.Second):
		t.Fatal("worker.Serve never returned after drain")
	}

	// the drain announcement flipped the worker's health — the router must refuse it (no staleness wait)
	p.mu.RLock()
	ws := p.workers["w-drain"]
	p.mu.RUnlock()
	if ws == nil || ws.Health != "draining" {
		t.Fatalf("controller never saw the draining announcement: %+v", ws)
	}
	if _, ok := p.reserve("m-drain", "unrestricted", "", nil); ok {
		t.Fatal("router still routes to a draining worker")
	}
}

func TestPlaneShutdownDrainsServers(t *testing.T) {
	auth := newAuthority(t)
	p, linkAddr, gw := livePlane(t, auth)

	// park a worker so the gateway can serve one slow request during shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w := NewWorker(WorkerConfig{
		Identity: auth.identity("w-ps"), Engine: engine.NewStub("m-ps"), ModelID: "m-ps",
		Class: "restricted", Site: "site-t", AdvertiseHost: "127.0.0.1",
		ControllerURLs: []string{"https://" + linkAddr},
		MaxConcurrent:  1, HeartbeatEvery: 100 * time.Millisecond,
	})
	go func() { _ = w.Serve(ctx, "127.0.0.1:0") }()
	// Observe readiness through the controller's synchronized fleet view. Reading
	// dispatchAddr directly races the worker's listener initialization.
	waitLiveFleet(t, gw, 1)

	// fire a slow request, then Shutdown the plane while it is in flight
	statusCh := make(chan int, 1)
	go func() {
		body, _ := json.Marshal(map[string]any{"model": "m-ps",
			"messages": []engine.Message{{Role: "user", Content: "slow one"}}, "max_tokens": 128})
		resp, err := http.Post("http://"+gw+"/v1/chat/completions", "application/json", bytes.NewReader(body))
		if err != nil {
			statusCh <- 0
			return
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		statusCh <- resp.StatusCode
	}()
	time.Sleep(300 * time.Millisecond)
	shCtx, shCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shCancel()
	if err := p.Shutdown(shCtx); err != nil {
		t.Fatalf("plane shutdown: %v", err)
	}
	if got := <-statusCh; got != http.StatusOK {
		t.Fatalf("in-flight gateway request dropped during Shutdown: %d", got)
	}
	// new connections are refused after drain
	if _, err := http.Get("http://" + gw + "/healthz"); err == nil {
		t.Fatal("gateway still accepting after Shutdown")
	}
}

func TestPlaneShutdownTimeoutSurfaces(t *testing.T) {
	auth := newAuthority(t)
	p, linkAddr, gw := livePlane(t, auth)
	// hold a connection open by keeping a request in flight against a never-answering "worker"
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w := NewWorker(WorkerConfig{
		Identity: auth.identity("w-hold"), Engine: engine.NewStub("m-hold"), ModelID: "m-hold",
		Class: "restricted", Site: "site-t", AdvertiseHost: "127.0.0.1", MaxConcurrent: 1, HeartbeatEvery: 100 * time.Millisecond,
		ControllerURLs: []string{"https://" + linkAddr},
	})
	go func() { _ = w.Serve(ctx, "127.0.0.1:0") }()
	waitLiveFleet(t, gw, 1)
	go func() {
		body, _ := json.Marshal(map[string]any{"model": "m-hold",
			"messages": []engine.Message{{Role: "user", Content: "slow"}}, "max_tokens": 256})
		resp, err := http.Post("http://"+gw+"/v1/chat/completions", "application/json", bytes.NewReader(body))
		if err == nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
	}()
	time.Sleep(300 * time.Millisecond)
	expired, cancelExpired := context.WithCancel(context.Background())
	cancelExpired() // an already-expired drain budget with a request in flight -> Shutdown must error
	if err := p.Shutdown(expired); err == nil {
		t.Fatal("Shutdown with an expired budget and in-flight work must surface the error")
	}
}

// handleHeartbeatDirect registers a heartbeat without the HTTP hop (test helper).
func (p *Plane) handleHeartbeatDirect(hb Heartbeat) {
	p.mu.Lock()
	p.workers[hb.NodeUUID] = &workerState{Heartbeat: hb, LastSeen: time.Now()}
	p.mu.Unlock()
}

func TestWorkerDrainTimeoutCutsOff(t *testing.T) {
	auth := newAuthority(t)
	_, linkAddr, gw := livePlane(t, auth)
	ctx, cancel := context.WithCancel(context.Background())
	w := NewWorker(WorkerConfig{
		Identity: auth.identity("w-cut"), Engine: engine.NewStub("m-cut"), ModelID: "m-cut",
		Class: "restricted", Site: "site-t", AdvertiseHost: "127.0.0.1",
		ControllerURLs: []string{"https://" + linkAddr}, MaxConcurrent: 1,
		HeartbeatEvery: 100 * time.Millisecond,
		DrainTimeout:   50 * time.Millisecond, // too short for the slow request — the cut-off branch
	})
	done := make(chan error, 1)
	go func() { done <- w.Serve(ctx, "127.0.0.1:0") }()
	waitLiveFleet(t, gw, 1)
	go func() {
		body, _ := json.Marshal(map[string]any{"model": "m-cut",
			"messages": []engine.Message{{Role: "user", Content: "very slow"}}, "max_tokens": 256})
		resp, err := http.Post("http://"+gw+"/v1/chat/completions", "application/json", bytes.NewReader(body))
		if err == nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
	}()
	time.Sleep(300 * time.Millisecond)
	cancel()
	select {
	case <-done: // returned promptly despite the still-running request — the timeout branch fired
	case <-time.After(5 * time.Second):
		t.Fatal("worker did not honor the drain timeout")
	}
}

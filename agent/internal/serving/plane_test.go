package serving

import (
	"testing"
	"time"
)

// newTestPlane builds a Plane with an injected worker table (no TLS needed — reserve doesn't dial).
func newTestPlane(site string, workers ...workerState) *Plane {
	p := &Plane{workers: map[string]*workerState{}, inflight: map[string]int{},
		drained: map[string]bool{}, revoked: map[string]bool{}, stale: time.Minute, site: site}
	for i := range workers {
		w := workers[i]
		w.LastSeen = time.Now()
		if w.Health == "" {
			w.Health = "healthy"
		}
		if w.MaxConcurrent == 0 {
			w.MaxConcurrent = 2
		}
		if w.QueueDepth == 0 {
			w.QueueDepth = 4
		}
		p.workers[w.NodeUUID] = &w
	}
	return p
}

func hb(uuid, model, class, site string, ema int64) workerState {
	return workerState{Heartbeat: Heartbeat{
		NodeUUID: uuid, DispatchAddr: uuid + ":9443", ModelID: model, Engine: "llama.cpp",
		Class: class, Site: site, MaxConcurrent: 2, QueueDepth: 4, EmaServiceMs: ema, Health: "healthy",
	}}
}

// Among identical-model workers, the one predicted to respond soonest wins.
func TestRouteFastestWins(t *testing.T) {
	p := newTestPlane("hq",
		hb("slow", "m", "restricted", "hq", 5000),
		hb("fast", "m", "restricted", "hq", 500),
	)
	c, ok := p.reserve("m", "unrestricted", "hq", nil)
	if !ok || c.uuid != "fast" {
		t.Fatalf("expected 'fast' (lowest predicted), got %q ok=%v", c.uuid, ok)
	}
}

// A free-but-slower worker beats a fast-but-loaded one (real load-balancing by completion time).
func TestRouteFreeBeatsBusy(t *testing.T) {
	p := newTestPlane("hq",
		hb("quick", "m", "restricted", "hq", 1000), // fast per-request...
		hb("idle", "m", "restricted", "hq", 1500),  // ...but slightly slower & free
	)
	p.inflight["quick"] = 4 // quick is backed up (pred = ceil(5/2)*1000 = 3000ms)
	// idle pred = ceil(1/2)*1500 = 1500ms -> should win
	c, ok := p.reserve("m", "unrestricted", "hq", nil)
	if !ok || c.uuid != "idle" {
		t.Fatalf("expected 'idle' (sooner despite slower per-token), got %q ok=%v", c.uuid, ok)
	}
}

// Locality outranks raw speed: a local (slower) worker beats a remote faster one.
func TestRouteLocalityWinsOverSpeed(t *testing.T) {
	p := newTestPlane("hq",
		hb("local", "m", "restricted", "hq", 3000),  // local but slow
		hb("remote", "m", "restricted", "dc2", 300), // remote but fast
	)
	c, ok := p.reserve("m", "unrestricted", "hq", nil)
	if !ok || c.uuid != "local" {
		t.Fatalf("expected 'local' (locality outranks speed), got %q ok=%v", c.uuid, ok)
	}
}

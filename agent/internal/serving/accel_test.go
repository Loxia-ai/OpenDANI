package serving

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"
)

// Accel advertised on the heartbeat surfaces verbatim in /dani/fleet (console + demo read it).
func TestFleetCarriesAccel(t *testing.T) {
	p := &Plane{workers: map[string]*workerState{}, inflight: map[string]int{},
		drained: map[string]bool{}, stale: time.Minute}
	p.workers["gpu-box"] = &workerState{LastSeen: time.Now(), Heartbeat: Heartbeat{
		NodeUUID: "gpu-box", ModelID: "m", Health: "healthy", Accel: "vulkan"}}
	p.workers["vm"] = &workerState{LastSeen: time.Now(), Heartbeat: Heartbeat{
		NodeUUID: "vm", ModelID: "m", Health: "healthy", Accel: "cpu"}}
	rec := httptest.NewRecorder()
	p.handleFleet(rec, httptest.NewRequest("GET", "/dani/fleet", nil))
	var got struct {
		Workers []struct{ UUID, Accel string }
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("bad json: %v", err)
	}
	byID := map[string]string{}
	for _, w := range got.Workers {
		byID[w.UUID] = w.Accel
	}
	if byID["gpu-box"] != "vulkan" || byID["vm"] != "cpu" {
		t.Fatalf("accel not carried: %v", byID)
	}
}

// NewWorker threads Accel through to the heartbeat struct it emits.
func TestWorkerConfigAccel(t *testing.T) {
	w := NewWorker(WorkerConfig{Identity: Identity{UUID: "w"}, ModelID: "m", Accel: "metal"})
	if w.accel != "metal" {
		t.Fatalf("worker accel not stored: %q", w.accel)
	}
}

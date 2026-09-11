package serving

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func ledgerPlane(t *testing.T, reserve float64) *Plane {
	t.Helper()
	p := &Plane{workers: map[string]*workerState{}, inflight: map[string]int{}, drained: map[string]bool{},
		revoked: map[string]bool{}, stale: time.Minute}
	p.EnableLedger(reserve)
	return p
}

func TestUtilization(t *testing.T) {
	p := ledgerPlane(t, 0.25)
	if p.utilization() != 1 {
		t.Fatal("no capacity => saturated (1)")
	}
	p.mu.Lock()
	p.workers["w"] = &workerState{LastSeen: time.Now(), Heartbeat: Heartbeat{NodeUUID: "w", Health: "healthy", MaxConcurrent: 4}}
	p.inflight["w"] = 2
	p.mu.Unlock()
	if u := p.utilization(); u != 0.5 {
		t.Fatalf("2/4 => 0.5, got %v", u)
	}
}

// the friendly rule: never hard-block. Under load, a contributor (priority) is admitted; a tourist
// is deferred (429, not rejected). With slack, everyone is admitted.
func TestLedgerAdmission(t *testing.T) {
	p := ledgerPlane(t, 0.25) // best-effort admitted while util < 0.75
	p.ledger.Earn("contributor", 500)
	// one worker, 4 slots, 3 in-flight => utilization 0.75 (>= 1-0.25) => best-effort deferred
	p.mu.Lock()
	p.workers["w"] = &workerState{LastSeen: time.Now(), Heartbeat: Heartbeat{NodeUUID: "w", Health: "healthy", MaxConcurrent: 4}}
	p.inflight["w"] = 3
	p.mu.Unlock()

	// contributor: always proceeds
	rc := httptest.NewRequest("POST", "/", nil)
	rc.Header.Set("X-Dani-Client", "contributor")
	proceed, priority := p.admitLedger(httptest.NewRecorder(), rc)
	if !proceed || !priority {
		t.Fatal("a contributor must always be admitted with priority")
	}
	// tourist under load: deferred (429), not hard-blocked
	rt := httptest.NewRequest("POST", "/", nil)
	rt.Header.Set("X-Dani-Client", "tourist")
	rw := httptest.NewRecorder()
	proceed, _ = p.admitLedger(rw, rt)
	if proceed || rw.Code != http.StatusTooManyRequests {
		t.Fatalf("a tourist under load is deferred with 429, got proceed=%v code=%d", proceed, rw.Code)
	}
	// with slack (1 in-flight => util 0.25 < 0.75), the tourist IS admitted (no unhappy clients)
	p.mu.Lock()
	p.inflight["w"] = 1
	p.mu.Unlock()
	proceed, _ = p.admitLedger(httptest.NewRecorder(), rt)
	if !proceed {
		t.Fatal("with spare capacity a tourist must be served — best-effort is the free tier")
	}
}

func TestLedgerOffProceedsAlways(t *testing.T) {
	p := &Plane{workers: map[string]*workerState{}, inflight: map[string]int{}, drained: map[string]bool{},
		revoked: map[string]bool{}, stale: time.Minute} // ledger NOT enabled
	proceed, priority := p.admitLedger(httptest.NewRecorder(), httptest.NewRequest("POST", "/", nil))
	if !proceed || priority {
		t.Fatal("ledger off: always proceed, never priority")
	}
}

func TestLedgerSettle(t *testing.T) {
	p := ledgerPlane(t, 0.25)
	body := []byte(`{"usage":{"completion_tokens":50}}`)
	// a user who runs a worker (earns) and consumes (spends) under the same id nets out.
	p.ledgerSettle("same-id", "same-id", body, false)
	if p.ledger.Balance("same-id") != 0 {
		t.Fatalf("earn+spend same id should net ~0, got %v", p.ledger.Balance("same-id"))
	}
	// a pure consumer goes negative (best-effort); the worker that served earns.
	p.ledgerSettle("tourist", "worker-x", body, false)
	if p.ledger.Balance("tourist") != -50 || p.ledger.Balance("worker-x") != 50 {
		t.Fatalf("consumer -50 / worker +50, got %v / %v", p.ledger.Balance("tourist"), p.ledger.Balance("worker-x"))
	}
	// a seed-REPLACED (poisoned) answer earns the worker NOTHING but still charges the consumer.
	p.ledgerSettle("tourist2", "bad-worker", body, true)
	if p.ledger.Balance("bad-worker") != 0 {
		t.Fatalf("a replaced answer must earn nothing, got %v", p.ledger.Balance("bad-worker"))
	}
}

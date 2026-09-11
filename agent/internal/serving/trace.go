package serving

// Request tracing (PRODUCTION-READINESS P2, deep/multi-site observability). Metrics answer
// "how fast is route X overall"; a trace answers "where did THIS request go, across the network,
// and why." In a deep multi-site fleet — and especially in a fan-out workload where one logical job
// scatters many requests across nodes — that per-request attribution is what makes the topology
// legible: which node/site served it, how long it took, how many workers it tried before landing.
//
// Dependency-free and bounded, in the same spirit as internal/metrics: a fixed-size ring of the most
// recent traces, exposed at GET /dani/traces for the console (and the investor demo's live fan-out
// view). Each request carries an X-Dani-Trace-Id, generated at the gateway or honored from an inbound
// header, and propagated to the worker so its logs correlate.

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// Trace is one request's journey through the gateway.
type Trace struct {
	ID          string   `json:"id"`
	Model       string   `json:"model"`
	User        string   `json:"user,omitempty"`
	Class       string   `json:"classification"`
	ServedBy    string   `json:"servedBy,omitempty"` // node uuid that answered ("" if unrouted)
	Site        string   `json:"site,omitempty"`
	Status      string   `json:"status"` // served | no_route | busy | error
	StartUnixMs int64    `json:"startMs"`
	DurationMs  int64    `json:"durationMs"`
	PredictedMs int64    `json:"predictedMs,omitempty"`
	Attempts    []string `json:"attempts,omitempty"` // workers tried before landing (retries)
}

// tracer is a fixed-size ring of recent traces.
type tracer struct {
	mu   sync.Mutex
	ring []Trace
	next int
	size int
	seq  int64
}

func newTracer(capacity int) *tracer {
	if capacity <= 0 {
		capacity = 512
	}
	return &tracer{ring: make([]Trace, capacity)}
}

// record stores a completed trace (overwriting the oldest when full).
func (tr *tracer) record(t Trace) {
	tr.mu.Lock()
	tr.ring[tr.next] = t
	tr.next = (tr.next + 1) % len(tr.ring)
	if tr.size < len(tr.ring) {
		tr.size++
	}
	tr.seq++
	tr.mu.Unlock()
}

// recent returns up to limit traces, newest first.
func (tr *tracer) recent(limit int) []Trace {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	if limit <= 0 || limit > tr.size {
		limit = tr.size
	}
	out := make([]Trace, 0, limit)
	// walk backwards from the most recently written slot
	idx := (tr.next - 1 + len(tr.ring)) % len(tr.ring)
	for i := 0; i < limit; i++ {
		out = append(out, tr.ring[idx])
		idx = (idx - 1 + len(tr.ring)) % len(tr.ring)
	}
	return out
}

// newTraceID mints a short random trace id.
func newTraceID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return "tr-" + hex.EncodeToString(b)
}

// traceID returns the inbound trace id (honoring a caller's X-Dani-Trace-Id) or a fresh one — so a
// deep chain that already has a trace id keeps it across hops.
func traceID(r *http.Request) string {
	if id := r.Header.Get("X-Dani-Trace-Id"); id != "" {
		return id
	}
	return newTraceID()
}

// EnableTracing turns on the request-trace ring (call before ServeGateway). capacity<=0 => 512.
func (p *Plane) EnableTracing(capacity int) { p.tracer = newTracer(capacity) }

// handleTraces serves the recent request traces (console + demo). ?limit=N (default all).
func (p *Plane) handleTraces(rw http.ResponseWriter, r *http.Request) {
	if p.tracer == nil {
		writeJSON(rw, http.StatusOK, map[string]any{"traces": []Trace{}})
		return
	}
	limit := 0
	if v := r.URL.Query().Get("limit"); v != "" {
		limit, _ = strconv.Atoi(v)
	}
	traces := p.tracer.recent(limit)
	writeJSON(rw, http.StatusOK, map[string]any{"traces": traces, "count": len(traces)})
}

// timeNow is a seam so traces are testable with a fixed clock.
var timeNow = time.Now

package serving

// Observability (PRODUCTION-READINESS P1-2): Prometheus metrics + readiness on both halves of the
// data plane.
//
//   Gateway:  GET /metrics  — request rate/latency/errors by route, unrouted (busy/no-route) counts,
//                             live fleet by state, gateway in-flight, fleet capacity, training jobs.
//             GET /readyz   — 200 only when ≥1 healthy non-trainer worker is live (an LB pulls a
//                             gateway that cannot serve inference); /healthz stays pure liveness.
//   Worker:   GET /metrics  — served/error counts, active/queued gauges, EMA service time (scraped
//                             over the same mTLS channel the controller dials — in-perimeter).
//             GET /readyz   — 200 once the engine is up (the listener only binds after engine.Start,
//                             so serving == ready on a worker).
//
// Route labels come from the FIXED mux patterns (bounded cardinality); anything unknown collapses
// into "other" so a scanner cannot mint unbounded series.

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"dani.local/agent/internal/metrics"
)

// atomicLoad reads a worker load counter (int64 atomics shared with the heartbeat path).
func atomicLoad(p *int64) int64 { return atomic.LoadInt64(p) }

// planeMetrics is the gateway-side instrument set.
type planeMetrics struct {
	reg         *metrics.Registry
	requests    *metrics.Counter   // dani_gateway_requests_total{route,code}
	duration    *metrics.Histogram // dani_gateway_request_duration_seconds{route}
	unrouted    *metrics.Counter   // dani_gateway_unrouted_total{reason} — busy | no_route
	edgeRefused *metrics.Counter   // dani_gateway_edge_refused_total{reason} — rate | body (P2-1)
}

// EnableMetrics attaches the observability surface to the gateway (call before ServeGateway).
// Returns the registry so callers can add their own instruments.
func (p *Plane) EnableMetrics() *metrics.Registry {
	reg := metrics.NewRegistry()
	pm := &planeMetrics{
		reg:         reg,
		requests:    reg.Counter("dani_gateway_requests_total", "Gateway HTTP requests by route and status code.", "route", "code"),
		duration:    reg.Histogram("dani_gateway_request_duration_seconds", "Gateway request latency by route.", nil, "route"),
		unrouted:    reg.Counter("dani_gateway_unrouted_total", "Chat requests the router could not place, by reason (busy = every eligible worker saturated; no_route = nothing serves the model/classification).", "reason"),
		edgeRefused: reg.Counter("dani_gateway_edge_refused_total", "Requests refused at the edge, by reason (rate = per-IP limit; body = size cap).", "reason"),
	}
	reg.GaugeFunc("dani_fleet_workers", "Fleet nodes by state as seen from live heartbeats.", []string{"state"}, p.fleetGauge)
	reg.GaugeFunc("dani_gateway_inflight", "Requests the gateway has dispatched and not yet completed.", nil, func() []metrics.GaugeSample {
		p.mu.RLock()
		defer p.mu.RUnlock()
		n := 0
		for _, v := range p.inflight {
			n += v
		}
		return []metrics.GaugeSample{{Value: float64(n)}}
	})
	reg.GaugeFunc("dani_fleet_capacity", "Total serving slots (max_concurrent) across live healthy workers.", nil, func() []metrics.GaugeSample {
		p.mu.RLock()
		defer p.mu.RUnlock()
		n := 0
		for _, w := range p.workers {
			if !w.Trainer && time.Since(w.LastSeen) <= p.stale && w.Health == "healthy" {
				n += w.MaxConcurrent
			}
		}
		return []metrics.GaugeSample{{Value: float64(n)}}
	})
	reg.GaugeFunc("dani_training_jobs", "Training jobs by state.", []string{"state"}, func() []metrics.GaugeSample {
		if p.training == nil || p.training.Training == nil {
			return nil
		}
		byState := map[string]int{}
		for _, j := range p.training.Training.List() {
			byState[string(j.State)]++
		}
		out := make([]metrics.GaugeSample, 0, len(byState))
		for s, n := range byState {
			out = append(out, metrics.GaugeSample{LabelVals: []string{s}, Value: float64(n)})
		}
		return out
	})
	reg.RuntimeGauges() // go_goroutines / heap / gc — leak + soak signals (P2-B)
	p.metrics = pm
	return reg
}

// fleetGauge classifies every known worker into exactly one state.
func (p *Plane) fleetGauge() []metrics.GaugeSample {
	p.mu.RLock()
	defer p.mu.RUnlock()
	counts := map[string]int{"healthy": 0, "stale": 0, "drained": 0, "trainer": 0, "degraded": 0}
	for _, w := range p.workers {
		switch {
		case p.drained[w.NodeUUID]:
			counts["drained"]++
		case w.Trainer:
			counts["trainer"]++
		case time.Since(w.LastSeen) > p.stale:
			counts["stale"]++
		case w.Health != "healthy":
			counts["degraded"]++
		default:
			counts["healthy"]++
		}
	}
	out := make([]metrics.GaugeSample, 0, len(counts))
	for _, s := range []string{"degraded", "drained", "healthy", "stale", "trainer"} { // stable order
		out = append(out, metrics.GaugeSample{LabelVals: []string{s}, Value: float64(counts[s])})
	}
	return out
}

// routeLabel collapses a request path onto its fixed mux pattern (bounded label cardinality).
func routeLabel(path string) string {
	switch {
	case path == "/", path == "/healthz", path == "/readyz", path == "/metrics",
		path == "/v1/chat/completions", path == "/v1/models":
		return path
	case strings.HasPrefix(path, "/dani/"):
		return path // fixed API surface (no path parameters — ids travel in queries/bodies)
	case strings.HasPrefix(path, "/auth/"):
		return path // login/callback/logout only
	case path == "/console" || strings.HasPrefix(path, "/console/"):
		return "/console"
	default:
		return "other" // scanners don't get to mint series
	}
}

// statusRecorder captures the response code for the request counter.
type statusRecorder struct {
	http.ResponseWriter
	code int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.code = code
	s.ResponseWriter.WriteHeader(code)
}

// instrument wraps the gateway handler with request counting + latency observation.
func (pm *planeMetrics) instrument(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: rw, code: http.StatusOK}
		next.ServeHTTP(rec, r)
		route := routeLabel(r.URL.Path)
		pm.requests.Inc(route, itoa3(rec.code))
		pm.duration.ObserveSince(start, route)
	})
}

// itoa3 formats a 3-digit HTTP status without strconv in the hot path.
func itoa3(code int) string {
	if code < 100 || code > 999 {
		code = 200
	}
	return string([]byte{byte('0' + code/100), byte('0' + code/10%10), byte('0' + code%10)})
}

// workerMetrics is the worker-side instrument set (scraped over the worker's mTLS server — the
// scraper sits in-perimeter and presents a fleet identity, exactly like the controller does).
type workerMetrics struct {
	reg      *metrics.Registry
	requests *metrics.Counter // dani_worker_requests_total{code}
}

// newWorkerMetrics builds the worker registry over the worker's live load atomics.
func newWorkerMetrics(w *Worker) *workerMetrics {
	reg := metrics.NewRegistry()
	wm := &workerMetrics{
		reg:      reg,
		requests: reg.Counter("dani_worker_requests_total", "Inference requests by status code.", "code"),
	}
	one := func(name, help string, read func() float64) {
		reg.GaugeFunc(name, help, nil, func() []metrics.GaugeSample {
			return []metrics.GaugeSample{{Value: read()}}
		})
	}
	one("dani_worker_active", "Requests being served right now.", func() float64 { return float64(atomicLoad(&w.active)) })
	one("dani_worker_queued", "Requests waiting for a serving slot (DP4).", func() float64 { return float64(atomicLoad(&w.queued)) })
	one("dani_worker_served_total", "Lifetime completions.", func() float64 { return float64(atomicLoad(&w.served)) })
	one("dani_worker_ema_service_ms", "EMA of service time in milliseconds.", func() float64 { return float64(atomicLoad(&w.emaMs)) })
	one("dani_worker_slots", "Configured serving slots (max concurrent).", func() float64 { return float64(w.maxConcurrent) })
	return wm
}

// instrument wraps the worker mux with the request counter (routes are fixed: chat/healthz/readyz/metrics).
func (wm *workerMetrics) instrument(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: rw, code: http.StatusOK}
		next.ServeHTTP(rec, r)
		if r.URL.Path == "/v1/chat/completions" { // count inference, not scrapes/probes
			wm.requests.Inc(itoa3(rec.code))
		}
	})
}

// handleReadyz: the gateway is READY when it can actually route inference — ≥1 live healthy
// non-trainer worker. Liveness (/healthz) stays unconditional; this is the LB signal.
func (p *Plane) handleReadyz(rw http.ResponseWriter, _ *http.Request) {
	p.mu.RLock()
	workers := 0
	for _, w := range p.workers {
		if !w.Trainer && !p.drained[w.NodeUUID] && time.Since(w.LastSeen) <= p.stale && w.Health == "healthy" {
			workers++
		}
	}
	p.mu.RUnlock()
	rw.Header().Set("Content-Type", "application/json")
	if workers == 0 {
		rw.WriteHeader(http.StatusServiceUnavailable)
	}
	_ = json.NewEncoder(rw).Encode(map[string]any{"ready": workers > 0, "workers": workers})
}

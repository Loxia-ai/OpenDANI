package serving

// Plane-side glue for the Open-DANI contribution economy (internal/ledger). Contributors (positive
// balance) get guaranteed service up to full capacity; everyone else is best-effort — admitted only
// while the fleet has spare capacity beyond the contributor reserve. Nothing is hard-blocked; a
// best-effort client is deferred (not rejected) only under genuine load. Off in enterprise.

import (
	"encoding/json"
	"net/http"
	"time"

	"dani.local/agent/internal/ledger"
)

// EnableLedger turns on the contribution economy. reserveFrac in [0,1) is the share of fleet capacity
// held for contributors (default 0.25): best-effort traffic is admitted only while utilization is
// below (1 - reserveFrac), so contributors keep flowing under load while tourists ride the slack.
func (p *Plane) EnableLedger(reserveFrac float64) {
	if reserveFrac < 0 || reserveFrac >= 1 {
		reserveFrac = 0.25
	}
	p.mu.Lock()
	p.ledger = ledger.New()
	p.reserveFrac = reserveFrac
	p.mu.Unlock()
}

// utilization is fleet-wide in-flight / total serving capacity across healthy, non-trainer,
// non-drained workers, in [0,1] (0 when there is no capacity).
func (p *Plane) utilization() float64 {
	p.mu.RLock()
	defer p.mu.RUnlock()
	inflight, capacity := 0, 0
	for _, w := range p.workers {
		if w.Trainer || p.drained[w.NodeUUID] || time.Since(w.LastSeen) > p.stale || w.Health != "healthy" {
			continue
		}
		capacity += w.MaxConcurrent
		inflight += p.inflight[w.NodeUUID]
	}
	if capacity == 0 {
		return 1 // no capacity = fully saturated (shed best-effort)
	}
	return float64(inflight) / float64(capacity)
}

// clientID is the consuming identity for the ledger (its self-minted open id, presented as a header).
// Absent -> "" -> anonymous tourist (best-effort).
func clientID(r *http.Request) string { return r.Header.Get("X-Dani-Client") }

// admitLedger decides whether to serve now. Returns (proceed, priority). When the ledger is off it
// always proceeds. A best-effort client is deferred with a friendly 429 (never a hard block) only
// when the fleet is busy past the contributor reserve; a priority contributor always proceeds.
func (p *Plane) admitLedger(rw http.ResponseWriter, r *http.Request) (proceed, priority bool) {
	p.mu.RLock()
	l, reserve := p.ledger, p.reserveFrac
	p.mu.RUnlock()
	if l == nil {
		return true, false
	}
	priority = l.Priority(clientID(r))
	if priority {
		return true, true
	}
	if p.utilization() >= 1-reserve {
		if p.metrics != nil {
			p.metrics.edgeRefused.Inc("best_effort_deferred")
		}
		rw.Header().Set("Retry-After", "2")
		rw.Header().Set("X-Dani-Tier", "best-effort")
		http.Error(rw, "network is busy serving contributors right now — run a worker (dani-agent worker --open-join) to earn priority, or retry shortly", http.StatusTooManyRequests)
		return false, false
	}
	return true, false
}

// ledgerSettle records the economics of a completed request: the CONSUMER spends the tokens it
// received; the WORKER that actually served useful (non-seed-replaced) work EARNS them. A user who
// runs a worker and consumes under the same id nets out — contribution funds consumption.
func (p *Plane) ledgerSettle(clientId, servedWorkerId string, servedBody []byte, seedReplaced bool) {
	p.mu.RLock()
	l := p.ledger
	p.mu.RUnlock()
	if l == nil {
		return
	}
	tok := float64(completionTokensOf(servedBody))
	if tok <= 0 {
		tok = 1
	}
	l.Spend(clientId, tok)
	if !seedReplaced { // only genuinely-served (verified) work earns — a replaced answer earns nothing
		l.Earn(servedWorkerId, tok)
	}
}

// completionTokensOf reads usage.completion_tokens from an OpenAI-shaped response body.
func completionTokensOf(body []byte) int {
	var r struct {
		Usage struct {
			CompletionTokens int `json:"completion_tokens"`
		} `json:"usage"`
	}
	if json.Unmarshal(body, &r) != nil {
		return 0
	}
	return r.Usage.CompletionTokens
}

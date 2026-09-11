package serving

// Open-DANI seed-anchored verification: a public network can't trust a volunteer's answer, and it
// can't exact-match it against a seed (LLM output is non-deterministic across hardware). So an
// answer from a LOW-REPUTATION, NON-SEED worker is cross-checked against a node the OPERATOR runs
// (a "seed"): if they agree (semantic similarity, not byte-equality) the volunteer's answer is served
// and its reputation rises; if they disagree the SEED's answer is served instead and the volunteer is
// penalized. High-reputation volunteers and seeds skip the check (sampling — cheap by design: one
// seed lifts a node, not a quorum). See OPEN-DANI-FIRST-SLICE.md.
//
// Similarity here is a dependency-free token-overlap (Jaccard). It is deliberately crude for the
// slice — the production upgrade is embedding cosine (the codebase already has an embedder). The
// STRONGER path for the flagship coding workload is outcome verification (does it compile/run?),
// which the /demo/verify gate already provides and needs no similarity at all.

import (
	"encoding/json"
	"strings"
	"time"

	"dani.local/agent/internal/reputation"
)

type verifyConfig struct {
	repThreshold float64 // volunteers at/above this reputation are trusted enough to skip cross-check
	simThreshold float64 // token-overlap at/above this = "agrees with the seed"
}

// EnableSeedVerify turns on seed-anchored verification (Open-DANI). repThreshold/simThreshold use
// sane defaults when <= 0.
func (p *Plane) EnableSeedVerify(repThreshold, simThreshold float64) {
	if repThreshold <= 0 {
		repThreshold = 0.7
	}
	if simThreshold <= 0 {
		simThreshold = 0.5
	}
	p.mu.Lock()
	p.reputation = reputation.New(0, 0, 0)
	p.verify = &verifyConfig{repThreshold: repThreshold, simThreshold: simThreshold}
	p.mu.Unlock()
}

// isSeed reports whether uuid is a trusted seed node.
func (p *Plane) isSeed(uuid string) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	w := p.workers[uuid]
	return w != nil && w.Seed
}

// needsVerify reports whether an answer served by `uuid` must be cross-checked: verification is on,
// the worker is not a seed, and its reputation is below the trust threshold.
func (p *Plane) needsVerify(uuid string, isSeed bool) bool {
	p.mu.RLock()
	v, rep := p.verify, p.reputation
	p.mu.RUnlock()
	if v == nil || rep == nil || isSeed {
		return false
	}
	return !rep.Trusted(uuid, v.repThreshold)
}

// reserveSeed picks a healthy trusted SEED serving the model, reserving a slot on it (so the
// cross-check load-balances across seeds). Returns ok=false if no seed can serve this model.
func (p *Plane) reserveSeed(model, classification string) (candidate, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	best := candidate{}
	found := false
	for _, w := range p.workers {
		if !w.Seed || w.Trainer || p.drained[w.NodeUUID] {
			continue
		}
		if time.Since(w.LastSeen) > p.stale || w.Health != "healthy" {
			continue
		}
		if rank(w.Class) < rank(classification) {
			continue
		}
		if model != "" && w.ModelID != model && !containsModel(w.Loaded, model) {
			continue
		}
		load := p.inflight[w.NodeUUID]
		if load >= w.MaxConcurrent+w.QueueDepth {
			continue
		}
		if !found || load < best.load || (load == best.load && w.NodeUUID < best.uuid) {
			best = candidate{uuid: w.NodeUUID, addr: w.DispatchAddr, site: w.Site, load: load,
				reverse: w.ReverseTunnel, tunnelAvail: w.TunnelAvailable}
			found = true
		}
	}
	if !found {
		return candidate{}, false
	}
	p.inflight[best.uuid]++
	return best, true
}

// tokenSet lowercases + splits into a set of word tokens (letters/digits runs).
func tokenSet(s string) map[string]struct{} {
	set := map[string]struct{}{}
	for _, f := range strings.FieldsFunc(strings.ToLower(s), func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9')
	}) {
		if f != "" {
			set[f] = struct{}{}
		}
	}
	return set
}

// similarity is token-overlap Jaccard in [0,1]. Two empty strings are identical (1); one empty is 0.
func similarity(a, b string) float64 {
	sa, sb := tokenSet(a), tokenSet(b)
	if len(sa) == 0 && len(sb) == 0 {
		return 1
	}
	if len(sa) == 0 || len(sb) == 0 {
		return 0
	}
	inter := 0
	for t := range sa {
		if _, ok := sb[t]; ok {
			inter++
		}
	}
	union := len(sa) + len(sb) - inter
	return float64(inter) / float64(union)
}

// extractAnswer pulls choices[0].message.content out of an OpenAI-shaped response body.
func extractAnswer(body []byte) string {
	var r struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if json.Unmarshal(body, &r) != nil || len(r.Choices) == 0 {
		return ""
	}
	return r.Choices[0].Message.Content
}

// agrees compares two answers under the config's similarity threshold.
func (p *Plane) agrees(a, b string) bool {
	p.mu.RLock()
	v := p.verify
	p.mu.RUnlock()
	if v == nil {
		return true
	}
	return similarity(a, b) >= v.simThreshold
}

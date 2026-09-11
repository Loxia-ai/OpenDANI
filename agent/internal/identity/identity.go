// Package identity is the Identity Bridge (Architecture §6.21 #9, D11/D39) — the thin slice the
// Training Subsystem and gateway need: resolve a bearer principal to {roles, clearance}.
//
// DEMO scope (Matrix #9): one provider, principals from an admin-loaded directory standing in for
// the IdP's group→role mapping (the OIDC exchange itself is out of this slice). What IS ported
// faithfully from the sim: the 15-minute principal cache (D39 — the TTL bounds the DP13
// verify-on-use freshness window) and the IdP-outage behavior (serve from cache within TTL;
// fail closed with no cache).
package identity

import (
	"fmt"
	"sync"
	"time"
)

// nowFn is a seam so tests can control the clock (production: time.Now).
var nowFn = time.Now

// Principal is a resolved identity: DANI roles + classification clearance.
type Principal struct {
	Sub       string   `json:"sub"`
	Display   string   `json:"display"`
	Roles     []string `json:"roles"`
	Clearance string   `json:"clearance"`
}

type cached struct {
	p  Principal
	at time.Time
}

// Bridge resolves principals against a directory with a D39 TTL cache.
type Bridge struct {
	Provider string
	TTL      time.Duration

	mu        sync.Mutex
	directory map[string]Principal
	cache     map[string]cached
	outage    bool
}

// New builds a Bridge with the D39 default TTL (15 minutes) and the DEMO directory — the same four
// principals the sim ships, standing in for a customer IdP with role mapping applied.
func New(provider string) *Bridge {
	b := &Bridge{Provider: provider, TTL: 15 * time.Minute, directory: map[string]Principal{}, cache: map[string]cached{}}
	for _, p := range []Principal{
		{Sub: "alice", Display: "Alice (Analyst)", Roles: []string{"user"}, Clearance: "restricted"},
		{Sub: "bob", Display: "Bob (Administrator)", Roles: []string{"user", "admin"}, Clearance: "secret"},
		{Sub: "carol", Display: "Carol (Contractor)", Roles: []string{"user"}, Clearance: "internal"},
		{Sub: "guest", Display: "Guest", Roles: []string{"user"}, Clearance: "unrestricted"},
	} {
		b.directory[p.Sub] = p
	}
	return b
}

// Add loads (or replaces) a directory principal — the admin-defined mapping hook.
func (b *Bridge) Add(p Principal) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.directory[p.Sub] = p
}

// SetOutage toggles the simulated IdP-unreachable state (D39 behavior is observable, not implied).
func (b *Bridge) SetOutage(v bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.outage = v
}

// Resolve returns the principal for sub. Cache hit within TTL short-circuits; during an IdP outage a
// cached principal (within TTL bounds, D39) is served, otherwise resolution fails closed.
func (b *Bridge) Resolve(sub string) (Principal, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := nowFn()
	if c, ok := b.cache[sub]; ok && now.Sub(c.at) < b.TTL {
		return c.p, nil
	}
	if b.outage {
		// Outage: a stale cache entry (past TTL) still beats failing — the sim's D39 call. With no
		// cache at all, resolution fails closed.
		if c, ok := b.cache[sub]; ok {
			return c.p, nil
		}
		return Principal{}, fmt.Errorf("identity: IdP outage and no cached principal for %q", sub)
	}
	p, ok := b.directory[sub]
	if !ok {
		return Principal{}, fmt.Errorf("identity: unknown principal %q", sub)
	}
	b.cache[sub] = cached{p: p, at: now}
	return p, nil
}

// Principals lists the directory (for the console).
func (b *Bridge) Principals() []Principal {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]Principal, 0, len(b.directory))
	for _, sub := range []string{"alice", "bob", "carol", "guest"} {
		if p, ok := b.directory[sub]; ok {
			out = append(out, p)
		}
	}
	// include any admin-added principals beyond the seeded four, in sub order (deterministic)
	var extra []Principal
	for sub, p := range b.directory {
		switch sub {
		case "alice", "bob", "carol", "guest":
		default:
			extra = append(extra, p)
		}
	}
	for i := 1; i < len(extra); i++ {
		for j := i; j > 0 && extra[j].Sub < extra[j-1].Sub; j-- {
			extra[j-1], extra[j] = extra[j], extra[j-1]
		}
	}
	return append(out, extra...)
}

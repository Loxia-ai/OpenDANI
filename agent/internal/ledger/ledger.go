// Package ledger is Open-DANI's contribution economy: you EARN credit by serving verified work and
// SPEND it by consuming inference. Contributors (positive balance) get PRIORITY — guaranteed service
// up to full network capacity. Everyone else gets BEST-EFFORT — served whenever there is spare
// capacity. Nothing is ever hard-blocked, so a client is only ever made to wait under genuine
// scarcity, and even then only if they are not contributing.
//
// Why this is Sybil-proof by construction: there are NO starter credits to farm. Best-effort IS the
// free tier, and it only ever uses capacity that would otherwise sit idle — free to give away. The
// only thing an identity earns you is priority, and priority can only be earned by actually
// contributing compute. So minting fake identities buys nothing.
//
// Keyed by the self-minted (pubkey-derived) identity, so a balance can't be forked by renaming.
// Enterprise DANI does not use this.
package ledger

import (
	"sort"
	"sync"
)

// Store is a thread-safe contribution balance table. balance = earned - spent (in tokens); it may go
// negative (a heavy consumer who never contributes) — that simply keeps them on best-effort.
type Store struct {
	mu  sync.RWMutex
	bal map[string]float64
}

func New() *Store { return &Store{bal: map[string]float64{}} }

// Earn credits an identity for serving verified work (tokens it produced). Reward for contribution.
func (s *Store) Earn(id string, tokens float64) {
	if id == "" || tokens <= 0 {
		return
	}
	s.mu.Lock()
	s.bal[id] += tokens
	s.mu.Unlock()
}

// Spend debits an identity for consuming inference (tokens it received).
func (s *Store) Spend(id string, tokens float64) {
	if id == "" || tokens <= 0 {
		return
	}
	s.mu.Lock()
	s.bal[id] -= tokens
	s.mu.Unlock()
}

// Balance returns an identity's current net contribution (0 if unseen).
func (s *Store) Balance(id string) float64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.bal[id]
}

// Priority reports whether an identity is a net contributor (earned more than it spent). Net
// contributors get guaranteed service; everyone else gets best-effort. An empty/absent id is never
// priority — an anonymous tourist rides best-effort.
func (s *Store) Priority(id string) bool {
	if id == "" {
		return false
	}
	return s.Balance(id) > 0
}

// Entry is one identity's balance (for the ops/fleet view).
type Entry struct {
	ID      string
	Balance float64
}

// Snapshot returns all non-zero balances, highest first (the network's top contributors/consumers).
func (s *Store) Snapshot() []Entry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Entry, 0, len(s.bal))
	for id, v := range s.bal {
		if v != 0 {
			out = append(out, Entry{ID: id, Balance: v})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Balance != out[j].Balance {
			return out[i].Balance > out[j].Balance
		}
		return out[i].ID < out[j].ID
	})
	return out
}

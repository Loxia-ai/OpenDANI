// Package reputation tracks how much Open-DANI trusts each volunteer node, keyed by its
// (pubkey-derived, self-certifying) id — so a Sybil can't reset its score by renaming. Score is in
// [0,1]; it rises when the node's output is verified correct and falls when it disagrees with a
// trusted seed or goes missing. The router and the verification gate read it: high-reputation nodes
// are cross-checked rarely, low-reputation ones always. This is the second line after proof-of-work
// (openid) — cheap because one seed agreement lifts a node, not a quorum.
package reputation

import (
	"sort"
	"sync"
)

// Store is a thread-safe per-node reputation table.
type Store struct {
	mu      sync.RWMutex
	score   map[string]float64
	initial float64
	reward  float64
	penalty float64
}

// New builds a store. initial is a new node's starting trust (default 0.3 — earn your way up);
// reward/penalty are the per-event step sizes (defaults 0.1 / 0.25 — distrust faster than trust).
func New(initial, reward, penalty float64) *Store {
	if initial <= 0 {
		initial = 0.3
	}
	if reward <= 0 {
		reward = 0.1
	}
	if penalty <= 0 {
		penalty = 0.25
	}
	return &Store{score: map[string]float64{}, initial: initial, reward: reward, penalty: penalty}
}

func clamp(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

// Get returns a node's current score (the initial value if unseen).
func (s *Store) Get(id string) float64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if v, ok := s.score[id]; ok {
		return v
	}
	return s.initial
}

// Reward nudges a node up (verified-correct output). Returns the new score.
func (s *Store) Reward(id string) float64 { return s.adjust(id, s.reward) }

// Penalize nudges a node down (disagreed with a seed / bad output). Returns the new score.
func (s *Store) Penalize(id string) float64 { return s.adjust(id, -s.penalty) }

func (s *Store) adjust(id string, delta float64) float64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, ok := s.score[id]
	if !ok {
		cur = s.initial
	}
	cur = clamp(cur + delta)
	s.score[id] = cur
	return cur
}

// Trusted reports whether a node's score is at or above threshold (skip cross-checking above it).
func (s *Store) Trusted(id string, threshold float64) bool { return s.Get(id) >= threshold }

// Snapshot returns a copy of all known scores (for the fleet view / ops), sorted by id.
type Entry struct {
	ID    string
	Score float64
}

func (s *Store) Snapshot() []Entry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Entry, 0, len(s.score))
	for id, v := range s.score {
		out = append(out, Entry{ID: id, Score: v})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

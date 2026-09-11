// Package config is the governed configuration store (PRODUCTION-READINESS P1-7, spec §6.20):
// operational parameters resolve through the four-scope hierarchy — Fleet-wide defaults, overridden
// per Site, per Role, per Node — most specific wins. Entries are durable (dbx seam: SQLite
// standalone / PostgreSQL HA), versioned (nodes cheaply detect change), validated at WRITE time
// (a bad value is refused at the console, not discovered on a node at 3am), and audited by the
// caller. Nodes fetch their EFFECTIVE map over the mTLS Link and live-apply dynamic keys.
package config

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"dani.local/agent/internal/dbx"
)

// Scope kinds, least to most specific (resolution precedence is the reverse).
const (
	ScopeFleet = "fleet"
	ScopeSite  = "site"
	ScopeRole  = "role"
	ScopeNode  = "node"
)

var scopeRank = map[string]int{ScopeFleet: 0, ScopeSite: 1, ScopeRole: 2, ScopeNode: 3}

// Entry is one stored override.
type Entry struct {
	Scope    string `json:"scope"`              // fleet | site | role | node
	ScopeVal string `json:"scopeVal,omitempty"` // "" for fleet; site tag / role name / node uuid otherwise
	Key      string `json:"key"`
	Value    string `json:"value"`
}

// Resolved is one effective value with its provenance (which scope won).
type Resolved struct {
	Value    string `json:"value"`
	Scope    string `json:"scope"`
	ScopeVal string `json:"scopeVal,omitempty"`
}

// NodeAttrs identify a node for resolution.
type NodeAttrs struct {
	UUID  string
	Site  string
	Roles []string
}

// validator checks a known key's value. Unknown keys must use the "x-" prefix (operator-defined),
// so a typo'd built-in key is a hard error instead of a silent no-op.
type validator struct {
	desc  string
	check func(string) error
}

func durationRange(min, max time.Duration) func(string) error {
	return func(v string) error {
		d, err := time.ParseDuration(v)
		if err != nil {
			return fmt.Errorf("want a duration (e.g. 20s): %w", err)
		}
		if d < min || d > max {
			return fmt.Errorf("duration %s out of range [%s, %s]", d, min, max)
		}
		return nil
	}
}

func intRange(min, max int) func(string) error {
	return func(v string) error {
		n, err := strconv.Atoi(v)
		if err != nil {
			return fmt.Errorf("want an integer: %w", err)
		}
		if n < min || n > max {
			return fmt.Errorf("%d out of range [%d, %d]", n, min, max)
		}
		return nil
	}
}

// intOrAll accepts the literal "all" (a dedicated machine) or an integer in [min, max].
func intOrAll(min, max int) func(string) error {
	inner := intRange(min, max)
	return func(v string) error {
		if strings.EqualFold(strings.TrimSpace(v), "all") {
			return nil
		}
		return inner(v)
	}
}

// knownKeys is the typed registry of built-in configuration keys.
var knownKeys = map[string]validator{
	"worker.slo-budget":      {"max time a request may wait in the admission queue (DP4)", durationRange(100*time.Millisecond, 10*time.Minute)},
	"worker.queue-depth":     {"admission-queue depth before back-pressure (DP4)", intRange(0, 1024)},
	"worker.max-cores":       {"CPU cores DANI may use on a node: 0 = auto (all inside a cgroup; bare host leaves 2 for the user, ≤2-core boxes go all-in), \"all\" = dedicated machine, or N", intOrAll(0, 1024)},
	"worker.max-model-mem-mb": {"model-memory budget in MB before a node refuses to load a model (0 = auto/unbounded)", intRange(0, 4_000_000)},
	"policy.rate-max":        {"max requests per principal per minute (0 = unlimited)", intRange(0, 1_000_000)},
	"gateway.max-body-bytes": {"max request-body size the gateway accepts (P2-1)", intRange(4096, 1<<30)},
	"gateway.rate-per-ip":    {"max requests per minute per client IP at the gateway edge (0 = off, P2-1)", intRange(0, 1_000_000)},
}

// KnownKeys lists the built-in keys and their descriptions (console help).
func KnownKeys() map[string]string {
	out := make(map[string]string, len(knownKeys))
	for k, v := range knownKeys {
		out[k] = v.desc
	}
	return out
}

// Store is the durable four-scope config store.
type Store struct {
	db      *sql.DB
	dialect dbx.Dialect
}

const schemaSQL = `
CREATE TABLE IF NOT EXISTS config_entries (
  scope_kind TEXT NOT NULL,
  scope_val  TEXT NOT NULL,
  key        TEXT NOT NULL,
  value      TEXT NOT NULL,
  PRIMARY KEY (scope_kind, scope_val, key)
);
CREATE TABLE IF NOT EXISTS config_version (
  id      INTEGER PRIMARY KEY,
  version BIGINT NOT NULL
);`

// Open opens (and migrates) the config store at dsn.
func Open(ctx context.Context, dsn string) (*Store, error) {
	db, dialect, err := dbx.Open(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("config store: %w", err)
	}
	if _, err := db.ExecContext(ctx, schemaSQL); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("config store: schema: %w", err)
	}
	// ensure the singleton version row exists
	if _, err := db.ExecContext(ctx, dialect.Rebind(`INSERT INTO config_version (id, version) SELECT 1, 0 WHERE NOT EXISTS (SELECT 1 FROM config_version WHERE id = 1)`)); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("config store: version seed: %w", err)
	}
	return &Store{db: db, dialect: dialect}, nil
}

// Close releases the underlying DB.
func (s *Store) Close() error { return s.db.Close() }

// validate checks scope + key + value shape (write-time validation, §6.20 "validated config").
func validate(e Entry) error {
	if _, ok := scopeRank[e.Scope]; !ok {
		return fmt.Errorf("config: unknown scope %q (want fleet|site|role|node)", e.Scope)
	}
	if e.Scope == ScopeFleet && e.ScopeVal != "" {
		return fmt.Errorf("config: fleet scope takes no scope value")
	}
	if e.Scope != ScopeFleet && e.ScopeVal == "" {
		return fmt.Errorf("config: %s scope needs a scope value (the %s)", e.Scope, e.Scope)
	}
	if e.Key == "" {
		return fmt.Errorf("config: empty key")
	}
	if v, known := knownKeys[e.Key]; known {
		if err := v.check(e.Value); err != nil {
			return fmt.Errorf("config: %s: %w", e.Key, err)
		}
		return nil
	}
	if !strings.HasPrefix(e.Key, "x-") {
		return fmt.Errorf("config: unknown key %q — built-in keys: %s (operator-defined keys use the x- prefix)",
			e.Key, strings.Join(sortedKeys(), ", "))
	}
	return nil
}

func sortedKeys() []string {
	out := make([]string, 0, len(knownKeys))
	for k := range knownKeys {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Set upserts one entry (validated) and bumps the version.
func (s *Store) Set(ctx context.Context, e Entry) error {
	if err := validate(e); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("config store: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	r := s.dialect.Rebind
	if _, err := tx.ExecContext(ctx, r(`DELETE FROM config_entries WHERE scope_kind = ? AND scope_val = ? AND key = ?`),
		e.Scope, e.ScopeVal, e.Key); err != nil {
		return fmt.Errorf("config store: clear: %w", err)
	}
	if _, err := tx.ExecContext(ctx, r(`INSERT INTO config_entries (scope_kind, scope_val, key, value) VALUES (?, ?, ?, ?)`),
		e.Scope, e.ScopeVal, e.Key, e.Value); err != nil {
		return fmt.Errorf("config store: insert: %w", err)
	}
	if _, err := tx.ExecContext(ctx, r(`UPDATE config_version SET version = version + 1 WHERE id = 1`)); err != nil {
		return fmt.Errorf("config store: version: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("config store: commit: %w", err)
	}
	return nil
}

// Delete removes one entry (idempotent) and bumps the version.
func (s *Store) Delete(ctx context.Context, scope, scopeVal, key string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("config store: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	r := s.dialect.Rebind
	if _, err := tx.ExecContext(ctx, r(`DELETE FROM config_entries WHERE scope_kind = ? AND scope_val = ? AND key = ?`),
		scope, scopeVal, key); err != nil {
		return fmt.Errorf("config store: delete: %w", err)
	}
	if _, err := tx.ExecContext(ctx, r(`UPDATE config_version SET version = version + 1 WHERE id = 1`)); err != nil {
		return fmt.Errorf("config store: version: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("config store: commit: %w", err)
	}
	return nil
}

// Version reports the store's change counter (nodes poll cheaply on it).
func (s *Store) Version(ctx context.Context) (int64, error) {
	var v int64
	if err := s.db.QueryRowContext(ctx, s.dialect.Rebind(`SELECT version FROM config_version WHERE id = 1`)).Scan(&v); err != nil {
		return 0, fmt.Errorf("config store: version: %w", err)
	}
	return v, nil
}

// List returns every stored entry (console view), scope-major order.
func (s *Store) List(ctx context.Context) ([]Entry, error) {
	rows, err := s.db.QueryContext(ctx, s.dialect.Rebind(`SELECT scope_kind, scope_val, key, value FROM config_entries ORDER BY scope_kind, scope_val, key`))
	if err != nil {
		return nil, fmt.Errorf("config store: list: %w", err)
	}
	defer rows.Close()
	out := []Entry{}
	for rows.Next() {
		var e Entry
		if err := rows.Scan(&e.Scope, &e.ScopeVal, &e.Key, &e.Value); err != nil {
			return nil, fmt.Errorf("config store: scan: %w", err)
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("config store: rows: %w", err)
	}
	return out, nil
}

// ResolveAll computes a node's EFFECTIVE configuration: for each key, the most specific matching
// scope wins (node > role > site > fleet). Among multiple matching role entries the first role in
// sorted order wins — deterministic, documented (D-37).
func (s *Store) ResolveAll(ctx context.Context, n NodeAttrs) (map[string]Resolved, error) {
	entries, err := s.List(ctx)
	if err != nil {
		return nil, err
	}
	roles := append([]string(nil), n.Roles...)
	sort.Strings(roles)
	roleIdx := map[string]int{}
	for i, r := range roles {
		roleIdx[r] = i
	}
	type winner struct {
		Resolved
		rank    int
		roleOrd int
	}
	best := map[string]winner{}
	for _, e := range entries {
		match, roleOrd := false, 0
		switch e.Scope {
		case ScopeFleet:
			match = true
		case ScopeSite:
			match = e.ScopeVal == n.Site
		case ScopeRole:
			if i, ok := roleIdx[e.ScopeVal]; ok {
				match, roleOrd = true, i
			}
		case ScopeNode:
			match = e.ScopeVal == n.UUID
		}
		if !match {
			continue
		}
		rank := scopeRank[e.Scope]
		cur, seen := best[e.Key]
		if !seen || rank > cur.rank || (rank == cur.rank && e.Scope == ScopeRole && roleOrd < cur.roleOrd) {
			best[e.Key] = winner{Resolved{Value: e.Value, Scope: e.Scope, ScopeVal: e.ScopeVal}, rank, roleOrd}
		}
	}
	out := make(map[string]Resolved, len(best))
	for k, w := range best {
		out[k] = w.Resolved
	}
	return out, nil
}

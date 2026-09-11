// Package audit is the Audit Log Aggregator (Architecture §6.17.7 + §6.15; DEMO scope Matrix #8:
// Active tier only, M4). Every event appends to a HASH CHAIN — each record carries the hash of the
// previous — and the chain head is periodically SIGNED with the KMS audit-chain-signing key
// (PurposeAuditChainSigning, minted at genesis). Verify() replays the whole chain and re-checks the
// head signatures, so any tampering with a historical record — an UPDATE in the database, a
// re-ordered row, a deleted event — breaks the chain and is detected (§6.17.12).
//
// Storage is SQLite (the registry pattern; PostgreSQL in v1.0). Archived/Compliance tiers stay a
// documented seam, exactly like the sim.
package audit

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"dani.local/agent/internal/dbx"
	"dani.local/agent/pkg/dani"
)

// nowFn is a seam for deterministic timestamps in tests (production: time.Now).
var nowFn = time.Now

const genesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

const schemaSQLite = `
CREATE TABLE IF NOT EXISTS audit_events (
  seq       INTEGER PRIMARY KEY,
  at        TEXT NOT NULL,
  type      TEXT NOT NULL,
  payload   TEXT NOT NULL,
  prev_hash TEXT NOT NULL,
  hash      TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_heads (
  seq  INTEGER NOT NULL,
  at   TEXT NOT NULL,
  head TEXT NOT NULL,
  sig  BLOB NOT NULL,
  pub  BLOB NOT NULL
);`

const schemaPostgres = `
CREATE TABLE IF NOT EXISTS audit_events (
  seq       BIGINT PRIMARY KEY,
  at        TEXT NOT NULL,
  type      TEXT NOT NULL,
  payload   TEXT NOT NULL,
  prev_hash TEXT NOT NULL,
  hash      TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_heads (
  seq  BIGINT NOT NULL,
  at   TEXT NOT NULL,
  head TEXT NOT NULL,
  sig  BYTEA NOT NULL,
  pub  BYTEA NOT NULL
);`

// Event is one link of the chain.
type Event struct {
	Seq      int64           `json:"seq"`
	At       time.Time       `json:"at"`
	Type     string          `json:"type"`
	Payload  json.RawMessage `json:"payload"`
	PrevHash string          `json:"prevHash"`
	Hash     string          `json:"hash"`
}

// Head is one signed chain-root anchor.
type Head struct {
	Seq  int64     `json:"seq"`
	At   time.Time `json:"at"`
	Head string    `json:"head"`
	Sig  []byte    `json:"sig"`
	Pub  []byte    `json:"pub"`
}

// Log is the Active-tier aggregator. SQLite (DEMO/dev) or PostgreSQL (HA) via the dbx seam.
type Log struct {
	mu      sync.Mutex
	db      *sql.DB
	dialect dbx.Dialect
	ks      dani.KeyStore
	seq     int64
	head    string
}

// Open opens (or creates) the audit chain at dsn and resumes seq/head. dsn is a SQLite path /
// ":memory:" / "sqlite:<path>", or a "postgres://..." URL (HA).
func Open(ctx context.Context, dsn string, ks dani.KeyStore) (*Log, error) {
	db, dialect, err := dbx.Open(ctx, dsn)
	if err != nil {
		return nil, err
	}
	schema := schemaSQLite
	if dialect == dbx.Postgres {
		schema = schemaPostgres
	}
	if _, err := db.ExecContext(ctx, schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("audit: apply schema: %w", err)
	}
	l := &Log{db: db, dialect: dialect, ks: ks, head: genesisHash}
	row := db.QueryRowContext(ctx, `SELECT seq, hash FROM audit_events ORDER BY seq DESC LIMIT 1`)
	var seq int64
	var head string
	switch err := row.Scan(&seq, &head); err {
	case nil:
		l.seq, l.head = seq, head
	case sql.ErrNoRows:
	default:
		_ = db.Close()
		return nil, err
	}
	return l, nil
}

// Close closes the underlying store.
func (l *Log) Close() error { return l.db.Close() }

// exec/queryRow/query rebind portable `?` SQL to the dialect, then delegate.
func (l *Log) exec(ctx context.Context, q string, args ...any) (sql.Result, error) {
	return l.db.ExecContext(ctx, l.dialect.Rebind(q), args...)
}
func (l *Log) queryRow(ctx context.Context, q string, args ...any) *sql.Row {
	return l.db.QueryRowContext(ctx, l.dialect.Rebind(q), args...)
}
func (l *Log) query(ctx context.Context, q string, args ...any) (*sql.Rows, error) {
	return l.db.QueryContext(ctx, l.dialect.Rebind(q), args...)
}

// hashRecord computes a link's hash over its canonical bytes (matches the sim's shape). at is the
// STORED timestamp string, so verification re-hashes exactly what was written.
func hashRecord(seq int64, at, typ string, payload []byte, prevHash string) string {
	b, _ := json.Marshal(struct {
		Seq      int64           `json:"seq"`
		At       string          `json:"at"`
		Type     string          `json:"type"`
		Payload  json.RawMessage `json:"payload"`
		PrevHash string          `json:"prevHash"`
	}{seq, at, typ, payload, prevHash})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Emit appends one event to the chain. payload must be JSON-marshalable (maps/strings — always is
// for our call sites). Fire-and-forget at call sites: an audit failure must not fail the operation,
// so callers ignore the error; it is returned for tests and the endpoint's health reporting.
func (l *Log) Emit(typ string, payload map[string]any) error {
	pj, _ := json.Marshal(payload) // map[string]any of strings/numbers — cannot fail
	l.mu.Lock()
	defer l.mu.Unlock()
	seq := l.seq + 1
	at := nowFn().UTC().Format(time.RFC3339Nano)
	h := hashRecord(seq, at, typ, pj, l.head)
	if _, err := l.db.Exec(l.dialect.Rebind(`INSERT INTO audit_events (seq, at, type, payload, prev_hash, hash) VALUES (?,?,?,?,?,?)`),
		seq, at, typ, string(pj), l.head, h); err != nil {
		return err
	}
	l.seq, l.head = seq, h
	return nil
}

// SignHead anchors the current chain head with the KMS audit-chain-signing key (§6.17.7 step 5).
// No-op on an empty chain.
func (l *Log) SignHead(ctx context.Context) error {
	l.mu.Lock()
	seq, head := l.seq, l.head
	l.mu.Unlock()
	if seq == 0 {
		return nil
	}
	at := nowFn().UTC()
	msg := headMsg(seq, head)
	sig, err := l.ks.Sign(ctx, dani.PurposeAuditChainSigning, msg)
	if err != nil {
		return err
	}
	pub, err := l.ks.GetPublicKey(ctx, dani.PurposeAuditChainSigning)
	if err != nil {
		return err
	}
	_, err = l.exec(ctx, `INSERT INTO audit_heads (seq, at, head, sig, pub) VALUES (?,?,?,?,?)`,
		seq, at.Format(time.RFC3339Nano), head, sig, pub)
	return err
}

// headMsg is the canonical byte string a head signature covers: the chain root AT a sequence point.
func headMsg(seq int64, head string) []byte {
	return []byte(fmt.Sprintf(`{"seq":%d,"head":%q}`, seq, head))
}

// StartSigning anchors the head every interval until ctx is done (hourly in production; the DEMO
// uses a short interval so the console shows fresh anchors).
func (l *Log) StartSigning(ctx context.Context, every time.Duration) {
	go func() {
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				_ = l.SignHead(ctx)
			}
		}
	}()
}

// Integrity is a Verify verdict.
type Integrity struct {
	OK          bool   `json:"ok"`
	Records     int64  `json:"records"`
	SignedHeads int    `json:"signedHeads"`
	BrokenAt    int64  `json:"brokenAt,omitempty"`
	Why         string `json:"why,omitempty"`
}

// Verify replays the ENTIRE chain (sequence continuity, prev-hash linkage, per-record hash) and
// re-verifies every signed head against its recorded public key — the §6.17.12 tamper-detection
// promise: any UPDATE, re-order, or delete of a historical record breaks it.
func (l *Log) Verify(ctx context.Context) (Integrity, error) {
	rows, err := l.query(ctx, `SELECT seq, at, type, payload, prev_hash, hash FROM audit_events ORDER BY seq`)
	if err != nil {
		return Integrity{}, err
	}
	defer rows.Close()
	prev := genesisHash
	var n int64
	hashAtSeq := map[int64]string{}
	for rows.Next() {
		var seq int64
		var at, typ, payload, prevHash, hash string
		if err := rows.Scan(&seq, &at, &typ, &payload, &prevHash, &hash); err != nil {
			return Integrity{}, err
		}
		n++
		if seq != n {
			return Integrity{Records: n, BrokenAt: seq, Why: "sequence gap (record deleted?)"}, nil
		}
		if prevHash != prev {
			return Integrity{Records: n, BrokenAt: seq, Why: "prev-hash break (chain re-ordered?)"}, nil
		}
		if hashRecord(seq, at, typ, []byte(payload), prevHash) != hash {
			return Integrity{Records: n, BrokenAt: seq, Why: "record hash mismatch (content tampered)"}, nil
		}
		prev = hash
		hashAtSeq[seq] = hash
	}
	if err := rows.Err(); err != nil {
		return Integrity{}, err
	}

	heads, err := l.query(ctx, `SELECT seq, head, sig, pub FROM audit_heads ORDER BY seq`)
	if err != nil {
		return Integrity{}, err
	}
	defer heads.Close()
	signed := 0
	for heads.Next() {
		var seq int64
		var head string
		var sig, pub []byte
		if err := heads.Scan(&seq, &head, &sig, &pub); err != nil {
			return Integrity{}, err
		}
		if hashAtSeq[seq] != head {
			return Integrity{Records: n, SignedHeads: signed, BrokenAt: seq, Why: "signed head does not match chain (history rewritten)"}, nil
		}
		pubAny, err := x509.ParsePKIXPublicKey(pub)
		if err != nil {
			return Integrity{Records: n, SignedHeads: signed, BrokenAt: seq, Why: "unparseable head signature key"}, nil
		}
		edPub, ok := pubAny.(ed25519.PublicKey)
		if !ok || !ed25519.Verify(edPub, headMsg(seq, head), sig) {
			return Integrity{Records: n, SignedHeads: signed, BrokenAt: seq, Why: "head signature invalid"}, nil
		}
		signed++
	}
	if err := heads.Err(); err != nil {
		return Integrity{}, err
	}
	return Integrity{OK: true, Records: n, SignedHeads: signed}, nil
}

// Recent returns the newest limit events, oldest-first.
func (l *Log) Recent(ctx context.Context, limit int) ([]Event, error) {
	return l.RecentFiltered(ctx, limit, "")
}

// RecentFiltered is Recent with an optional type-prefix filter (e.g. "deployment." matches every
// deployment lifecycle event) — the console's audit browser drills down with it.
func (l *Log) RecentFiltered(ctx context.Context, limit int, typePrefix string) ([]Event, error) {
	if limit <= 0 {
		limit = 12
	}
	q := `SELECT seq, at, type, payload, prev_hash, hash FROM audit_events ORDER BY seq DESC LIMIT ?`
	args := []any{limit}
	if typePrefix != "" {
		q = `SELECT seq, at, type, payload, prev_hash, hash FROM audit_events WHERE type LIKE ? ESCAPE '\' ORDER BY seq DESC LIMIT ?`
		args = []any{likePrefix(typePrefix), limit}
	}
	rows, err := l.query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Event
	for rows.Next() {
		var e Event
		var at, payload string
		if err := rows.Scan(&e.Seq, &at, &e.Type, &payload, &e.PrevHash, &e.Hash); err != nil {
			return nil, err
		}
		e.At, _ = time.Parse(time.RFC3339Nano, at)
		e.Payload = json.RawMessage(payload)
		out = append(out, e)
	}
	// reverse to oldest-first
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out, rows.Err()
}

// Stats returns the chain's current shape (records, head, signed anchors).
func (l *Log) Stats(ctx context.Context) (records int64, head string, signedHeads int, err error) {
	l.mu.Lock()
	records, head = l.seq, l.head
	l.mu.Unlock()
	err = l.queryRow(ctx, `SELECT COUNT(*) FROM audit_heads`).Scan(&signedHeads)
	return records, head, signedHeads, err
}

// likePrefix escapes LIKE wildcards in a user-supplied prefix and anchors it (the query pairs it
// with ESCAPE '\', which SQLite and Postgres both honor — event types like "model.gate_failed"
// keep their underscores literal).
func likePrefix(p string) string {
	r := strings.NewReplacer(`\`, `\\`, "%", `\%`, "_", `\_`)
	return r.Replace(p) + "%"
}

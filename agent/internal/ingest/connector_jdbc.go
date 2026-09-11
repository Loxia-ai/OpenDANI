package ingest

// JDBCConnector — RAG/training over a RELATIONAL DATABASE: an operator points DANI at a SQL database
// with a connection string + a SELECT, and each returned ROW becomes a document. Reuses the shared
// dbx backend seam (pure-Go pgx for PostgreSQL, modernc for SQLite — no CGO, single-static-binary
// unchanged). The FIRST selected column is the stable document id; every column is rendered into the
// document text as "column: value" lines, which the extract layer passes through as plain text.
//
// Incremental by content hash: SQL has no delta feed, so each sync runs the query, hashes each row's
// rendered text, and emits only rows whose hash is new or changed; a row whose id vanished from the
// result set is reported gone. (A WHERE watermark > cursor incremental — for append-heavy tables — is
// a documented future refinement; the honest slice-1 is a full scan + diff, correct for any schema.)
//
// Classification: the DefaultClass is the floor for the whole result set (the container), with the
// optional id-prefix classmap dialect on top — same as every other connector. The query is the
// operator's own trusted SQL; point it at a READ-ONLY account.

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"dani.local/agent/internal/dbx"
)

// JDBCConnector runs one SELECT and turns its rows into documents.
type JDBCConnector struct {
	DSN          string // full connection string — resolved by the caller, never logged
	Query        string // SELECT; the first column is the doc id, all columns become the text
	ClassMap     map[string]string
	DefaultClass string
	MaxRows      int     // safety cap on rows per sync (default 50000)
	MaxBytes     int     // per-document text cap (default 4 MiB)
	DB           *sql.DB // test seam; when nil, opened from DSN via dbx (and closed after each sync)
}

func (c *JDBCConnector) Name() string { return "jdbc" }

// open returns a usable DB handle and a cleanup func. With an injected DB (tests) cleanup is a no-op.
func (c *JDBCConnector) open(ctx context.Context) (*sql.DB, func(), error) {
	if c.DB != nil {
		return c.DB, func() {}, nil
	}
	db, _, err := dbx.Open(ctx, c.DSN)
	if err != nil {
		return nil, nil, fmt.Errorf("jdbc: connect: %w", err)
	}
	return db, func() { _ = db.Close() }, nil
}

// Sync runs the query and diffs the rows against the cursor (id -> content hash).
func (c *JDBCConnector) Sync(ctx context.Context, state map[string]string) ([]ConnectorDoc, []string, map[string]string, error) {
	maxRows := c.MaxRows
	if maxRows <= 0 {
		maxRows = 50000
	}
	maxBytes := c.MaxBytes
	if maxBytes <= 0 {
		maxBytes = 4 << 20
	}
	db, cleanup, err := c.open(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	defer cleanup()

	rows, err := db.QueryContext(ctx, c.Query)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("jdbc: query: %w", err)
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("jdbc: columns: %w", err)
	}
	if len(cols) == 0 {
		return nil, nil, nil, fmt.Errorf("jdbc: query returned no columns")
	}

	next := make(map[string]string, len(state))
	for k, v := range state {
		next[k] = v
	}
	seen := make(map[string]bool)
	var changed []ConnectorDoc

	cells := make([]any, len(cols))
	ptrs := make([]any, len(cols))
	for i := range cells {
		ptrs[i] = &cells[i]
	}
	n := 0
	for rows.Next() {
		if n >= maxRows {
			return nil, nil, nil, fmt.Errorf("jdbc: query returned more than %d rows — narrow it with a WHERE/LIMIT", maxRows)
		}
		n++
		if err := rows.Scan(ptrs...); err != nil {
			return nil, nil, nil, fmt.Errorf("jdbc: scan: %w", err)
		}
		docID := cellString(cells[0])
		if docID == "" {
			continue // a row with no id can't be addressed/updated/deleted — skip it
		}
		var b strings.Builder
		for i, name := range cols {
			b.WriteString(name)
			b.WriteString(": ")
			b.WriteString(cellString(cells[i]))
			b.WriteByte('\n')
			if b.Len() > maxBytes {
				break
			}
		}
		text := b.String()
		if len(text) > maxBytes {
			text = text[:maxBytes]
		}
		sum := sha256.Sum256([]byte(text))
		hash := hex.EncodeToString(sum[:])
		key := "id:" + docID
		seen[key] = true
		if next[key] == hash {
			continue // unchanged since last sync
		}
		changed = append(changed, ConnectorDoc{
			ID: docID, Text: text, Format: "text",
			SrcClass: classForPrefix(docID, c.ClassMap, c.DefaultClass),
		})
		next[key] = hash
	}
	if err := rows.Err(); err != nil {
		return nil, nil, nil, fmt.Errorf("jdbc: rows: %w", err)
	}

	// deletions: an id we tracked that no longer appears in the result set
	var gone []string
	for key := range state {
		if !strings.HasPrefix(key, "id:") || seen[key] {
			continue
		}
		gone = append(gone, strings.TrimPrefix(key, "id:"))
		delete(next, key)
	}

	sort.Slice(changed, func(i, j int) bool { return changed[i].ID < changed[j].ID })
	sort.Strings(gone)
	return changed, gone, next, nil
}

// cellString renders a scanned driver value (int64/float64/bool/[]byte/string/time/nil) as text.
func cellString(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case []byte:
		return string(t)
	case string:
		return t
	default:
		return fmt.Sprintf("%v", t)
	}
}

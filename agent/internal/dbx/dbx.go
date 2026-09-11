// Package dbx is the database-backend seam: it opens either SQLite (pure-Go modernc, the DEMO
// default / dev / single-controller) or PostgreSQL (pure-Go pgx stdlib, production / HA) from a DSN,
// and translates portable `?`-placeholder SQL to each engine's dialect. Both drivers are CGO-free, so
// the single-static-binary build is unchanged (RR-R11-03).
//
// The Node Registry and Audit Log write portable SQL with `?` placeholders and pick their schema by
// Dialect; everything else — content-addressing, hash chains, Raft replication — is unaffected.
package dbx

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	_ "github.com/jackc/pgx/v5/stdlib" // pure-Go PostgreSQL driver
	_ "modernc.org/sqlite"             // pure-Go SQLite driver
)

// Dialect identifies the SQL engine so callers pick the right schema + placeholder style.
type Dialect string

const (
	SQLite   Dialect = "sqlite"
	Postgres Dialect = "postgres"
)

// Open dispatches on the DSN:
//
//	""  |  ":memory:"  |  sqlite:<path>  |  <bare path>   -> SQLite (modernc)
//	postgres://user:pass@host:port/db?...                 -> PostgreSQL (pgx)
//	postgresql://...                                       -> PostgreSQL (pgx)
//
// It returns the *sql.DB, the Dialect, and verifies connectivity with a Ping (so a bad Postgres DSN
// fails at Open, not on first query).
func Open(ctx context.Context, dsn string) (*sql.DB, Dialect, error) {
	driver, conn, dialect := resolve(dsn)
	db, err := sql.Open(driver, conn)
	if err != nil {
		return nil, dialect, err
	}
	if dialect == SQLite {
		// One connection serializes every writer through Go's pool instead of SQLite's file lock.
		// Without this, two in-process writers (e.g. the audit Emit and the SignHead ticker) can race
		// to SQLITE_BUSY — and a fire-and-forget caller would then LOSE its write silently. Found
		// live: a model.signed audit event dropped under sign+anchor contention (D-31).
		db.SetMaxOpenConns(1)
		if _, err := db.ExecContext(ctx, `PRAGMA busy_timeout=5000`); err != nil {
			_ = db.Close()
			return nil, dialect, fmt.Errorf("dbx: sqlite busy_timeout: %w", err)
		}
	}
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, dialect, fmt.Errorf("dbx: connect %s: %w", dialect, err)
	}
	return db, dialect, nil
}

// resolve maps a DSN to (driverName, connString, dialect).
func resolve(dsn string) (driver, conn string, d Dialect) {
	switch {
	case strings.HasPrefix(dsn, "postgres://"), strings.HasPrefix(dsn, "postgresql://"):
		return "pgx", dsn, Postgres
	case strings.HasPrefix(dsn, "sqlite:"):
		return "sqlite", strings.TrimPrefix(dsn, "sqlite:"), SQLite
	default:
		// bare path or ":memory:" — SQLite
		if dsn == "" {
			dsn = ":memory:"
		}
		return "sqlite", dsn, SQLite
	}
}

// Rebind rewrites a `?`-placeholder query for the dialect. SQLite keeps `?`; Postgres gets positional
// `$1,$2,...`. Our queries carry no `?` inside string literals, so a sequential scan is correct (the
// same approach sqlx.Rebind uses).
func (d Dialect) Rebind(query string) string {
	if d != Postgres {
		return query
	}
	var b strings.Builder
	b.Grow(len(query) + 8)
	n := 0
	for i := 0; i < len(query); i++ {
		if query[i] == '?' {
			n++
			b.WriteByte('$')
			b.WriteString(itoa(n))
		} else {
			b.WriteByte(query[i])
		}
	}
	return b.String()
}

// itoa is a tiny int->string without importing strconv for one call site.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [12]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

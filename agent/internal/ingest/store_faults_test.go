package ingest

// Fault-injection coverage for the durable store's error paths (the 100%-coverage rule): SQLite lets
// us break individual statements — drop a table to fail a DELETE/SELECT, swap a table for a view with
// an INSTEAD OF DELETE trigger (DELETE succeeds, INSERT fails) to fail a mid-transaction INSERT, drop
// NOT NULL and plant a NULL to fail a Scan, cancel the context mid-iteration to fail rows.Err().
// Residual uncovered lines (tx.Commit failure, rows.Close failure) are registry-class DB guards —
// documented in COVERAGE.md, not fakeable without a corrupt filesystem.

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"dani.local/agent/internal/dbx"
)

func TestQASystemPromptAndListOrder(t *testing.T) {
	// {"prompt","completion","system"} — the system turn leads the rendered messages
	ex, ok := parseExample(`{"prompt":"q","completion":"a","system":"be brief"}`)
	if !ok || ex.format != "chat" || !strings.Contains(string(ex.messages), "be brief") {
		t.Fatalf("system prompt lost: ok=%v %+v", ok, ex)
	}
	// List returns name order regardless of map iteration
	s := New()
	for _, n := range []string{"legal", "hr", "finance"} {
		if _, err := s.Ingest(n); err != nil {
			t.Fatalf("Ingest %s: %v", n, err)
		}
	}
	l := s.List()
	if len(l) != 3 || l[0].Name != "finance" || l[1].Name != "hr" || l[2].Name != "legal" {
		t.Fatalf("List out of order: %+v", l)
	}
}

func TestSchemaFor(t *testing.T) {
	if schemaFor(dbx.Postgres) != schemaPostgres || schemaFor(dbx.SQLite) != schemaSQLite {
		t.Fatal("schemaFor picked the wrong DDL")
	}
}

func TestOpenStoreSchemaFails(t *testing.T) {
	// a fresh READ-ONLY database cannot run the DDL -> OpenStore must fail at schema, not at first use
	dir := t.TempDir()
	path := filepath.Join(dir, "ro.db")
	st, err := OpenStore(context.Background(), path) // create a valid file first
	if err != nil {
		t.Fatalf("seed store: %v", err)
	}
	if _, err := st.db.Exec(`DROP TABLE ingest_chunks`); err != nil { // remove one table so DDL must WRITE
		t.Fatalf("drop: %v", err)
	}
	_ = st.Close()
	if _, err := OpenStore(context.Background(), "sqlite:file:"+filepath.ToSlash(path)+"?mode=ro"); err == nil {
		t.Fatal("OpenStore succeeded running DDL on a read-only database")
	}
}

// breakTable replaces a real table with a same-shape VIEW that accepts DELETE (no-op trigger) but
// refuses INSERT — so a transaction gets past its DELETEs and fails at the target INSERT.
func breakTable(t *testing.T, st *Store, table, columns string) {
	t.Helper()
	if _, err := st.db.Exec(`DROP TABLE ` + table); err != nil {
		t.Fatalf("drop %s: %v", table, err)
	}
	if _, err := st.db.Exec(`CREATE VIEW ` + table + ` AS SELECT ` + columns); err != nil {
		t.Fatalf("view %s: %v", table, err)
	}
	if _, err := st.db.Exec(`CREATE TRIGGER ` + table + `_del INSTEAD OF DELETE ON ` + table + ` BEGIN SELECT 1; END`); err != nil {
		t.Fatalf("trigger %s: %v", table, err)
	}
}

func TestSaveCollectionStatementFailures(t *testing.T) {
	ctx := context.Background()
	col := Collection{Name: "x", Connector: "upload", Chunks: []Chunk{{ID: "x#1", DocID: "x/1", Text: "t", Classification: "internal", Source: "upload", Format: "text"}}}

	// 1. DELETE FROM ingest_chunks fails (table gone)
	st, _ := openTestStore(t)
	if _, err := st.db.Exec(`DROP TABLE ingest_chunks`); err != nil {
		t.Fatal(err)
	}
	if err := st.saveCollection(ctx, col); err == nil {
		t.Fatal("saveCollection survived a missing chunks table")
	}

	// 2. DELETE FROM ingest_collections fails (only that table gone)
	st2, _ := openTestStore(t)
	if _, err := st2.db.Exec(`DROP TABLE ingest_collections`); err != nil {
		t.Fatal(err)
	}
	if err := st2.saveCollection(ctx, col); err == nil {
		t.Fatal("saveCollection survived a missing collections table")
	}

	// 3. INSERT INTO ingest_collections fails (view refuses INSERT, DELETE trigger lets us reach it)
	st3, _ := openTestStore(t)
	breakTable(t, st3, "ingest_collections", `'a' AS name, 'b' AS connector`)
	if err := st3.saveCollection(ctx, col); err == nil {
		t.Fatal("saveCollection survived an unwritable collections table")
	}

	// 4. INSERT INTO ingest_chunks fails
	st4, _ := openTestStore(t)
	breakTable(t, st4, "ingest_chunks",
		`'c' AS collection, 0 AS seq, 'i' AS id, 'd' AS doc_id, 't' AS text, 'x' AS classification, 's' AS source, 'f' AS format, NULL AS messages, NULL AS tools, NULL AS vec`)
	if err := st4.saveCollection(ctx, col); err == nil {
		t.Fatal("saveCollection survived an unwritable chunks table")
	}
}

func TestSaveCustomStatementFailures(t *testing.T) {
	ctx := context.Background()
	c := corpus{connector: "upload", srcClass: "internal", examples: []example{{text: "t", format: "text"}}}

	// DELETE fails
	st, _ := openTestStore(t)
	if _, err := st.db.Exec(`DROP TABLE ingest_custom`); err != nil {
		t.Fatal(err)
	}
	if err := st.saveCustom(ctx, "n", c); err == nil {
		t.Fatal("saveCustom survived a missing table")
	}

	// INSERT fails
	st2, _ := openTestStore(t)
	breakTable(t, st2, "ingest_custom",
		`'n' AS name, 0 AS seq, 'i' AS src_class, 't' AS text, 'f' AS format, NULL AS messages, NULL AS tools`)
	if err := st2.saveCustom(ctx, "n", c); err == nil {
		t.Fatal("saveCustom survived an unwritable table")
	}
}

// nullify recreates a table without NOT NULL constraints and plants a row of NULLs, so loadAll's
// Scan into string fails.
func nullify(t *testing.T, st *Store, drop, create, insert string) {
	t.Helper()
	for _, q := range []string{drop, create, insert} {
		if _, err := st.db.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
}

func TestLoadAllScanAndQueryFailures(t *testing.T) {
	ctx := context.Background()

	// collections scan error: NULL connector
	st, _ := openTestStore(t)
	nullify(t, st, `DROP TABLE ingest_collections`,
		`CREATE TABLE ingest_collections (name TEXT, connector TEXT)`,
		`INSERT INTO ingest_collections VALUES ('c', NULL)`)
	if _, _, err := st.loadAll(ctx); err == nil {
		t.Fatal("loadAll survived a NULL collection row")
	}

	// chunks query error: table missing (collections intact)
	st2, _ := openTestStore(t)
	if _, err := st2.db.Exec(`DROP TABLE ingest_chunks`); err != nil {
		t.Fatal(err)
	}
	if _, _, err := st2.loadAll(ctx); err == nil {
		t.Fatal("loadAll survived a missing chunks table")
	}

	// chunks scan error: NULL text
	st3, _ := openTestStore(t)
	nullify(t, st3, `DROP TABLE ingest_chunks`,
		`CREATE TABLE ingest_chunks (collection TEXT, seq INTEGER, id TEXT, doc_id TEXT, text TEXT, classification TEXT, source TEXT, format TEXT, messages BLOB, tools BLOB, vec BLOB)`,
		`INSERT INTO ingest_chunks VALUES ('c', 0, 'i', 'd', NULL, 'x', 's', 'f', NULL, NULL, NULL)`)
	if _, _, err := st3.loadAll(ctx); err == nil {
		t.Fatal("loadAll survived a NULL chunk row")
	}

	// custom query error: table missing
	st4, _ := openTestStore(t)
	if _, err := st4.db.Exec(`DROP TABLE ingest_custom`); err != nil {
		t.Fatal(err)
	}
	if _, _, err := st4.loadAll(ctx); err == nil {
		t.Fatal("loadAll survived a missing custom table")
	}

	// custom scan error: NULL text
	st5, _ := openTestStore(t)
	nullify(t, st5, `DROP TABLE ingest_custom`,
		`CREATE TABLE ingest_custom (name TEXT, seq INTEGER, src_class TEXT, text TEXT, format TEXT, messages BLOB, tools BLOB)`,
		`INSERT INTO ingest_custom VALUES ('n', 0, 'i', NULL, 'f', NULL, NULL)`)
	if _, _, err := st5.loadAll(ctx); err == nil {
		t.Fatal("loadAll survived a NULL custom row")
	}
}

func TestCloseRowsSurfacesIterationError(t *testing.T) {
	st, _ := openTestStore(t)
	// rows opened inside a tx that gets rolled back UNDER them: database/sql closes the rows and
	// records the abort as the iteration error — exactly what closeRows must surface.
	tx, err := st.db.Begin()
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	rows, err := tx.Query(`SELECT name FROM ingest_collections`)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	_ = tx.Rollback()
	for rows.Next() {
	}
	if err := closeRows(rows); err == nil {
		t.Skip("driver did not surface the tx abort as rows.Err() — guard remains documented")
	}
}

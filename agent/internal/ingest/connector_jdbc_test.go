package ingest

// JDBCConnector against a real temp SQLite DB (through the shared dbx seam): rows become documents,
// the first column is the id, the id-prefix classmap sets floors, and an incremental sync sees an
// UPDATE as changed, a DELETE as gone, and an unchanged row as neither.

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"dani.local/agent/internal/dbx"
)

func seedJDBC(t *testing.T, dsn, stmt string) {
	t.Helper()
	db, _, err := dbx.Open(context.Background(), dsn)
	if err != nil {
		t.Fatalf("seed open: %v", err)
	}
	defer db.Close()
	if _, err := db.ExecContext(context.Background(), stmt); err != nil {
		t.Fatalf("seed exec: %v", err)
	}
}

func TestJDBCConnectorSync(t *testing.T) {
	dsn := "sqlite:" + filepath.Join(t.TempDir(), "kb.db")
	seedJDBC(t, dsn, `CREATE TABLE docs (id TEXT PRIMARY KEY, title TEXT, body TEXT, dept TEXT);
		INSERT INTO docs VALUES ('KB-1','Onboarding','welcome aboard','People');
		INSERT INTO docs VALUES ('HR-9','Salary bands','confidential comp','People');
		INSERT INTO docs VALUES ('KB-2','VPN setup','howto connect','IT');`)

	c := &JDBCConnector{
		DSN:      dsn,
		Query:    "SELECT id, title, body, dept FROM docs ORDER BY id",
		ClassMap: map[string]string{"HR-": "restricted"}, DefaultClass: "internal",
	}

	// initial crawl: 3 rows → 3 docs
	changed, gone, cursor, err := c.Sync(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(changed) != 3 || len(gone) != 0 {
		t.Fatalf("initial: %d changed %d gone: %v", len(changed), len(gone), ids(changed))
	}
	byID := map[string]ConnectorDoc{}
	for _, d := range changed {
		byID[d.ID] = d
	}
	if d := byID["HR-9"]; d.SrcClass != "restricted" || !strings.Contains(d.Text, "title: Salary bands") || !strings.Contains(d.Text, "body: confidential comp") {
		t.Fatalf("HR row floor/text wrong: %+v", d)
	}
	if d := byID["KB-1"]; d.SrcClass != "internal" || d.Format != "text" {
		t.Fatalf("default floor/format wrong: %+v", d)
	}

	// incremental: UPDATE KB-1 (changed), DELETE KB-2 (gone), HR-9 untouched (neither)
	seedJDBC(t, dsn, `UPDATE docs SET body='welcome, revised' WHERE id='KB-1';
		DELETE FROM docs WHERE id='KB-2';`)
	changed, gone, cursor, err = c.Sync(context.Background(), cursor)
	if err != nil {
		t.Fatal(err)
	}
	if len(changed) != 1 || changed[0].ID != "KB-1" || !strings.Contains(changed[0].Text, "welcome, revised") {
		t.Fatalf("incremental changed: %v", ids(changed))
	}
	if len(gone) != 1 || gone[0] != "KB-2" {
		t.Fatalf("incremental gone: %v", gone)
	}
	if _, still := map[string]string(cursor)["id:KB-2"]; still {
		t.Fatal("deleted row must be dropped from the cursor")
	}
}

func TestJDBCDefValidation(t *testing.T) {
	if err := (ConnectorDef{Kind: "jdbc", Collection: "kb"}).Validate(); err == nil {
		t.Fatal("jdbc def without dsn/query must fail")
	}
	if err := (ConnectorDef{Kind: "jdbc", Collection: "kb", Secret: "sqlite::memory:"}).Validate(); err == nil {
		t.Fatal("jdbc def without a query must fail")
	}
	if err := (ConnectorDef{Kind: "jdbc", Collection: "kb", Secret: "sqlite::memory:", Query: "SELECT 1"}).Validate(); err != nil {
		t.Fatalf("valid jdbc def rejected: %v", err)
	}
}

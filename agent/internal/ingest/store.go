package ingest

// Durable ingest (PRODUCTION-READINESS P1-1): ingested collections — chunks, structured
// messages/tools, AND their embeddings — plus operator-uploaded corpora persist through the dbx seam
// (SQLite standalone / PostgreSQL HA), so customer data survives a controller restart and, on
// Postgres, an HA failover. Before this, ingest was in-memory only: every dataset and RAG index
// vanished on restart (the readiness audit's top P1 gap).
//
// Same layering as the Node Registry and Audit Log: portable `?`-placeholder SQL, schema picked by
// dialect, write-through on mutation, full rehydration at Open. Embeddings are stored as little-endian
// float32 blobs so a restart does NOT need the embedder (the index comes back byte-identical — a
// re-embed against a different/upgraded embedder would silently change retrieval).

import (
	"context"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"

	"dani.local/agent/internal/dbx"
)

// Store persists collections + uploaded corpora behind the Subsystem.
type Store struct {
	db      *sql.DB
	dialect dbx.Dialect
}

// schemaSQLite / schemaPostgres: same shape, engine-native types (BLOB vs BYTEA).
const schemaSQLite = `
CREATE TABLE IF NOT EXISTS ingest_collections (
  name      TEXT PRIMARY KEY,
  connector TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ingest_chunks (
  collection     TEXT    NOT NULL,
  seq            INTEGER NOT NULL,
  id             TEXT    NOT NULL,
  doc_id         TEXT    NOT NULL,
  section        TEXT    NOT NULL DEFAULT '',
  text           TEXT    NOT NULL,
  classification TEXT    NOT NULL,
  source         TEXT    NOT NULL,
  format         TEXT    NOT NULL,
  messages       BLOB,
  tools          BLOB,
  vec            BLOB,
  PRIMARY KEY (collection, seq)
);
CREATE TABLE IF NOT EXISTS ingest_custom (
  name      TEXT    NOT NULL,
  seq       INTEGER NOT NULL,
  src_class TEXT    NOT NULL,
  text      TEXT    NOT NULL,
  format    TEXT    NOT NULL,
  messages  BLOB,
  tools     BLOB,
  PRIMARY KEY (name, seq)
);
CREATE TABLE IF NOT EXISTS ingest_connector_docs (
  collection TEXT NOT NULL,
  id         TEXT NOT NULL,
  text       TEXT NOT NULL,
  src_class  TEXT NOT NULL,
  format     TEXT NOT NULL DEFAULT 'text',
  PRIMARY KEY (collection, id)
);
CREATE TABLE IF NOT EXISTS ingest_connector_state (
  collection TEXT PRIMARY KEY,
  cursor     BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS ingest_connector_defs (
  collection TEXT PRIMARY KEY,
  def        BLOB NOT NULL
);`

const schemaPostgres = `
CREATE TABLE IF NOT EXISTS ingest_collections (
  name      TEXT PRIMARY KEY,
  connector TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ingest_chunks (
  collection     TEXT   NOT NULL,
  seq            BIGINT NOT NULL,
  id             TEXT   NOT NULL,
  doc_id         TEXT   NOT NULL,
  section        TEXT   NOT NULL DEFAULT '',
  text           TEXT   NOT NULL,
  classification TEXT   NOT NULL,
  source         TEXT   NOT NULL,
  format         TEXT   NOT NULL,
  messages       BYTEA,
  tools          BYTEA,
  vec            BYTEA,
  PRIMARY KEY (collection, seq)
);
CREATE TABLE IF NOT EXISTS ingest_custom (
  name      TEXT   NOT NULL,
  seq       BIGINT NOT NULL,
  src_class TEXT   NOT NULL,
  text      TEXT   NOT NULL,
  format    TEXT   NOT NULL,
  messages  BYTEA,
  tools     BYTEA,
  PRIMARY KEY (name, seq)
);
CREATE TABLE IF NOT EXISTS ingest_connector_docs (
  collection TEXT NOT NULL,
  id         TEXT NOT NULL,
  text       TEXT NOT NULL,
  src_class  TEXT NOT NULL,
  format     TEXT NOT NULL DEFAULT 'text',
  PRIMARY KEY (collection, id)
);
CREATE TABLE IF NOT EXISTS ingest_connector_state (
  collection TEXT PRIMARY KEY,
  cursor     BYTEA NOT NULL
);
CREATE TABLE IF NOT EXISTS ingest_connector_defs (
  collection TEXT PRIMARY KEY,
  def        BYTEA NOT NULL
);`

// schemaFor picks the engine-native DDL for a dialect.
func schemaFor(d dbx.Dialect) string {
	if d == dbx.Postgres {
		return schemaPostgres
	}
	return schemaSQLite
}

// OpenStore opens (and migrates) the durable ingest store at dsn — a SQLite path or postgres:// URL.
func OpenStore(ctx context.Context, dsn string) (*Store, error) {
	db, dialect, err := dbx.Open(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("ingest store: %w", err)
	}
	if _, err := db.ExecContext(ctx, schemaFor(dialect)); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ingest store: schema: %w", err)
	}
	// migration: pre-existing DBs lack the format column (added with the extract layer) — the ALTER
	// fails harmlessly where it already exists.
	_, _ = db.ExecContext(ctx, `ALTER TABLE ingest_connector_docs ADD COLUMN format TEXT NOT NULL DEFAULT 'text'`)
	// migration: pre-existing DBs lack the section column (added with structure-aware chunking).
	_, _ = db.ExecContext(ctx, `ALTER TABLE ingest_chunks ADD COLUMN section TEXT NOT NULL DEFAULT ''`)
	return &Store{db: db, dialect: dialect}, nil
}

// Close releases the underlying DB.
func (st *Store) Close() error { return st.db.Close() }

// saveCollection transactionally replaces one collection's rows (an ingest run is a full re-crawl,
// so replace-all is the correct semantic — no partial merge states).
func (st *Store) saveCollection(ctx context.Context, col Collection) error {
	tx, err := st.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("ingest store: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	r := st.dialect.Rebind
	if _, err := tx.ExecContext(ctx, r(`DELETE FROM ingest_chunks WHERE collection = ?`), col.Name); err != nil {
		return fmt.Errorf("ingest store: clear chunks: %w", err)
	}
	if _, err := tx.ExecContext(ctx, r(`DELETE FROM ingest_collections WHERE name = ?`), col.Name); err != nil {
		return fmt.Errorf("ingest store: clear collection: %w", err)
	}
	if _, err := tx.ExecContext(ctx, r(`INSERT INTO ingest_collections (name, connector) VALUES (?, ?)`),
		col.Name, col.Connector); err != nil {
		return fmt.Errorf("ingest store: insert collection: %w", err)
	}
	ins := r(`INSERT INTO ingest_chunks
		(collection, seq, id, doc_id, section, text, classification, source, format, messages, tools, vec)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	for i, ch := range col.Chunks {
		if _, err := tx.ExecContext(ctx, ins, col.Name, i, ch.ID, ch.DocID, ch.Section, ch.Text,
			ch.Classification, ch.Source, ch.Format, []byte(ch.Messages), []byte(ch.Tools),
			encodeVec(ch.Vec)); err != nil {
			return fmt.Errorf("ingest store: insert chunk %s: %w", ch.ID, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("ingest store: commit: %w", err)
	}
	return nil
}

// saveCustom transactionally replaces one uploaded corpus (same replace-all semantic as upload).
func (st *Store) saveCustom(ctx context.Context, name string, c corpus) error {
	tx, err := st.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("ingest store: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	r := st.dialect.Rebind
	if _, err := tx.ExecContext(ctx, r(`DELETE FROM ingest_custom WHERE name = ?`), name); err != nil {
		return fmt.Errorf("ingest store: clear custom: %w", err)
	}
	ins := r(`INSERT INTO ingest_custom (name, seq, src_class, text, format, messages, tools)
		VALUES (?, ?, ?, ?, ?, ?, ?)`)
	for i, ex := range c.examples {
		if _, err := tx.ExecContext(ctx, ins, name, i, c.srcClass, ex.text, ex.format,
			[]byte(ex.messages), []byte(ex.tools)); err != nil {
			return fmt.Errorf("ingest store: insert example %d: %w", i, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("ingest store: commit: %w", err)
	}
	return nil
}

// saveConnectorSync transactionally replaces one connector collection's doc set + cursor (a sync is
// the full new truth for the source — replace-all keeps no phantom docs).
func (st *Store) saveConnectorSync(ctx context.Context, collection string, docs map[string]ConnectorDoc, cursor map[string]string) error {
	cur, err := json.Marshal(cursor)
	if err != nil {
		return fmt.Errorf("ingest store: cursor: %w", err)
	}
	tx, err := st.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("ingest store: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	r := st.dialect.Rebind
	if _, err := tx.ExecContext(ctx, r(`DELETE FROM ingest_connector_docs WHERE collection = ?`), collection); err != nil {
		return fmt.Errorf("ingest store: clear connector docs: %w", err)
	}
	ins := r(`INSERT INTO ingest_connector_docs (collection, id, text, src_class, format) VALUES (?, ?, ?, ?, ?)`)
	for _, d := range docs {
		format := d.Format
		if format == "" {
			format = "text"
		}
		if _, err := tx.ExecContext(ctx, ins, collection, d.ID, d.Text, d.SrcClass, format); err != nil {
			return fmt.Errorf("ingest store: insert connector doc %s: %w", d.ID, err)
		}
	}
	if _, err := tx.ExecContext(ctx, r(`DELETE FROM ingest_connector_state WHERE collection = ?`), collection); err != nil {
		return fmt.Errorf("ingest store: clear cursor: %w", err)
	}
	if _, err := tx.ExecContext(ctx, r(`INSERT INTO ingest_connector_state (collection, cursor) VALUES (?, ?)`), collection, cur); err != nil {
		return fmt.Errorf("ingest store: insert cursor: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("ingest store: commit: %w", err)
	}
	return nil
}

// loadConnectors rehydrates connector doc sets + cursors (boot path).
func (st *Store) loadConnectors(ctx context.Context) (map[string]*connectorEntry, error) {
	r := st.dialect.Rebind
	out := map[string]*connectorEntry{}
	entry := func(col string) *connectorEntry {
		e, ok := out[col]
		if !ok {
			e = &connectorEntry{docs: map[string]ConnectorDoc{}, cursor: map[string]string{}}
			out[col] = e
		}
		return e
	}
	rows, err := st.db.QueryContext(ctx, r(`SELECT collection, id, text, src_class, format FROM ingest_connector_docs`))
	if err != nil {
		return nil, fmt.Errorf("ingest store: load connector docs: %w", err)
	}
	for rows.Next() {
		var col string
		var d ConnectorDoc
		if err := rows.Scan(&col, &d.ID, &d.Text, &d.SrcClass, &d.Format); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("ingest store: scan connector doc: %w", err)
		}
		entry(col).docs[d.ID] = d
	}
	if err := closeRows(rows); err != nil {
		return nil, err
	}
	curRows, err := st.db.QueryContext(ctx, r(`SELECT collection, cursor FROM ingest_connector_state`))
	if err != nil {
		return nil, fmt.Errorf("ingest store: load cursors: %w", err)
	}
	for curRows.Next() {
		var col string
		var raw []byte
		if err := curRows.Scan(&col, &raw); err != nil {
			_ = curRows.Close()
			return nil, fmt.Errorf("ingest store: scan cursor: %w", err)
		}
		cursor := map[string]string{}
		if err := json.Unmarshal(raw, &cursor); err != nil {
			_ = curRows.Close()
			return nil, fmt.Errorf("ingest store: cursor decode: %w", err)
		}
		entry(col).cursor = cursor
	}
	if err := closeRows(curRows); err != nil {
		return nil, err
	}
	return out, nil
}

// loadAll rehydrates every persisted collection and uploaded corpus (boot path).
func (st *Store) loadAll(ctx context.Context) (map[string]Collection, map[string]corpus, error) {
	r := st.dialect.Rebind
	cols := map[string]Collection{}
	rows, err := st.db.QueryContext(ctx, r(`SELECT name, connector FROM ingest_collections`))
	if err != nil {
		return nil, nil, fmt.Errorf("ingest store: load collections: %w", err)
	}
	for rows.Next() {
		var c Collection
		if err := rows.Scan(&c.Name, &c.Connector); err != nil {
			_ = rows.Close()
			return nil, nil, fmt.Errorf("ingest store: scan collection: %w", err)
		}
		cols[c.Name] = c
	}
	if err := closeRows(rows); err != nil {
		return nil, nil, err
	}

	chunkRows, err := st.db.QueryContext(ctx, r(`SELECT collection, id, doc_id, section, text, classification,
		source, format, messages, tools, vec FROM ingest_chunks ORDER BY collection, seq`))
	if err != nil {
		return nil, nil, fmt.Errorf("ingest store: load chunks: %w", err)
	}
	for chunkRows.Next() {
		var colName string
		var ch Chunk
		var messages, tools, vec []byte
		if err := chunkRows.Scan(&colName, &ch.ID, &ch.DocID, &ch.Section, &ch.Text, &ch.Classification,
			&ch.Source, &ch.Format, &messages, &tools, &vec); err != nil {
			_ = chunkRows.Close()
			return nil, nil, fmt.Errorf("ingest store: scan chunk: %w", err)
		}
		if len(messages) > 0 {
			ch.Messages = messages
		}
		if len(tools) > 0 {
			ch.Tools = tools
		}
		ch.Vec = decodeVec(vec)
		col := cols[colName] // chunks reference an existing collection row (same transaction wrote both)
		col.Chunks = append(col.Chunks, ch)
		cols[colName] = col
	}
	if err := closeRows(chunkRows); err != nil {
		return nil, nil, err
	}

	customs := map[string]corpus{}
	exRows, err := st.db.QueryContext(ctx, r(`SELECT name, src_class, text, format, messages, tools
		FROM ingest_custom ORDER BY name, seq`))
	if err != nil {
		return nil, nil, fmt.Errorf("ingest store: load custom: %w", err)
	}
	for exRows.Next() {
		var name, srcClass string
		var ex example
		var messages, tools []byte
		if err := exRows.Scan(&name, &srcClass, &ex.text, &ex.format, &messages, &tools); err != nil {
			_ = exRows.Close()
			return nil, nil, fmt.Errorf("ingest store: scan example: %w", err)
		}
		if len(messages) > 0 {
			ex.messages = messages
		}
		if len(tools) > 0 {
			ex.tools = tools
		}
		c := customs[name]
		c.connector, c.srcClass = "upload", srcClass
		c.examples = append(c.examples, ex)
		customs[name] = c
	}
	if err := closeRows(exRows); err != nil {
		return nil, nil, err
	}
	return cols, customs, nil
}

// closeRows surfaces both the iteration error and the close error (DB-guard hygiene).
func closeRows(rows *sql.Rows) error {
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return fmt.Errorf("ingest store: rows: %w", err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("ingest store: close: %w", err)
	}
	return nil
}

// encodeVec packs an embedding as little-endian float32 (nil-safe; empty slice -> nil blob).
func encodeVec(v []float32) []byte {
	if len(v) == 0 {
		return nil
	}
	out := make([]byte, 4*len(v))
	for i, f := range v {
		binary.LittleEndian.PutUint32(out[4*i:], math.Float32bits(f))
	}
	return out
}

// decodeVec is the inverse of encodeVec (tolerates a trailing partial word from a corrupt row by
// truncating to whole float32s — retrieval degrades, it does not panic).
func decodeVec(b []byte) []float32 {
	n := len(b) / 4
	if n == 0 {
		return nil
	}
	out := make([]float32, n)
	for i := range out {
		out[i] = math.Float32frombits(binary.LittleEndian.Uint32(b[4*i:]))
	}
	return out
}

// ---- connector definitions (console-connected sources; PRODUCTION: "Connect a source") ----

// saveConnectorDef upserts one console-defined connector (the def carries its secret — the store
// file is the controller's protected state; reads through the API always redact).
func (st *Store) saveConnectorDef(ctx context.Context, def ConnectorDef) error {
	raw, err := json.Marshal(def)
	if err != nil {
		return fmt.Errorf("ingest store: def: %w", err)
	}
	r := st.dialect.Rebind
	if _, err := st.db.ExecContext(ctx, r(`DELETE FROM ingest_connector_defs WHERE collection = ?`), def.Collection); err != nil {
		return fmt.Errorf("ingest store: clear def: %w", err)
	}
	if _, err := st.db.ExecContext(ctx, r(`INSERT INTO ingest_connector_defs (collection, def) VALUES (?, ?)`), def.Collection, raw); err != nil {
		return fmt.Errorf("ingest store: insert def: %w", err)
	}
	return nil
}

// deleteConnectorDef removes a console-defined connector AND its synced data (docs, cursor, chunks).
func (st *Store) deleteConnectorDef(ctx context.Context, collection string) error {
	r := st.dialect.Rebind
	for _, q := range []string{
		`DELETE FROM ingest_connector_defs WHERE collection = ?`,
		`DELETE FROM ingest_connector_docs WHERE collection = ?`,
		`DELETE FROM ingest_connector_state WHERE collection = ?`,
		`DELETE FROM ingest_chunks WHERE collection = ?`,
		`DELETE FROM ingest_collections WHERE name = ?`,
	} {
		if _, err := st.db.ExecContext(ctx, r(q), collection); err != nil {
			return fmt.Errorf("ingest store: disconnect %s: %w", collection, err)
		}
	}
	return nil
}

// loadConnectorDefs rehydrates the console-defined connectors (boot path).
func (st *Store) loadConnectorDefs(ctx context.Context) ([]ConnectorDef, error) {
	r := st.dialect.Rebind
	rows, err := st.db.QueryContext(ctx, r(`SELECT def FROM ingest_connector_defs`))
	if err != nil {
		return nil, fmt.Errorf("ingest store: load defs: %w", err)
	}
	var out []ConnectorDef
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("ingest store: scan def: %w", err)
		}
		var def ConnectorDef
		if err := json.Unmarshal(raw, &def); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("ingest store: def decode: %w", err)
		}
		out = append(out, def)
	}
	return out, closeRows(rows)
}

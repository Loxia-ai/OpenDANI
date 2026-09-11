// Package registry is the Node Registry (DL-R11-03a) backed by SQLite via the pure-Go
// modernc.org/sqlite driver (RR-R11-03: avoids CGO, works on Windows controllers). The schema is
// node_registry.sql verbatim (embedded), including the v_renewal_status view (DL-R11.2-05).
package registry

import (
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
	"fmt"
	"time"

	"dani.local/agent/internal/dbx"
)

//go:embed schema_sqlite.sql
var schemaSQLite string

//go:embed schema_postgres.sql
var schemaPostgres string

const rfc3339 = time.RFC3339

// Registry is the Node Registry database. SQLite (DEMO/dev) or PostgreSQL (HA) via the dbx seam.
type Registry struct {
	db      *sql.DB
	dialect dbx.Dialect
}

// Open opens (or creates) the registry DB at dsn and applies the dialect-appropriate schema. dsn is
// a SQLite path / ":memory:" / "sqlite:<path>", or a "postgres://..." URL (HA).
func Open(ctx context.Context, dsn string) (*Registry, error) {
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
		return nil, fmt.Errorf("apply schema: %w", err)
	}
	return &Registry{db: db, dialect: dialect}, nil
}

func (r *Registry) Close() error { return r.db.Close() }

// exec/queryRow/query rebind portable `?` SQL to the dialect, then delegate.
func (r *Registry) exec(ctx context.Context, q string, args ...any) (sql.Result, error) {
	return r.db.ExecContext(ctx, r.dialect.Rebind(q), args...)
}
func (r *Registry) queryRow(ctx context.Context, q string, args ...any) *sql.Row {
	return r.db.QueryRowContext(ctx, r.dialect.Rebind(q), args...)
}
func (r *Registry) query(ctx context.Context, q string, args ...any) (*sql.Rows, error) {
	return r.db.QueryContext(ctx, r.dialect.Rebind(q), args...)
}

// NodeRecord is the data the enrollment service stamps into the registry on admission.
type NodeRecord struct {
	UUID             string
	CertSerial       string
	NotBefore        time.Time
	NotAfter         time.Time
	Generation       int
	HardwareFprint   []byte
	Roles            []string
	Class            string
	Site             string
	Tier             int
	CapabilitiesJSON []byte
}

// UpsertEnrolled inserts (or refreshes) an enrolled node (DL-R11.2-03 assigned attributes).
func (r *Registry) UpsertEnrolled(ctx context.Context, n NodeRecord) error {
	roles, _ := json.Marshal(n.Roles)
	now := time.Now().UTC().Format(rfc3339)
	site := sql.NullString{String: n.Site, Valid: n.Site != ""}
	_, err := r.exec(ctx, `
		INSERT INTO nodes
		  (node_uuid, cert_serial, cert_not_before, cert_not_after, cert_generation, hardware_fprint,
		   assigned_roles, assigned_class, site_tag, attestation_tier, last_attested_at,
		   health_state, lifecycle_state, enrolled_at, row_updated_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?, 'unknown','active',?,?)
		ON CONFLICT(node_uuid) DO UPDATE SET
		  cert_serial=excluded.cert_serial, cert_not_before=excluded.cert_not_before,
		  cert_not_after=excluded.cert_not_after, cert_generation=excluded.cert_generation,
		  assigned_roles=excluded.assigned_roles, assigned_class=excluded.assigned_class,
		  site_tag=excluded.site_tag, attestation_tier=excluded.attestation_tier, row_updated_at=excluded.row_updated_at`,
		n.UUID, n.CertSerial, n.NotBefore.UTC().Format(rfc3339), n.NotAfter.UTC().Format(rfc3339), n.Generation,
		n.HardwareFprint, string(roles), n.Class, site, n.Tier, now /*last_attested_at*/, now /*enrolled_at*/, now /*row_updated_at*/)
	if err != nil {
		return err
	}
	if n.CapabilitiesJSON != nil {
		_, err = r.exec(ctx, `
			INSERT INTO node_capabilities (node_uuid, capabilities, cap_updated_at) VALUES (?,?,?)
			ON CONFLICT(node_uuid) DO UPDATE SET capabilities=excluded.capabilities, cap_updated_at=excluded.cap_updated_at`,
			n.UUID, string(n.CapabilitiesJSON), now)
	}
	return err
}

// Renew updates the cert window + generation after a renewal (DL-R11.2-05).
func (r *Registry) Renew(ctx context.Context, uuid, serial string, notBefore, notAfter time.Time, generation int) error {
	now := time.Now().UTC().Format(rfc3339)
	_, err := r.exec(ctx,
		`UPDATE nodes SET cert_serial=?, cert_not_before=?, cert_not_after=?, cert_generation=?, row_updated_at=? WHERE node_uuid=?`,
		serial, notBefore.UTC().Format(rfc3339), notAfter.UTC().Format(rfc3339), generation, now, uuid)
	return err
}

// Heartbeat records liveness + applied config version.
func (r *Registry) Heartbeat(ctx context.Context, uuid, health, appliedConfigVer string) error {
	now := time.Now().UTC().Format(rfc3339)
	_, err := r.exec(ctx,
		`UPDATE nodes SET last_heartbeat_at=?, health_state=?, applied_config_ver=?, row_updated_at=? WHERE node_uuid=?`,
		now, health, appliedConfigVer, now, uuid)
	return err
}

// SetLifecycle transitions a node (active|draining|revoked|decommissioned).
func (r *Registry) SetLifecycle(ctx context.Context, uuid, state string) error {
	now := time.Now().UTC().Format(rfc3339)
	var revoked sql.NullString
	if state == "revoked" {
		revoked = sql.NullString{String: now, Valid: true}
	}
	_, err := r.exec(ctx, `UPDATE nodes SET lifecycle_state=?, revoked_at=?, row_updated_at=? WHERE node_uuid=?`, state, revoked, now, uuid)
	return err
}

// RenewalStatus returns the v_renewal_status verdict for a node (healthy|renewal_due|grace_overdue|expired|revoked).
func (r *Registry) RenewalStatus(ctx context.Context, uuid string) (string, error) {
	var s string
	err := r.queryRow(ctx, `SELECT renewal_status FROM v_renewal_status WHERE node_uuid=?`, uuid).Scan(&s)
	return s, err
}

// RegRow is a full durable registry row — the unit of a Raft FSM snapshot (DL-R11-03b).
type RegRow struct {
	NodeRecord
	Lifecycle string `json:"lifecycle"`
	Health    string `json:"health"`
}

// DumpAll returns every durable node row, for a Raft snapshot.
func (r *Registry) DumpAll(ctx context.Context) ([]RegRow, error) {
	rows, err := r.query(ctx, `
		SELECT node_uuid, cert_serial, cert_not_before, cert_not_after, cert_generation, hardware_fprint,
		       assigned_roles, assigned_class, site_tag, attestation_tier, lifecycle_state, health_state
		FROM nodes ORDER BY node_uuid`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RegRow
	for rows.Next() {
		var x RegRow
		var nb, na, roles string
		var site sql.NullString
		if err := rows.Scan(&x.UUID, &x.CertSerial, &nb, &na, &x.Generation, &x.HardwareFprint,
			&roles, &x.Class, &site, &x.Tier, &x.Lifecycle, &x.Health); err != nil {
			return nil, err
		}
		x.NotBefore, _ = time.Parse(rfc3339, nb)
		x.NotAfter, _ = time.Parse(rfc3339, na)
		x.Site = site.String
		_ = json.Unmarshal([]byte(roles), &x.Roles)
		out = append(out, x)
	}
	return out, rows.Err()
}

// LoadAll replaces the registry contents with rows (a Raft snapshot restore).
func (r *Registry) LoadAll(ctx context.Context, rows []RegRow) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, r.dialect.Rebind(`DELETE FROM nodes`)); err != nil {
		return err
	}
	now := time.Now().UTC().Format(rfc3339)
	for _, x := range rows {
		roles, _ := json.Marshal(x.Roles)
		site := sql.NullString{String: x.Site, Valid: x.Site != ""}
		if _, err := tx.ExecContext(ctx, r.dialect.Rebind(`
			INSERT INTO nodes
			  (node_uuid, cert_serial, cert_not_before, cert_not_after, cert_generation, hardware_fprint,
			   assigned_roles, assigned_class, site_tag, attestation_tier, last_attested_at,
			   health_state, lifecycle_state, enrolled_at, row_updated_at)
			VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`),
			x.UUID, x.CertSerial, x.NotBefore.UTC().Format(rfc3339), x.NotAfter.UTC().Format(rfc3339), x.Generation,
			x.HardwareFprint, string(roles), x.Class, site, x.Tier, now, x.Health, x.Lifecycle, now, now); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ActiveNodesWithRole returns the UUIDs of active nodes whose assigned roles include role, ordered by
// UUID. Used for dedicated-hardware allocation (e.g. D17: find a trainer node, never an inference
// worker).
func (r *Registry) ActiveNodesWithRole(ctx context.Context, role string) ([]string, error) {
	rows, err := r.query(ctx,
		`SELECT node_uuid, assigned_roles FROM nodes WHERE lifecycle_state='active' ORDER BY node_uuid`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var uuid, rolesJSON string
		if err := rows.Scan(&uuid, &rolesJSON); err != nil {
			return nil, err
		}
		var roles []string
		_ = json.Unmarshal([]byte(rolesJSON), &roles)
		for _, rr := range roles {
			if rr == role {
				out = append(out, uuid)
				break
			}
		}
	}
	return out, rows.Err()
}

// Count returns the number of registered nodes.
func (r *Registry) Count(ctx context.Context) (int, error) {
	var n int
	err := r.queryRow(ctx, `SELECT COUNT(*) FROM nodes`).Scan(&n)
	return n, err
}

// Row is a registry row projection.
type Row struct {
	UUID, Class, Health, Lifecycle string
	Roles                          []string
	Tier, Generation               int
}

// Get returns a node's row.
func (r *Registry) Get(ctx context.Context, uuid string) (*Row, error) {
	var row Row
	var roles string
	err := r.queryRow(ctx,
		`SELECT node_uuid, assigned_class, health_state, lifecycle_state, assigned_roles, attestation_tier, cert_generation FROM nodes WHERE node_uuid=?`, uuid).
		Scan(&row.UUID, &row.Class, &row.Health, &row.Lifecycle, &roles, &row.Tier, &row.Generation)
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal([]byte(roles), &row.Roles)
	return &row, nil
}

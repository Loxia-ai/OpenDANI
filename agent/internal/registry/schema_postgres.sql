-- DANI Node Registry — PostgreSQL schema (HA / production; parity with schema_sqlite.sql).
CREATE TABLE IF NOT EXISTS nodes (
    node_uuid          TEXT PRIMARY KEY NOT NULL,
    cert_serial        TEXT NOT NULL,
    cert_not_before    TEXT NOT NULL,
    cert_not_after     TEXT NOT NULL,
    cert_generation    INTEGER NOT NULL DEFAULT 1,
    hardware_fprint    BYTEA NOT NULL,
    assigned_roles     TEXT NOT NULL,
    assigned_class     TEXT NOT NULL,
    site_tag           TEXT,
    attestation_tier   INTEGER NOT NULL,
    last_attested_at   TEXT NOT NULL,
    health_state       TEXT NOT NULL DEFAULT 'unknown',
    last_heartbeat_at  TEXT,
    applied_config_ver TEXT,
    lifecycle_state    TEXT NOT NULL,
    enrolled_at        TEXT NOT NULL,
    revoked_at         TEXT,
    row_updated_at     TEXT NOT NULL,
    CHECK (attestation_tier BETWEEN 0 AND 3),
    CHECK (lifecycle_state IN ('active','draining','revoked','decommissioned')),
    CHECK (health_state   IN ('healthy','degraded','draining','unknown'))
);

CREATE INDEX IF NOT EXISTS idx_nodes_class      ON nodes(assigned_class);
CREATE INDEX IF NOT EXISTS idx_nodes_tier       ON nodes(attestation_tier);
CREATE INDEX IF NOT EXISTS idx_nodes_health     ON nodes(health_state);
CREATE INDEX IF NOT EXISTS idx_nodes_lifecycle  ON nodes(lifecycle_state);
CREATE INDEX IF NOT EXISTS idx_nodes_not_after  ON nodes(cert_not_after);
CREATE INDEX IF NOT EXISTS idx_nodes_site       ON nodes(site_tag);

CREATE TABLE IF NOT EXISTS node_capabilities (
    node_uuid      TEXT PRIMARY KEY NOT NULL REFERENCES nodes(node_uuid) ON DELETE CASCADE,
    capabilities   TEXT NOT NULL,
    cap_updated_at TEXT NOT NULL
);

-- Renewal-status view (DL-R11.2-05): the SQLite julianday() math, expressed with timestamptz casts.
-- Renewal window opens at 50% of cert life, grace/overdue past 90%.
CREATE OR REPLACE VIEW v_renewal_status AS
SELECT
    node_uuid,
    cert_not_before,
    cert_not_after,
    lifecycle_state,
    CASE
        WHEN lifecycle_state = 'revoked' THEN 'revoked'
        WHEN cert_not_after::timestamptz < now() THEN 'expired'
        WHEN now() >= cert_not_before::timestamptz
                    + (cert_not_after::timestamptz - cert_not_before::timestamptz) * 0.5
         AND now() <  cert_not_before::timestamptz
                    + (cert_not_after::timestamptz - cert_not_before::timestamptz) * 0.9
            THEN 'renewal_due'
        WHEN now() >= cert_not_before::timestamptz
                    + (cert_not_after::timestamptz - cert_not_before::timestamptz) * 0.9
            THEN 'grace_overdue'
        ELSE 'healthy'
    END AS renewal_status
FROM nodes;

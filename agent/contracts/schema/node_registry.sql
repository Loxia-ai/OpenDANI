-- DANI Node Registry — SQLite schema
-- Governing decisions:
--   DL-R11-03a : SQLite for Node Registry, WAL mode, synchronous=NORMAL, one DB file per service
--   DL-R11-07  : one X.509 identity cert per node; roles/classification advisory bearer claims
--   DL-R11-08 / DF-R11-02 : cert carries node-uuid (CN), roles[], classification, attestationTier,
--                           hardwareFprint, enrolledAt, siteTag
--   DL-R11.2-02 : attestation tiers 0..3 (proven, not claimed)
--   DL-R11.2-03 : approval stamps ASSIGNED attributes (roles, classification, site); declared != assigned
--   DL-R11.2-05 : controller-side renewal-status view (Healthy/Renewal-due/Grace-overdue/Expired)
--                 derived from cert expiry the controller already knows
--
-- This file is the Node Registry service's OWN database (one-DB-file-per-service, DL-R11-04).
-- It is NOT shared with config.db, audit-buffer, raft stores, or the pending-join queue.

PRAGMA journal_mode = WAL;          -- DL-R11-03a
PRAGMA synchronous  = NORMAL;       -- DL-R11-03a
PRAGMA foreign_keys = ON;
PRAGMA busy_timeout = 5000;

-- ---------------------------------------------------------------------------
-- nodes : the authoritative per-node registry row
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS nodes (
    node_uuid          TEXT PRIMARY KEY NOT NULL,   -- DF-R11-02 cert CN; stable for life (D43)
    -- Identity / cert state -------------------------------------------------
    cert_serial        TEXT NOT NULL,               -- current identity cert serial
    cert_not_before    TEXT NOT NULL,               -- RFC3339
    cert_not_after     TEXT NOT NULL,               -- RFC3339; basis of renewal-status (DL-R11.2-05)
    cert_generation    INTEGER NOT NULL DEFAULT 1,  -- bumps on each renewal/rotation (DL-R11-07)
    hardware_fprint    BLOB NOT NULL,               -- DF-R11-02 hardwareFprint (TPM EK pub hash)
    -- ASSIGNED attributes (set by approver, authoritative — DL-R11.2-03) -----
    assigned_roles     TEXT NOT NULL,               -- JSON array, e.g. ["worker","gateway"]
    assigned_class     TEXT NOT NULL,               -- e.g. "restricted" | "unrestricted:secret"
    site_tag           TEXT,                        -- optional; DF-R11-02 siteTag
    -- Attestation (proven, not claimed — DL-R11.2-02) -----------------------
    attestation_tier   INTEGER NOT NULL,            -- 0..3
    last_attested_at   TEXT NOT NULL,               -- RFC3339; basis of re-attestation interval
    -- Liveness / health -----------------------------------------------------
    health_state       TEXT NOT NULL DEFAULT 'unknown',  -- healthy|degraded|draining|unknown
    last_heartbeat_at  TEXT,                        -- RFC3339; from Link stream (DL-R11-06)
    applied_config_ver TEXT,                        -- config convergence (DL-R11-10)
    -- Lifecycle -------------------------------------------------------------
    lifecycle_state    TEXT NOT NULL,               -- active|draining|revoked|decommissioned
    enrolled_at        TEXT NOT NULL,               -- RFC3339; DF-R11-02 enrolledAt
    revoked_at         TEXT,                         -- set when trust severed (→ full re-enroll)
    -- Bookkeeping -----------------------------------------------------------
    row_updated_at     TEXT NOT NULL,
    CHECK (attestation_tier BETWEEN 0 AND 3),
    CHECK (lifecycle_state IN ('active','draining','revoked','decommissioned')),
    CHECK (health_state   IN ('healthy','degraded','draining','unknown'))
);

CREATE INDEX IF NOT EXISTS idx_nodes_class      ON nodes(assigned_class);
CREATE INDEX IF NOT EXISTS idx_nodes_tier       ON nodes(attestation_tier);
CREATE INDEX IF NOT EXISTS idx_nodes_health     ON nodes(health_state);
CREATE INDEX IF NOT EXISTS idx_nodes_lifecycle  ON nodes(lifecycle_state);
CREATE INDEX IF NOT EXISTS idx_nodes_not_after  ON nodes(cert_not_after);  -- renewal-status scans
CREATE INDEX IF NOT EXISTS idx_nodes_site       ON nodes(site_tag);

-- Capability inventory: queried by routing/placement ("workers with cap X, VRAM >= N").
-- Stored as JSON1 column on the node row's satellite table to keep the hot row lean.
CREATE TABLE IF NOT EXISTS node_capabilities (
    node_uuid     TEXT PRIMARY KEY NOT NULL REFERENCES nodes(node_uuid) ON DELETE CASCADE,
    capabilities  TEXT NOT NULL,        -- JSON object (engines, VRAM, accelerators, etc.)
    cap_updated_at TEXT NOT NULL
);

-- ---------------------------------------------------------------------------
-- renewal_status : a VIEW, not a table (DL-R11.2-05).
-- Derived purely from cert_not_after vs now + renewal window — "nearly free,
-- no new protocol, no node-side work". Controller reads this to surface
-- Healthy / Renewal-due / Grace-overdue / Expired and raise early warnings.
--
-- Renewal window opens at 50% life (DL-R11-07). We cannot compute 50% without
-- not_before, so the view uses both ends. ':now' is bound by the caller.
-- ---------------------------------------------------------------------------
CREATE VIEW IF NOT EXISTS v_renewal_status AS
SELECT
    node_uuid,
    cert_not_before,
    cert_not_after,
    lifecycle_state,
    CASE
        WHEN lifecycle_state = 'revoked'        THEN 'revoked'
        WHEN julianday(cert_not_after) <  julianday('now')  THEN 'expired'
        -- past 50% life = renewal window open
        WHEN julianday('now') >=
             julianday(cert_not_before) +
             (julianday(cert_not_after) - julianday(cert_not_before)) * 0.5
          AND julianday('now') <
             julianday(cert_not_before) +
             (julianday(cert_not_after) - julianday(cert_not_before)) * 0.9
            THEN 'renewal_due'
        -- past 90% life and still not renewed = grace/overdue (early unreachability signal)
        WHEN julianday('now') >=
             julianday(cert_not_before) +
             (julianday(cert_not_after) - julianday(cert_not_before)) * 0.9
            THEN 'grace_overdue'
        ELSE 'healthy'
    END AS renewal_status
FROM nodes;

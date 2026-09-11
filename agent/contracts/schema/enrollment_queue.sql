-- DANI Enrollment — Pending-Join Queue SQLite schema
-- Governing decisions:
--   DL-R11.2-03 : ONE pending-join queue, three drain modes (auto-policy / batch-confirm / scrutiny).
--                 Node-initiated; lingers harmlessly; advertises proven facts.
--   DL-R11.2-04 : EnrollPending{requestId, queuePosition?, mode}; patient pollable state;
--                 attestation RE-VALIDATED at admission, not just request.
--   DL-R11.2-01 : bootstrap token single-use first-factor; burned on SUCCESS not attempt (DL-R11.2-04).
--   RR-R11.2-06 : rate-limit + auto-expire stale pending entries + alert on abnormal growth.
--   DL-R11-04   : one DB file per service — this is the Enrollment service's queue DB, separate
--                 from node_registry.db.

PRAGMA journal_mode = WAL;
PRAGMA synchronous  = NORMAL;
PRAGMA foreign_keys = ON;
PRAGMA busy_timeout = 5000;

-- ---------------------------------------------------------------------------
-- pending_enrollments : a node that passed attestation and is waiting to join.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS pending_enrollments (
    request_id        TEXT PRIMARY KEY NOT NULL,    -- EnrollPending.requestId (opaque, node polls on it)
    node_uuid         TEXT NOT NULL,                -- candidate node identity (self-minted, DL-R11.2-01)
    token_id          TEXT NOT NULL,                -- which bootstrap token was used (audit + single-use)
    deployment_id     TEXT NOT NULL,                -- token deploymentId (replay-scope, DL-R11.2-01)
    -- Proven facts advertised to the approver (DL-R11.2-03) ------------------
    achieved_tier     INTEGER NOT NULL,             -- attestation tier the node ACTUALLY reached (0..3)
    declared_roles    TEXT NOT NULL,                -- JSON array — request, NOT grant (DL-R11.2-03a)
    declared_class    TEXT NOT NULL,                -- request, NOT grant
    hardware_fprint   BLOB NOT NULL,
    capability_inv    TEXT NOT NULL,                -- JSON; from EnrollProof.capabilityInventory
    csr_der           BLOB NOT NULL,                -- the CSR awaiting signature (DL-R11.2-04 step 3)
    -- Attestation freshness — basis for RE-VALIDATION at admission (DL-R11.2-04) ---
    attested_at       TEXT NOT NULL,                -- RFC3339 when proof was verified
    pcr_quote_digest  BLOB,                          -- retained to detect staleness at admit time
    -- Queue state -----------------------------------------------------------
    drain_mode        TEXT NOT NULL,                -- auto_policy|batch_confirm|scrutiny (DL-R11.2-03)
    queue_state       TEXT NOT NULL DEFAULT 'waiting', -- waiting|approved|rejected|expired
    matched_policy_id TEXT,                          -- set if a Mode-1 auto-policy matched
    -- Lifecycle / anti-grief (RR-R11.2-06) ----------------------------------
    requested_at      TEXT NOT NULL,                 -- RFC3339
    expires_at        TEXT NOT NULL,                 -- auto-expire stale entries
    source_addr       TEXT,                          -- for per-source rate-limiting
    decided_at        TEXT,                          -- when approved/rejected
    decided_by        TEXT,                          -- SO principal or policy id
    reject_reason     TEXT,
    CHECK (achieved_tier BETWEEN 0 AND 3),
    CHECK (drain_mode  IN ('auto_policy','batch_confirm','scrutiny')),
    CHECK (queue_state IN ('waiting','approved','rejected','expired'))
);

CREATE INDEX IF NOT EXISTS idx_pending_state    ON pending_enrollments(queue_state);
CREATE INDEX IF NOT EXISTS idx_pending_expires  ON pending_enrollments(expires_at);
CREATE INDEX IF NOT EXISTS idx_pending_token    ON pending_enrollments(token_id);
CREATE INDEX IF NOT EXISTS idx_pending_source   ON pending_enrollments(source_addr);
CREATE INDEX IF NOT EXISTS idx_pending_node     ON pending_enrollments(node_uuid);

-- ---------------------------------------------------------------------------
-- consumed_tokens : single-use enforcement (DL-R11.2-01).
-- A token is recorded here ONLY on successful cert issuance (DL-R11.2-04
-- token-consumption rule: burned on success, not on a failed attempt).
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS consumed_tokens (
    token_id      TEXT PRIMARY KEY NOT NULL,
    nonce         TEXT NOT NULL,                    -- DL-R11.2-01 token nonce
    consumed_at   TEXT NOT NULL,                    -- RFC3339; set at successful EnrollComplete
    node_uuid     TEXT NOT NULL                     -- which node it minted
);

-- ---------------------------------------------------------------------------
-- auto_approval_policies : Mode-1 signed policies (DL-R11.2-03).
-- Time-bounded (mandatory not_after), Tier-2-floored, classification-ceilinged.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS auto_approval_policies (
    policy_id         TEXT PRIMARY KEY NOT NULL,
    signed_blob       BLOB NOT NULL,                -- SO-signed policy document (verify on use, DP13)
    min_tier          INTEGER NOT NULL,             -- must be >= 2 (linchpin, DL-R11.2-02)
    class_ceiling     TEXT NOT NULL,                -- auto-approval cannot exceed this (DL-R11.2-03b)
    match_selector    TEXT NOT NULL,                -- JSON: MDM group / hostname pattern / roles
    not_after         TEXT NOT NULL,                -- MANDATORY expiry (DL-R11.2-03 / Daniel)
    max_count         INTEGER,                       -- OPTIONAL count cap
    approved_count    INTEGER NOT NULL DEFAULT 0,
    created_at        TEXT NOT NULL,
    created_by        TEXT NOT NULL,                -- SO principal
    revoked_at        TEXT,
    CHECK (min_tier >= 2)                            -- enforce Tier-2 floor at schema level
);

CREATE INDEX IF NOT EXISTS idx_policies_notafter ON auto_approval_policies(not_after);

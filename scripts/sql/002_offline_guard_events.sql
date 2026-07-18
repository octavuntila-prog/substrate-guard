-- Remote sink table for the L6 offline store's SyncEngine (audit 2026-07-17 item 2.C).
-- LocalStore keeps an append-only SQLite `events` log; SyncEngine pushes unsynced rows
-- into this canonical `guard_events` table on the remote (PostgreSQL in production),
-- via INSERT ... ON CONFLICT (id) DO NOTHING (append-only union by primary-key id).
-- Columns MUST match SyncEngine.sync()'s INSERT (id..prev_hash + source); the
-- HMAC-chain columns are stored byte-exact so verify_chain still holds across the sink.

CREATE TABLE IF NOT EXISTS guard_events (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    event_type TEXT NOT NULL,
    agent_id TEXT,
    layer TEXT NOT NULL,
    data TEXT NOT NULL,
    hmac_hash TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    source TEXT
);

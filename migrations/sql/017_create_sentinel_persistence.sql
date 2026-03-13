-- Sentinel persistence entries
CREATE TABLE IF NOT EXISTS sentinel_persistence_entries (
    id TEXT PRIMARY KEY NOT NULL,
    timestamp TEXT NOT NULL,
    mechanism TEXT NOT NULL,
    path TEXT NOT NULL,
    content_hash TEXT NOT NULL DEFAULT '',
    detail TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_sentinel_persistence_entries_timestamp ON sentinel_persistence_entries(timestamp);
CREATE INDEX IF NOT EXISTS idx_sentinel_persistence_entries_mechanism ON sentinel_persistence_entries(mechanism);
CREATE INDEX IF NOT EXISTS idx_sentinel_persistence_entries_path ON sentinel_persistence_entries(path);

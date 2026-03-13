-- Sentinel baselines and metadata
CREATE TABLE IF NOT EXISTS sentinel_baselines (
    id TEXT PRIMARY KEY NOT NULL,
    category TEXT NOT NULL,
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    captured_at TEXT NOT NULL,
    UNIQUE(category, key)
);
CREATE INDEX IF NOT EXISTS idx_sentinel_baselines_category ON sentinel_baselines(category);
CREATE INDEX IF NOT EXISTS idx_sentinel_baselines_captured_at ON sentinel_baselines(captured_at);

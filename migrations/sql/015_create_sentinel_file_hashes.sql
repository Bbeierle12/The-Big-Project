-- Sentinel file integrity snapshots
CREATE TABLE IF NOT EXISTS sentinel_file_hashes (
    id TEXT PRIMARY KEY NOT NULL,
    timestamp TEXT NOT NULL,
    path TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    size_bytes INTEGER NOT NULL DEFAULT 0,
    mtime REAL NOT NULL DEFAULT 0,
    ctime REAL NOT NULL DEFAULT 0,
    uid INTEGER NOT NULL DEFAULT 0,
    gid INTEGER NOT NULL DEFAULT 0,
    mode INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_sentinel_file_hashes_timestamp ON sentinel_file_hashes(timestamp);
CREATE INDEX IF NOT EXISTS idx_sentinel_file_hashes_path ON sentinel_file_hashes(path);
CREATE INDEX IF NOT EXISTS idx_sentinel_file_hashes_sha256 ON sentinel_file_hashes(sha256);

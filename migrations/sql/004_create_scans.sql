-- Scan execution records
CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY NOT NULL,
    scan_type TEXT NOT NULL DEFAULT 'custom',
    tool TEXT NOT NULL,
    target TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    progress REAL NOT NULL DEFAULT 0.0,
    parameters TEXT NOT NULL DEFAULT '{}',
    results TEXT NOT NULL DEFAULT '{}',
    started_at TEXT,
    completed_at TEXT,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status);
CREATE INDEX IF NOT EXISTS idx_scans_tool ON scans(tool);

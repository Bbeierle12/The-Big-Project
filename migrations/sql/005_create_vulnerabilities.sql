-- Discovered vulnerabilities
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id TEXT PRIMARY KEY NOT NULL,
    cve_id TEXT,
    cvss_score REAL,
    severity TEXT NOT NULL DEFAULT 'info',
    title TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    device_id TEXT REFERENCES devices(id) ON DELETE SET NULL,
    port INTEGER,
    source_tool TEXT NOT NULL,
    solution TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_vulns_cve_id ON vulnerabilities(cve_id);
CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulnerabilities(severity);
CREATE INDEX IF NOT EXISTS idx_vulns_device_id ON vulnerabilities(device_id);

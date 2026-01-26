-- Security alerts from the pipeline
CREATE TABLE IF NOT EXISTS alerts (
    id TEXT PRIMARY KEY NOT NULL,
    severity TEXT NOT NULL DEFAULT 'info',
    status TEXT NOT NULL DEFAULT 'new',
    source_tool TEXT NOT NULL,
    category TEXT NOT NULL DEFAULT 'other',
    title TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    device_ip TEXT,
    fingerprint TEXT NOT NULL,
    correlation_id TEXT,
    count INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_fingerprint ON alerts(fingerprint);
CREATE INDEX IF NOT EXISTS idx_alerts_device_ip ON alerts(device_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_correlation_id ON alerts(correlation_id);

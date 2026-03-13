-- Sentinel auth events
CREATE TABLE IF NOT EXISTS sentinel_auth_events (
    id TEXT PRIMARY KEY NOT NULL,
    timestamp TEXT NOT NULL,
    event_type TEXT NOT NULL,
    user TEXT NOT NULL DEFAULT '',
    source_ip TEXT NOT NULL DEFAULT '',
    method TEXT NOT NULL DEFAULT '',
    detail TEXT NOT NULL DEFAULT '',
    severity TEXT NOT NULL DEFAULT 'info'
);
CREATE INDEX IF NOT EXISTS idx_sentinel_auth_events_timestamp ON sentinel_auth_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_sentinel_auth_events_user ON sentinel_auth_events(user);
CREATE INDEX IF NOT EXISTS idx_sentinel_auth_events_type ON sentinel_auth_events(event_type);

-- Passive protocol observations
CREATE TABLE IF NOT EXISTS observations (
    id TEXT PRIMARY KEY NOT NULL,
    device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    protocol TEXT NOT NULL,
    source_data TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_observations_device_id ON observations(device_id);
CREATE INDEX IF NOT EXISTS idx_observations_protocol ON observations(protocol);

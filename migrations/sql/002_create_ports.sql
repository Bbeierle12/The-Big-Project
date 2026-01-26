-- Ports discovered on devices
CREATE TABLE IF NOT EXISTS ports (
    id TEXT PRIMARY KEY NOT NULL,
    device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    port_number INTEGER NOT NULL,
    protocol TEXT NOT NULL DEFAULT 'tcp',
    state TEXT NOT NULL DEFAULT 'unknown',
    service_name TEXT,
    service_version TEXT,
    banner TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_ports_device_id ON ports(device_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_ports_device_port_proto ON ports(device_id, port_number, protocol);

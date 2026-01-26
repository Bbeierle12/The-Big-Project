-- Network traffic flow records
CREATE TABLE IF NOT EXISTS traffic_flows (
    id TEXT PRIMARY KEY NOT NULL,
    src_ip TEXT NOT NULL,
    src_port INTEGER NOT NULL,
    dst_ip TEXT NOT NULL,
    dst_port INTEGER NOT NULL,
    protocol TEXT NOT NULL DEFAULT 'tcp',
    bytes_sent INTEGER NOT NULL DEFAULT 0,
    bytes_received INTEGER NOT NULL DEFAULT 0,
    packets_sent INTEGER NOT NULL DEFAULT 0,
    packets_received INTEGER NOT NULL DEFAULT 0,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_traffic_src_ip ON traffic_flows(src_ip);
CREATE INDEX IF NOT EXISTS idx_traffic_dst_ip ON traffic_flows(dst_ip);

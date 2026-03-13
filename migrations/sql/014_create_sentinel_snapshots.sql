-- Sentinel host snapshot tables
CREATE TABLE IF NOT EXISTS sentinel_process_snapshots (
    id TEXT PRIMARY KEY NOT NULL,
    timestamp TEXT NOT NULL,
    pid INTEGER NOT NULL,
    name TEXT NOT NULL,
    user TEXT NOT NULL DEFAULT '',
    ppid INTEGER NOT NULL DEFAULT 0,
    parent_name TEXT NOT NULL DEFAULT '',
    exe_path TEXT NOT NULL DEFAULT '',
    cmdline TEXT NOT NULL DEFAULT '',
    cpu_pct REAL NOT NULL DEFAULT 0,
    rss_bytes INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_sentinel_process_snapshots_timestamp ON sentinel_process_snapshots(timestamp);
CREATE INDEX IF NOT EXISTS idx_sentinel_process_snapshots_name ON sentinel_process_snapshots(name);
CREATE INDEX IF NOT EXISTS idx_sentinel_process_snapshots_pid ON sentinel_process_snapshots(pid);

CREATE TABLE IF NOT EXISTS sentinel_network_snapshots (
    id TEXT PRIMARY KEY NOT NULL,
    timestamp TEXT NOT NULL,
    proto TEXT NOT NULL,
    local_addr TEXT NOT NULL DEFAULT '',
    local_port INTEGER NOT NULL DEFAULT 0,
    remote_addr TEXT NOT NULL DEFAULT '',
    remote_port INTEGER NOT NULL DEFAULT 0,
    state TEXT NOT NULL DEFAULT '',
    pid INTEGER NOT NULL DEFAULT 0,
    process_name TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_sentinel_network_snapshots_timestamp ON sentinel_network_snapshots(timestamp);
CREATE INDEX IF NOT EXISTS idx_sentinel_network_snapshots_remote ON sentinel_network_snapshots(remote_addr);
CREATE INDEX IF NOT EXISTS idx_sentinel_network_snapshots_pid ON sentinel_network_snapshots(pid);

CREATE TABLE IF NOT EXISTS sentinel_system_metrics (
    id TEXT PRIMARY KEY NOT NULL,
    timestamp TEXT NOT NULL,
    cpu_pct REAL NOT NULL DEFAULT 0,
    mem_pct REAL NOT NULL DEFAULT 0,
    mem_used_mb REAL NOT NULL DEFAULT 0,
    disk_pct REAL NOT NULL DEFAULT 0,
    disk_used_gb REAL NOT NULL DEFAULT 0,
    net_bytes_sent INTEGER NOT NULL DEFAULT 0,
    net_bytes_recv INTEGER NOT NULL DEFAULT 0,
    load_1m REAL NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_sentinel_system_metrics_timestamp ON sentinel_system_metrics(timestamp);

# Sentinel: Host Security & OSINT Module for NetSec

## Overview

Sentinel adds host-based security monitoring, OSINT threat intelligence, and
detection algorithms to The Big Project (NetSec Orchestrator). It is **not** a
separate project — it lives inside the existing workspace and reuses the
pipeline, database, event bus, scheduler, models, and API.

### What Already Exists (reuse, do not rebuild)

| Capability | Existing Location |
|---|---|
| Alert model (`NormalizedAlert`, `Alert`, Severity, Category) | `netsec-models/src/alert.rs` |
| 5-stage pipeline (dedup → correlate → score → dispatch) | `netsec-pipeline/` |
| EventBus + WebSocket forwarding | `netsec-events/` |
| SQLite pool + migrations | `netsec-db/` |
| Scheduler (cron + interval, persisted) | `netsec-scheduler/` |
| ThreatDetector trait + ThreatEngine | `netsec-threat/src/lib.rs` |
| Shannon entropy + beaconing + cryptojack detection | `netsec-threat/src/entropy.rs` |
| BaseAdapter + ToolInfo + ToolCategory | `python/netsec/adapters/base.py` |
| Process subprocess helpers | `python/netsec/adapters/process.py` |
| FastAPI router scaffold | `python/netsec/api/routers/` |
| Desktop GUI dashboard framework | `netsec-gui/` |

### What Sentinel Adds (net-new)

1. **Rust crate `netsec-sentinel`** — host-monitoring collectors + detection algorithms
2. **Python module `python/netsec/sentinel/`** — OSINT feeds, reputation APIs, vuln scanner
3. **Python adapter `python/netsec/adapters/sentinel.py`** — adapter wrapping the sentinel module
4. **FastAPI router `python/netsec/api/routers/sentinel.py`** — `/api/sentinel/*` endpoints
5. **6 new DB migrations** — sentinel-specific tables
6. **Config section** — `[sentinel]` in `config/default.toml`

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        NetSec Orchestrator                       │
│                                                                   │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────────────┐ │
│  │ netsec-threat │   │netsec-sentinel│  │ python/netsec/sentinel│ │
│  │ (existing)    │   │ (NEW Rust)    │  │ (NEW Python)          │ │
│  │              │   │              │  │                        │ │
│  │ ARP spoof    │   │ Collectors:  │  │ OSINT:                │ │
│  │ DNS hijack   │   │  process     │  │  feed_manager         │ │
│  │ Evil twin    │   │  network     │  │  reputation           │ │
│  │ Entropy ────────▶│  file_integ  │  │  vuln_scanner         │ │
│  │ Covert chan  │   │  auth        │  │  dnsbl                │ │
│  │ Malvertising │   │  persistence │  │  cert_monitor         │ │
│  │ Infostealer  │   │  metrics     │  │  correlator           │ │
│  │              │   │              │  │                        │ │
│  │              │   │ Analyzers:   │  │ Adapters:             │ │
│  │              │   │  process_tree│  │  sentinel.py          │ │
│  │              │   │  reverse_shell│ │   (BaseAdapter impl)  │ │
│  │              │   │  masquerade  │  │                        │ │
│  │              │   │  fileless    │  │                        │ │
│  │              │   │  ewma_spike  │  │                        │ │
│  │              │   │  suid_drift  │  │                        │ │
│  │              │   │  timestomp   │  │                        │ │
│  │              │   │  log_tamper  │  │                        │ │
│  │              │   │  beaconing   │  │                        │ │
│  │              │   │  risk_accum  │  │                        │ │
│  └──────────────┘   └──────┬───────┘  └───────────┬────────────┘ │
│                            │                       │              │
│                            ▼                       ▼              │
│                   ┌────────────────────────────────────┐          │
│                   │   NormalizedAlert → Pipeline        │          │
│                   │   (dedup → correlate → score →      │          │
│                   │    dispatch → DB + EventBus + WS)   │          │
│                   └────────────────────────────────────┘          │
│                            │                                      │
│                   ┌────────┴────────┐                             │
│                   │   netsec-db      │                             │
│                   │   (existing +    │                             │
│                   │    6 new tables)  │                             │
│                   └─────────────────┘                             │
└─────────────────────────────────────────────────────────────────┘
```

---

## Step 1: Architecture (Infrastructure, Collection, Storage)

Build the skeleton: collectors that capture raw host state, OSINT feed
ingestion, new DB tables, adapter registration, API endpoints, and scheduler
jobs. No detection intelligence yet — just data capture and storage.

### Phase 1A: Rust Crate `netsec-sentinel` — Collectors

**New crate:** `crates/netsec-sentinel/`

```
crates/netsec-sentinel/
├── Cargo.toml
└── src/
    ├── lib.rs                  # pub mod collectors; pub mod analyzers;
    ├── config.rs               # SentinelConfig (deserialized from TOML)
    ├── collectors/
    │   ├── mod.rs              # Collector trait + HostSnapshot struct
    │   ├── process.rs          # psutil-equivalent via /proc
    │   ├── network.rs          # /proc/net/tcp + /proc/[pid]/fd
    │   ├── file_integrity.rs   # SHA-256 hashing of watched files
    │   ├── auth.rs             # auth.log seek-based parser
    │   ├── persistence.rs      # Enumerate 20+ MITRE persistence locations
    │   └── metrics.rs          # CPU/mem/disk/net from /proc/stat, /proc/meminfo
    └── analyzers/
        └── mod.rs              # Empty — Step 2
```

**Dependencies (add to workspace Cargo.toml):**
```toml
netsec-sentinel = { path = "crates/netsec-sentinel" }
sha2 = "0.10"       # SHA-256 hashing
walkdir = "2"        # Directory traversal for persistence scan
```

**Collector trait (mirrors ThreatDetector pattern):**
```rust
#[async_trait]
pub trait Collector: Send + Sync {
    fn name(&self) -> &str;
    async fn collect(&self) -> CollectorResult<Vec<CollectedEvent>>;
    fn available(&self) -> bool { true }
}
```

**CollectedEvent (new model in netsec-models):**
```rust
// netsec-models/src/sentinel.rs (new file)
pub struct CollectedEvent {
    pub collector: String,          // "process", "network", "file", etc.
    pub event_type: String,         // "snapshot", "change", "new_entry"
    pub data: serde_json::Value,    // Collector-specific payload
    pub timestamp: DateTime<Utc>,
    pub risk_hint: u8,              // 0-100, advisory for analyzers
}
```

**Collector Details:**

`process.rs` — Reads `/proc/[pid]/stat`, `/proc/[pid]/cmdline`, `/proc/[pid]/exe`,
`/proc/[pid]/status` for all processes. Outputs JSON with: pid, name, ppid,
parent_name, uid, exe_path, cmdline, cpu_pct, rss_bytes. No analysis.

`network.rs` — Parses `/proc/net/tcp`, `/proc/net/tcp6`, `/proc/net/udp`.
Maps socket inodes to PIDs via `/proc/[pid]/fd/`. Outputs: proto, local_addr,
local_port, remote_addr, remote_port, state, pid, process_name.

`file_integrity.rs` — SHA-256 hashes files from `SentinelConfig.watch_paths`.
Outputs: path, sha256, size, mtime, uid, gid, mode. Also scans /tmp, /dev/shm,
/var/tmp for executables (checks ELF magic `\x7fELF` and shebang `#!`).

`auth.rs` — Reads `/var/log/auth.log` from stored seek offset. Regex patterns
for: `sshd.*Accepted`, `sshd.*Failed`, `sudo:.*COMMAND`, `su.*session opened`,
`useradd`, `usermod`, `passwd`. Outputs structured events with user, source_ip,
method, command.

`persistence.rs` — Walks all 20+ persistence locations. For each file found:
path, mechanism type (cron/systemd/profile/xdg/linker/ssh/init/apt/motd/module),
content SHA-256, mtime. Uses `walkdir` for directories. Static list of all paths
from MITRE research.

`metrics.rs` — Reads `/proc/stat` (CPU), `/proc/meminfo` (memory),
`statvfs("/")` (disk), `/proc/net/dev` (network bytes), `/proc/loadavg`.
Outputs single snapshot row.

**CollectorEngine (mirrors ThreatEngine):**
```rust
pub struct CollectorEngine {
    collectors: Vec<Box<dyn Collector>>,
}
impl CollectorEngine {
    pub fn with_defaults(config: &SentinelConfig) -> Self { ... }
    pub async fn run_all(&self) -> Vec<CollectedEvent> { ... }
}
```

### Phase 1B: Database Migrations

**6 new migration files in `migrations/sql/`:**

`014_create_sentinel_snapshots.sql` — process + network + metrics snapshots
```sql
CREATE TABLE IF NOT EXISTS sentinel_process_snapshots (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    pid INTEGER NOT NULL,
    name TEXT NOT NULL,
    ppid INTEGER,
    parent_name TEXT,
    uid INTEGER,
    user TEXT,
    exe_path TEXT,
    cmdline TEXT,
    cpu_pct REAL,
    rss_bytes INTEGER
);
CREATE INDEX idx_sps_timestamp ON sentinel_process_snapshots(timestamp);
CREATE INDEX idx_sps_name ON sentinel_process_snapshots(name);

CREATE TABLE IF NOT EXISTS sentinel_network_snapshots (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    proto TEXT NOT NULL,
    local_addr TEXT,
    local_port INTEGER,
    remote_addr TEXT,
    remote_port INTEGER,
    state TEXT,
    pid INTEGER,
    process_name TEXT
);
CREATE INDEX idx_sns_timestamp ON sentinel_network_snapshots(timestamp);
CREATE INDEX idx_sns_remote ON sentinel_network_snapshots(remote_addr);

CREATE TABLE IF NOT EXISTS sentinel_system_metrics (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    cpu_pct REAL,
    mem_pct REAL,
    mem_used_mb REAL,
    disk_pct REAL,
    disk_used_gb REAL,
    net_bytes_sent INTEGER,
    net_bytes_recv INTEGER,
    load_1m REAL
);
CREATE INDEX idx_ssm_timestamp ON sentinel_system_metrics(timestamp);
```

`015_create_sentinel_file_hashes.sql`
```sql
CREATE TABLE IF NOT EXISTS sentinel_file_hashes (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    path TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    size_bytes INTEGER,
    mtime TEXT,
    uid INTEGER,
    gid INTEGER,
    mode INTEGER
);
CREATE INDEX idx_sfh_timestamp ON sentinel_file_hashes(timestamp);
CREATE INDEX idx_sfh_path ON sentinel_file_hashes(path);
```

`016_create_sentinel_auth_events.sql`
```sql
CREATE TABLE IF NOT EXISTS sentinel_auth_events (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    event_type TEXT NOT NULL,
    user TEXT,
    source_ip TEXT,
    method TEXT,
    detail TEXT,
    severity TEXT DEFAULT 'info'
);
CREATE INDEX idx_sae_timestamp ON sentinel_auth_events(timestamp);
CREATE INDEX idx_sae_user ON sentinel_auth_events(user);
CREATE INDEX idx_sae_type ON sentinel_auth_events(event_type);
```

`017_create_sentinel_persistence.sql`
```sql
CREATE TABLE IF NOT EXISTS sentinel_persistence_entries (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    mechanism TEXT NOT NULL,
    path TEXT NOT NULL,
    content_hash TEXT,
    detail TEXT
);
CREATE INDEX idx_spe_timestamp ON sentinel_persistence_entries(timestamp);
CREATE INDEX idx_spe_mechanism ON sentinel_persistence_entries(mechanism);
CREATE INDEX idx_spe_path ON sentinel_persistence_entries(path);
```

`018_create_sentinel_baselines.sql`
```sql
CREATE TABLE IF NOT EXISTS sentinel_baselines (
    id TEXT PRIMARY KEY,
    category TEXT NOT NULL,
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    captured_at TEXT NOT NULL,
    UNIQUE(category, key)
);
CREATE INDEX idx_sb_category ON sentinel_baselines(category);
```

`019_create_sentinel_osint.sql`
```sql
CREATE TABLE IF NOT EXISTS sentinel_ioc_ips (
    ip TEXT NOT NULL,
    source TEXT NOT NULL,
    threat_type TEXT,
    confidence INTEGER DEFAULT 0,
    first_seen TEXT NOT NULL,
    last_updated TEXT NOT NULL,
    PRIMARY KEY (ip, source)
);
CREATE INDEX idx_sii_ip ON sentinel_ioc_ips(ip);

CREATE TABLE IF NOT EXISTS sentinel_ioc_domains (
    domain TEXT NOT NULL,
    source TEXT NOT NULL,
    threat_type TEXT,
    first_seen TEXT NOT NULL,
    last_updated TEXT NOT NULL,
    PRIMARY KEY (domain, source)
);

CREATE TABLE IF NOT EXISTS sentinel_ioc_hashes (
    sha256 TEXT NOT NULL,
    source TEXT NOT NULL,
    malware_family TEXT,
    first_seen TEXT NOT NULL,
    last_updated TEXT NOT NULL,
    PRIMARY KEY (sha256, source)
);

CREATE TABLE IF NOT EXISTS sentinel_ioc_urls (
    url TEXT NOT NULL,
    source TEXT NOT NULL,
    threat_type TEXT,
    first_seen TEXT NOT NULL,
    last_updated TEXT NOT NULL,
    PRIMARY KEY (url, source)
);

CREATE TABLE IF NOT EXISTS sentinel_ioc_cves (
    cve_id TEXT NOT NULL,
    vendor TEXT,
    product TEXT,
    severity TEXT,
    exploited INTEGER DEFAULT 0,
    source TEXT NOT NULL,
    last_updated TEXT NOT NULL,
    PRIMARY KEY (cve_id, source)
);

CREATE TABLE IF NOT EXISTS sentinel_reputation_cache (
    indicator TEXT NOT NULL,
    indicator_type TEXT NOT NULL,
    source TEXT NOT NULL,
    result_json TEXT,
    queried_at TEXT NOT NULL,
    ttl_hours INTEGER DEFAULT 24,
    PRIMARY KEY (indicator, source)
);
CREATE INDEX idx_src_indicator ON sentinel_reputation_cache(indicator);

CREATE TABLE IF NOT EXISTS sentinel_vuln_matches (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    package TEXT NOT NULL,
    version TEXT NOT NULL,
    cve_id TEXT NOT NULL,
    severity TEXT,
    source TEXT NOT NULL
);
CREATE INDEX idx_svm_package ON sentinel_vuln_matches(package);
CREATE INDEX idx_svm_cve ON sentinel_vuln_matches(cve_id);
```

### Phase 1C: Python OSINT Module

**New module:** `python/netsec/sentinel/`

```
python/netsec/sentinel/
├── __init__.py
├── feed_manager.py         # Bulk feed download + IOC table loading
├── reputation.py           # Cached API lookups (AbuseIPDB, VT, GN, OTX)
├── vuln_scanner.py         # dpkg inventory → OSV.dev batch + CISA KEV
├── dnsbl.py                # DNS blacklist lookups via socket
├── cert_monitor.py         # crt.sh certificate transparency
└── correlator.py           # Match local state against IOC DB
```

**feed_manager.py:**
- `async def update_all_feeds(db) -> FeedUpdateResult`
- Downloads and parses:
  - ThreatFox IOCs (POST to API, JSON)
  - URLhaus online CSV
  - Feodo Tracker IP blocklist CSV
  - SSLBL IP blacklist CSV
  - CISA KEV JSON
- Upserts rows into `sentinel_ioc_*` tables
- Tracks last update time in `sentinel_baselines` table
- Skips download if feed was updated within `feed_refresh_hours`

**reputation.py:**
- `async def check_ip(ip, db, config) -> ReputationResult`
- Tiered lookup: cache → local IOC tables → DNSBL → AbuseIPDB → GreyNoise → VT
- Caches results in `sentinel_reputation_cache` with configurable TTL
- Rate limiter per API (simple token bucket: `last_call_time + min_interval`)
- Skips RFC 1918 / loopback / multicast / known-good CIDRs
- Returns: `{ip, malicious: bool, confidence: 0-100, sources: [...], details: {...}}`

**vuln_scanner.py:**
- `async def scan_packages(db) -> list[VulnMatch]`
- Runs `dpkg-query -W -f '${Package}\t${Version}\n'`
- Batches packages into OSV.dev `/v1/querybatch` requests (ecosystem: "Debian", max 1000/batch)
- Cross-references CVE matches against `sentinel_ioc_cves` (CISA KEV)
- Optionally enriches with NVD CVSS scores if API key configured
- Stores results in `sentinel_vuln_matches`

**dnsbl.py:**
- `async def check_ip_dnsbl(ip) -> DnsblResult`
- Reverses octets, queries 4 DNSBLs via `socket.getaddrinfo()`
  - `zen.spamhaus.org`, `b.barracudacentral.org`, `dnsbl.sorbs.net`, `bl.spamcop.net`
- Returns number of lists the IP appears on + which ones
- Self-throttles: 1 query per 3 seconds

**correlator.py:**
- `async def correlate(db) -> list[NormalizedAlert]`
- Reads latest `sentinel_network_snapshots` → checks all remote IPs against IOC DB + DNSBL
- Reads latest `sentinel_file_hashes` → checks SHA-256 against `sentinel_ioc_hashes`
- Reads `sentinel_vuln_matches` → generates alerts for CISA KEV matches
- Returns `NormalizedAlert` objects ready for the existing pipeline

### Phase 1D: Python Adapter

**New file:** `python/netsec/adapters/sentinel.py`

Implements `BaseAdapter` with:
- `tool_info()` → `ToolInfo(name="sentinel", category=ToolCategory.HOST_MONITOR, ...)`
- `detect()` → always True (no external binary needed)
- `health_check()` → checks DB connectivity and last collection timestamp
- `execute(task, params)` → dispatches to:
  - `"collect"` → run all Rust collectors via PyO3 or subprocess
  - `"feeds_update"` → `feed_manager.update_all_feeds()`
  - `"vuln_scan"` → `vuln_scanner.scan_packages()`
  - `"correlate"` → `correlator.correlate()`
  - `"baseline_capture"` → snapshot current state as known-good
  - `"report"` → generate summary of last 24h
- `parse_output()` → JSON passthrough

Register in `python/netsec/adapters/registry.py`.

### Phase 1E: API Router

**New file:** `python/netsec/api/routers/sentinel.py`

```python
router = APIRouter(prefix="/api/sentinel", tags=["sentinel"])

GET  /status           # Last run times, IOC counts, alert count
GET  /snapshots        # Latest process/network/metric snapshots
GET  /file-hashes      # Current file integrity state
GET  /persistence      # Current persistence entries
GET  /auth-events      # Recent auth events (paginated)
GET  /baselines        # Current baselines
POST /baselines        # Capture new baseline
GET  /osint/feeds      # Feed update status + IOC counts per source
POST /osint/feeds      # Force feed refresh
GET  /osint/reputation/{ip}  # Single IP reputation lookup
GET  /vulns            # Vulnerable packages
POST /vulns/scan       # Trigger vulnerability scan
POST /correlate        # Run full correlation now
GET  /report           # 24h summary report
```

Register in `python/netsec/api/routers/__init__.py`.

### Phase 1F: Scheduler Jobs

Register in NetSec's existing scheduler:

| Job Name | Trigger | Action |
|---|---|---|
| `sentinel_collect` | interval 300s (5 min) | Run all collectors |
| `sentinel_feeds` | interval 21600s (6 hr) | Update OSINT feeds |
| `sentinel_correlate` | interval 600s (10 min) | Run correlator |
| `sentinel_vuln_scan` | cron `0 4 * * *` (4 AM daily) | Package vuln scan |
| `sentinel_prune` | cron `0 3 * * *` (3 AM daily) | Delete rows > 30 days |

### Phase 1G: Config Addition

Add to `config/default.toml`:

```toml
[sentinel]
enabled = true
retention_days = 30
collect_interval_secs = 300

[sentinel.process]
root_allowlist = [
    "systemd", "cron", "sshd", "NetworkManager", "thermald",
    "irqbalance", "rsyslogd", "cupsd", "lightdm", "Xorg",
    "cinnamon", "polkitd", "udisksd", "upowerd", "dbus-daemon",
    "ollama", "uvicorn", "postgres", "redis-server"
]

[sentinel.network]
known_listeners = [22, 53, 631, 3001, 3002, 5110, 5432, 5433, 6379, 8080, 8420, 11434, 18789, 18791, 18792]

[sentinel.files]
watch_paths = [
    "/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow",
    "/etc/sudoers", "/etc/hosts", "/etc/resolv.conf",
    "/etc/ssh/sshd_config", "/etc/pam.d/common-auth",
    "/etc/ld.so.preload", "/etc/ld.so.conf",
    "/etc/rc.local", "/etc/crontab", "/etc/environment",
    "/etc/profile", "/etc/bash.bashrc"
]
scan_tmp = true
scan_dev_shm = true

[sentinel.osint]
feed_refresh_hours = 6
reputation_cache_ttl_hours = 24
skip_private_ips = true

[sentinel.osint.feeds]
enable_threatfox = true
enable_urlhaus = true
enable_feodo = true
enable_sslbl = true
enable_cisa_kev = true
enable_osv = true

[sentinel.osint.apis]
abuseipdb_key = ""
virustotal_key = ""
greynoise_key = ""
otx_key = ""
nvd_key = ""

[sentinel.osint.dnsbl]
enabled = true
lists = ["zen.spamhaus.org", "b.barracudacentral.org", "dnsbl.sorbs.net", "bl.spamcop.net"]

[sentinel.osint.vuln]
enable_osv = true
scan_interval_hours = 24
```

---

## Step 2: Intelligence Layer (Detection Algorithms)

All analyzers live in `crates/netsec-sentinel/src/analyzers/`. Each implements
the existing `ThreatDetector` trait so they plug directly into `ThreatEngine`.
They read collector data from the sentinel DB tables and emit `NormalizedAlert`
objects into the existing pipeline.

### Phase 2A: Process Analyzers

**`analyzers/process_tree.rs`** — Parent-Child Anomaly Detection
- Build frequency table of `(parent_name, child_name)` from `sentinel_process_snapshots`
- Maintain known-good allowlist from config
- Flag pairs never seen during baseline period
- High-severity rules: shell spawned by web server, script interpreter from /tmp
- Implements `ThreatDetector` trait
- MITRE: T1059

**`analyzers/masquerade.rs`** — Process Masquerading Detection
- For each process, read `/proc/[pid]/exe` real path vs `cmdline[0]`
- Flag mismatches (exe ≠ argv[0])
- Flag fake kernel threads: bracket-prefixed names with an exe link
- MITRE: T1036

**`analyzers/fileless.rs`** — Fileless Execution Detection
- Scan `/proc/*/exe` symlinks for `memfd:` or `(deleted)`
- `memfd_create()` payloads → immediate critical alert
- Deleted binary still running → high alert
- MITRE: T1620

**`analyzers/reverse_shell.rs`** — Reverse Shell Detection
- For each shell process (bash/sh/zsh/dash/fish), read `/proc/[pid]/fd/{0,1,2}`
- If stdin or stdout points to `socket:[inode]` instead of `/dev/pts/N` → alert
- Also regex match cmdline for: `/dev/tcp/`, `mkfifo.*nc`, `socat exec`, `pty.spawn`
- MITRE: T1059

### Phase 2B: Resource & Network Analyzers

**`analyzers/resource_spike.rs`** — EWMA Anomaly Detection
- Per-process EWMA for CPU and memory: `S_t = 0.2 * x_t + 0.8 * S_{t-1}`
- Alert when `x_t > S_t + 3σ` (rolling σ from last 24h of `sentinel_system_metrics`)
- Cryptominer heuristic: sustained >80% CPU by single non-allowlisted process
- System-level: Holt-Winters triple exponential smoothing for CPU/mem/net
  - `L_t = α(x_t - S_{t-p}) + (1-α)(L_{t-1} + T_{t-1})`
  - Period p = 288 (5-min intervals over 24h)
  - Alert when actual > predicted + 3σ
- MITRE: T1496

**`analyzers/beaconing.rs`** — FFT-Based Beaconing Detection
- Enhances existing `entropy.rs` beaconing with proper FFT
- For each unique `(remote_addr, remote_port)` in 24h window of `sentinel_network_snapshots`:
  - Compute inter-arrival times `Δt_i`
  - Coefficient of variation: `CV = σ(Δt) / μ(Δt)` — CV < 0.15 = periodic candidate
  - Apply FFT to inter-arrival series, find dominant frequency peak
  - Confirm beaconing even with 30-40% jitter
- Depends on: no new crate deps (FFT is ~50 lines of Rust for real-valued DFT at this scale)
- MITRE: T1071

**`analyzers/dns_entropy.rs`** — DNS Tunneling Detection
- Parse DNS queries from syslog or systemd-resolved journal
- Shannon entropy per domain (reuse `EntropyDetector::shannon_entropy`)
- Normal: H ≈ 3.0–3.5. DGA/tunneling: H > 3.8
- Flag: subdomain labels > 24 chars, high query volume to single domain
- MITRE: T1071.004

### Phase 2C: File System Analyzers

**`analyzers/file_drift.rs`** — File Integrity + SUID Drift
- Compare current `sentinel_file_hashes` against `sentinel_baselines`
- Tiered alerting:
  - Tier 1 (critical): /etc/passwd, /etc/shadow, /etc/sudoers, /etc/ld.so.preload, authorized_keys
  - Tier 2 (high): sshd_config, cron files, systemd units, shell profiles
  - Tier 3 (medium): everything else on watchlist
- SUID/SGID: periodic `find / -perm -4000`, compare against baseline set
- Cross-ref new SUID binaries against GTFOBins list (~50 dangerous binaries)
- Capabilities: `getcap` baseline comparison
- MITRE: T1548.001

**`analyzers/timestomp.rs`** — Timestomping Detection
- For monitored files: compare mtime vs ctime (from stat)
- `mtime < ctime` = timestomped (kernel sets ctime, cannot be faked without raw disk)
- MITRE: T1070.006

**`analyzers/persistence_drift.rs`** — Persistence Mechanism Drift
- Compare current `sentinel_persistence_entries` hashes against baselines
- Content analysis on new entries:
  - Cron: flag `curl|sh`, `wget|bash`, references to /tmp or /dev/shm
  - Systemd: flag ExecStart pointing to temp dirs or base64 commands
  - Profiles: flag LD_PRELOAD additions, eval, nohup, backgrounded processes
  - APT hooks: flag Pre-Invoke/Post-Invoke with shell commands
  - XDG: flag suspicious Exec= lines
- MITRE: T1053, T1543, T1546, T1547, T1574

**`analyzers/suspicious_temp.rs`** — Temp Directory Scanner
- Scan /tmp, /dev/shm, /var/tmp for:
  - Executable files (mode & 0o111)
  - ELF binaries (magic bytes \x7fELF)
  - Script shebangs (#!/)
  - Root-owned files in user-writable dirs
  - Hidden (dot-prefixed) files
- MITRE: T1074

### Phase 2D: Auth Analyzers

**`analyzers/brute_force.rs`** — Brute Force + Password Spray
- Sliding window over `sentinel_auth_events`: count failed auths per (user, source_ip) in 5 min
- ≥3 failures → warning, ≥10 → critical
- Password spray: ≥3 different users failing from same IP in 5 min
- MITRE: T1110

**`analyzers/log_tamper.rs`** — Log Tampering Detection
- Monitor sizes of: auth.log, syslog, wtmp, btmp, lastlog
- Alert if any log shrinks or becomes 0 bytes
- Detect timestamp gaps in sequential log entries
- Flag bash_history becoming empty, symlinked to /dev/null, or HISTFILE unset
- MITRE: T1070.002

### Phase 2E: OSINT Correlation Analyzer

**`python/netsec/sentinel/correlator.py`** (enhanced from Step 1)
- Match network connections against IOC DB → generate NormalizedAlerts
- Match file hashes against IOC DB → generate NormalizedAlerts
- Match vulnerable packages against CISA KEV → generate NormalizedAlerts
- Risk scoring per match:
  - CISA KEV match: risk +90
  - abuse.ch match: risk +70
  - Listed in ≥2 DNSBLs: risk +60
  - AbuseIPDB confidence ≥80: risk +50
  - GreyNoise `malicious`: risk +40
  - VirusTotal ≥5 detections: risk +50

### Phase 2F: Risk Accumulation Engine

**`analyzers/risk_accumulator.rs`** — Splunk RBA Model
- New table: `sentinel_risk_scores`
  ```sql
  CREATE TABLE sentinel_risk_scores (
      entity TEXT NOT NULL,
      entity_type TEXT NOT NULL,  -- "process", "ip", "user", "file"
      risk_score INTEGER NOT NULL,
      source_alert_id TEXT,
      mitre_id TEXT,
      timestamp TEXT NOT NULL
  );
  ```
- Each alert adds risk_score to its entity (process name, IP, user)
- Base score by tier: Tier 1 = 80-100, Tier 2 = 40-79, Tier 3 = 10-39
- Modifiers: MITRE Execution/Initial Access = 1.5x, after-hours = 1.3x
- Rolling 24h window accumulation
- When entity score crosses threshold (default 150) → emit **Risk Notable**
  (a correlated super-alert that groups the contributing alerts)
- Alert fatigue reduction:
  - Dedup: identical alerts within 15 min → collapse with count
  - Suppression: acknowledged alerts suppressed for configurable window
  - Adaptive: rules firing >20/day with no ack → auto-raise threshold 10%

---

## Implementation Order

| Order | Phase | What | Depends On | New Files |
|---|---|---|---|---|
| 1 | 1A | `netsec-sentinel` crate + collectors | netsec-models | ~8 Rust files |
| 2 | 1B | DB migrations | netsec-db | 6 SQL files |
| 3 | 1C | Python OSINT module | migrations | 6 Python files |
| 4 | 1D | Sentinel adapter | OSINT module | 1 Python file |
| 5 | 1E | API router | adapter | 1 Python file |
| 6 | 1F | Scheduler jobs | adapter + router | config only |
| 7 | 1G | Config section | — | config only |
| 8 | 2A | Process analyzers (4 detectors) | collectors | 4 Rust files |
| 9 | 2B | Resource + network analyzers (3) | collectors + metrics | 3 Rust files |
| 10 | 2C | File system analyzers (4) | file_integrity + persistence | 4 Rust files |
| 11 | 2D | Auth analyzers (2) | auth collector | 2 Rust files |
| 12 | 2E | OSINT correlator enhancement | OSINT module + collectors | update 1 file |
| 13 | 2F | Risk accumulation engine | all analyzers | 1 Rust + 1 SQL |

**Test target:** Each phase ships with full unit tests following NetSec's
existing pattern (272 Rust tests currently passing). Each analyzer gets ≥5 tests.
Expected new test count: ~120-150.

**New dependencies:** `sha2`, `walkdir` (Rust). Zero new Python deps beyond
`requests` (already available).

---

## File Summary

### New Rust Files (crates/netsec-sentinel/)
```
src/lib.rs
src/config.rs
src/collectors/mod.rs
src/collectors/process.rs
src/collectors/network.rs
src/collectors/file_integrity.rs
src/collectors/auth.rs
src/collectors/persistence.rs
src/collectors/metrics.rs
src/analyzers/mod.rs
src/analyzers/process_tree.rs
src/analyzers/masquerade.rs
src/analyzers/fileless.rs
src/analyzers/reverse_shell.rs
src/analyzers/resource_spike.rs
src/analyzers/beaconing.rs
src/analyzers/dns_entropy.rs
src/analyzers/file_drift.rs
src/analyzers/timestomp.rs
src/analyzers/persistence_drift.rs
src/analyzers/suspicious_temp.rs
src/analyzers/brute_force.rs
src/analyzers/log_tamper.rs
src/analyzers/risk_accumulator.rs
```

### New Python Files (python/netsec/sentinel/)
```
__init__.py
feed_manager.py
reputation.py
vuln_scanner.py
dnsbl.py
cert_monitor.py
correlator.py
```

### New Python Files (existing directories)
```
python/netsec/adapters/sentinel.py
python/netsec/api/routers/sentinel.py
```

### New SQL Migrations
```
migrations/sql/014_create_sentinel_snapshots.sql
migrations/sql/015_create_sentinel_file_hashes.sql
migrations/sql/016_create_sentinel_auth_events.sql
migrations/sql/017_create_sentinel_persistence.sql
migrations/sql/018_create_sentinel_baselines.sql
migrations/sql/019_create_sentinel_osint.sql
migrations/sql/020_create_sentinel_risk_scores.sql  (Phase 2F)
```

### Modified Files
```
Cargo.toml                              (add netsec-sentinel to workspace)
crates/netsec-models/src/lib.rs         (add pub mod sentinel)
crates/netsec-models/src/sentinel.rs    (CollectedEvent struct)
crates/netsec-threat/src/lib.rs         (register sentinel analyzers in ThreatEngine)
python/netsec/adapters/registry.py      (register SentinelAdapter)
python/netsec/api/routers/__init__.py   (register sentinel router)
config/default.toml                     (add [sentinel] section)
```

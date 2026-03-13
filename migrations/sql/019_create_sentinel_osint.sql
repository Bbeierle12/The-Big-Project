-- Sentinel OSINT IOC and enrichment tables
CREATE TABLE IF NOT EXISTS sentinel_ioc_ips (
    ip TEXT NOT NULL,
    source TEXT NOT NULL,
    threat_type TEXT NOT NULL DEFAULT '',
    confidence INTEGER NOT NULL DEFAULT 0,
    first_seen TEXT NOT NULL,
    last_updated TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (ip, source)
);
CREATE INDEX IF NOT EXISTS idx_sentinel_ioc_ips_ip ON sentinel_ioc_ips(ip);

CREATE TABLE IF NOT EXISTS sentinel_ioc_domains (
    domain TEXT NOT NULL,
    source TEXT NOT NULL,
    threat_type TEXT NOT NULL DEFAULT '',
    first_seen TEXT NOT NULL,
    last_updated TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (domain, source)
);
CREATE INDEX IF NOT EXISTS idx_sentinel_ioc_domains_domain ON sentinel_ioc_domains(domain);

CREATE TABLE IF NOT EXISTS sentinel_ioc_hashes (
    sha256 TEXT NOT NULL,
    md5 TEXT NOT NULL DEFAULT '',
    source TEXT NOT NULL,
    malware_family TEXT NOT NULL DEFAULT '',
    first_seen TEXT NOT NULL,
    last_updated TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (sha256, source)
);
CREATE INDEX IF NOT EXISTS idx_sentinel_ioc_hashes_sha256 ON sentinel_ioc_hashes(sha256);

CREATE TABLE IF NOT EXISTS sentinel_ioc_urls (
    url TEXT NOT NULL,
    source TEXT NOT NULL,
    threat_type TEXT NOT NULL DEFAULT '',
    first_seen TEXT NOT NULL,
    last_updated TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (url, source)
);
CREATE INDEX IF NOT EXISTS idx_sentinel_ioc_urls_url ON sentinel_ioc_urls(url);

CREATE TABLE IF NOT EXISTS sentinel_ioc_cves (
    cve_id TEXT NOT NULL,
    vendor TEXT NOT NULL DEFAULT '',
    product TEXT NOT NULL DEFAULT '',
    severity TEXT NOT NULL DEFAULT '',
    exploited INTEGER NOT NULL DEFAULT 0,
    source TEXT NOT NULL,
    last_updated TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (cve_id, source)
);
CREATE INDEX IF NOT EXISTS idx_sentinel_ioc_cves_cve_id ON sentinel_ioc_cves(cve_id);

CREATE TABLE IF NOT EXISTS sentinel_ioc_ssl (
    fingerprint TEXT NOT NULL,
    source TEXT NOT NULL,
    reason TEXT NOT NULL DEFAULT '',
    last_updated TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (fingerprint, source)
);
CREATE INDEX IF NOT EXISTS idx_sentinel_ioc_ssl_fingerprint ON sentinel_ioc_ssl(fingerprint);

CREATE TABLE IF NOT EXISTS sentinel_reputation_cache (
    indicator TEXT NOT NULL,
    indicator_type TEXT NOT NULL,
    source TEXT NOT NULL,
    result_json TEXT NOT NULL DEFAULT '',
    queried_at TEXT NOT NULL,
    ttl_hours INTEGER NOT NULL DEFAULT 24,
    PRIMARY KEY (indicator, indicator_type, source)
);
CREATE INDEX IF NOT EXISTS idx_sentinel_reputation_cache_indicator ON sentinel_reputation_cache(indicator, indicator_type);

CREATE TABLE IF NOT EXISTS sentinel_vuln_matches (
    id TEXT PRIMARY KEY NOT NULL,
    timestamp TEXT NOT NULL,
    package TEXT NOT NULL,
    version TEXT NOT NULL,
    cve_id TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT '',
    source TEXT NOT NULL,
    exploited INTEGER NOT NULL DEFAULT 0,
    detail TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_sentinel_vuln_matches_timestamp ON sentinel_vuln_matches(timestamp);
CREATE INDEX IF NOT EXISTS idx_sentinel_vuln_matches_package ON sentinel_vuln_matches(package);
CREATE INDEX IF NOT EXISTS idx_sentinel_vuln_matches_cve ON sentinel_vuln_matches(cve_id);

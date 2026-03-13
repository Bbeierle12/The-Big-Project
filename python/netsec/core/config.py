"""Layered TOML configuration with Pydantic models."""
from __future__ import annotations

import sys
from functools import lru_cache
from pathlib import Path
from typing import Any

from pydantic import BaseModel

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib


class ServerConfig(BaseModel):
    host: str = "127.0.0.1"
    port: int = 8420
    reload: bool = False
    workers: int = 1


class DatabaseConfig(BaseModel):
    url: str = "sqlite+aiosqlite:///./netsec.db"
    echo: bool = False


class LoggingConfig(BaseModel):
    level: str = "INFO"
    format: str = "json"


class SchedulerConfig(BaseModel):
    enabled: bool = True
    timezone: str = "UTC"


class AuthConfig(BaseModel):
    enabled: bool = False
    api_key: str = ""


class DispatchConfig(BaseModel):
    webhook_url: str = ""
    email_enabled: bool = False
    email_smtp_host: str = ""
    email_smtp_port: int = 587
    email_from: str = ""
    email_to: str = ""


class AlertsConfig(BaseModel):
    dedup_window_seconds: int = 300
    max_alerts_per_minute: int = 100
    dispatch: DispatchConfig = DispatchConfig()


class ToolsConfig(BaseModel):
    scan_timeout: int = 300
    max_concurrent_scans: int = 3


class SentinelProcessConfig(BaseModel):
    root_allowlist: list[str] = [
        "systemd",
        "cron",
        "sshd",
        "NetworkManager",
        "thermald",
        "irqbalance",
        "rsyslogd",
        "cupsd",
        "lightdm",
        "Xorg",
        "cinnamon",
        "polkitd",
        "udisksd",
        "upowerd",
        "dbus-daemon",
        "ollama",
        "uvicorn",
        "postgres",
        "redis-server",
    ]


class SentinelNetworkConfig(BaseModel):
    known_listeners: list[int] = [22, 53, 631, 3001, 3002, 5110, 5432, 5433, 6379, 8080, 8420, 11434, 18789, 18791, 18792]


class SentinelFilesConfig(BaseModel):
    watch_paths: list[str] = [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/group",
        "/etc/gshadow",
        "/etc/sudoers",
        "/etc/hosts",
        "/etc/resolv.conf",
        "/etc/ssh/sshd_config",
        "/etc/pam.d/common-auth",
        "/etc/ld.so.preload",
        "/etc/ld.so.conf",
        "/etc/rc.local",
        "/etc/crontab",
        "/etc/environment",
        "/etc/profile",
        "/etc/bash.bashrc",
    ]
    scan_tmp: bool = True
    scan_dev_shm: bool = True


class SentinelOsintFeedsConfig(BaseModel):
    enable_threatfox: bool = False
    enable_urlhaus: bool = True
    enable_feodo: bool = True
    enable_sslbl: bool = True
    enable_cisa_kev: bool = True
    enable_osv: bool = True


class SentinelOsintApisConfig(BaseModel):
    threatfox_auth_key: str = ""
    abuseipdb_key: str = ""
    virustotal_key: str = ""
    greynoise_key: str = ""
    otx_key: str = ""
    nvd_key: str = ""


class SentinelOsintDnsblConfig(BaseModel):
    enabled: bool = True
    lists: list[str] = [
        "zen.spamhaus.org",
        "b.barracudacentral.org",
        "dnsbl.sorbs.net",
        "bl.spamcop.net",
    ]


class SentinelOsintDomainsConfig(BaseModel):
    monitor: list[str] = []


class SentinelOsintVulnConfig(BaseModel):
    enable_osv: bool = True
    scan_interval_hours: int = 24


class SentinelOsintConfig(BaseModel):
    feed_refresh_hours: int = 6
    reputation_cache_ttl_hours: int = 24
    skip_private_ips: bool = True
    known_good_cidrs: list[str] = [
        "127.0.0.0/8",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "100.64.0.0/10",
    ]
    extra_ip_feeds: list[str] = []
    extra_domain_feeds: list[str] = []
    extra_hash_feeds: list[str] = []
    cache_dir: str = "data/sentinel"
    feeds: SentinelOsintFeedsConfig = SentinelOsintFeedsConfig()
    apis: SentinelOsintApisConfig = SentinelOsintApisConfig()
    dnsbl: SentinelOsintDnsblConfig = SentinelOsintDnsblConfig()
    domains: SentinelOsintDomainsConfig = SentinelOsintDomainsConfig()
    vuln: SentinelOsintVulnConfig = SentinelOsintVulnConfig()


class SentinelConfig(BaseModel):
    enabled: bool = True
    retention_days: int = 30
    collect_interval_secs: int = 300
    process: SentinelProcessConfig = SentinelProcessConfig()
    network: SentinelNetworkConfig = SentinelNetworkConfig()
    files: SentinelFilesConfig = SentinelFilesConfig()
    osint: SentinelOsintConfig = SentinelOsintConfig()


class Settings(BaseModel):
    server: ServerConfig = ServerConfig()
    database: DatabaseConfig = DatabaseConfig()
    logging: LoggingConfig = LoggingConfig()
    scheduler: SchedulerConfig = SchedulerConfig()
    auth: AuthConfig = AuthConfig()
    alerts: AlertsConfig = AlertsConfig()
    tools: ToolsConfig = ToolsConfig()
    sentinel: SentinelConfig = SentinelConfig()


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """Deep merge override into base dict."""
    result = base.copy()
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def load_settings(config_dir: Path | None = None) -> Settings:
    """Load settings from default.toml, overlay with local.toml if present."""
    if config_dir is None:
        config_dir = Path(__file__).resolve().parents[3] / "config"

    data: dict[str, Any] = {}

    default_path = config_dir / "default.toml"
    if default_path.exists():
        with open(default_path, "rb") as f:
            data = tomllib.load(f)

    local_path = config_dir / "local.toml"
    if local_path.exists():
        with open(local_path, "rb") as f:
            local_data = tomllib.load(f)
        data = _deep_merge(data, local_data)

    return Settings.model_validate(data)


@lru_cache
def get_settings() -> Settings:
    """Cached settings singleton."""
    return load_settings()

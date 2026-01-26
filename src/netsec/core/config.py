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


class Settings(BaseModel):
    server: ServerConfig = ServerConfig()
    database: DatabaseConfig = DatabaseConfig()
    logging: LoggingConfig = LoggingConfig()
    scheduler: SchedulerConfig = SchedulerConfig()
    auth: AuthConfig = AuthConfig()
    alerts: AlertsConfig = AlertsConfig()
    tools: ToolsConfig = ToolsConfig()


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

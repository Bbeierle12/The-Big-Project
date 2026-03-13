"""Sentinel OSINT integration helpers for NetSec."""
from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

from netsec.core.config import get_settings

_SCHEMA_FILES = [
    "014_create_sentinel_snapshots.sql",
    "015_create_sentinel_file_hashes.sql",
    "016_create_sentinel_auth_events.sql",
    "017_create_sentinel_persistence.sql",
    "018_create_sentinel_baselines.sql",
    "019_create_sentinel_osint.sql",
]
_SCHEMA_READY = False


def repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def database_path(settings: Any | None = None) -> str:
    resolved_settings = settings or get_settings()
    url = resolved_settings.database.url
    if url == ":memory:":
        return url
    prefixes = ("sqlite+aiosqlite:///", "sqlite:///")
    for prefix in prefixes:
        if url.startswith(prefix):
            raw_path = url[len(prefix):]
            path = Path(raw_path)
            if not path.is_absolute():
                path = (repo_root() / path).resolve()
            path.parent.mkdir(parents=True, exist_ok=True)
            return str(path)
    raise RuntimeError(f"Sentinel currently supports only SQLite URLs, got: {url}")


def cache_dir(settings: Any | None = None) -> Path:
    resolved_settings = settings or get_settings()
    configured = Path(resolved_settings.sentinel.osint.cache_dir)
    directory = configured if configured.is_absolute() else (repo_root() / configured).resolve()
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def connect(settings: Any | None = None) -> sqlite3.Connection:
    connection = sqlite3.connect(database_path(settings), timeout=30.0)
    connection.row_factory = sqlite3.Row
    return connection


def ensure_schema(settings: Any | None = None) -> dict[str, Any]:
    global _SCHEMA_READY
    if _SCHEMA_READY:
        return {"ready": True, "db_path": database_path(settings)}

    with connect(settings) as connection:
        for filename in _SCHEMA_FILES:
            sql = (repo_root() / "migrations" / "sql" / filename).read_text(encoding="utf-8")
            connection.executescript(sql)

    _SCHEMA_READY = True
    return {"ready": True, "db_path": database_path(settings), "migrations": list(_SCHEMA_FILES)}


def utcnow() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def row_dicts(rows: list[sqlite3.Row]) -> list[dict[str, Any]]:
    return [dict(row) for row in rows]


async def status(settings: Any | None = None) -> dict[str, Any]:
    from netsec.sentinel.feed_manager import feeds_status
    from netsec.sentinel.vuln_scanner import latest_matches

    ensure_schema(settings)
    with connect(settings) as connection:
        timestamps = {
            "process": connection.execute("SELECT MAX(timestamp) AS ts FROM sentinel_process_snapshots").fetchone()["ts"],
            "network": connection.execute("SELECT MAX(timestamp) AS ts FROM sentinel_network_snapshots").fetchone()["ts"],
            "file_hashes": connection.execute("SELECT MAX(timestamp) AS ts FROM sentinel_file_hashes").fetchone()["ts"],
            "auth": connection.execute("SELECT MAX(timestamp) AS ts FROM sentinel_auth_events").fetchone()["ts"],
            "persistence": connection.execute("SELECT MAX(timestamp) AS ts FROM sentinel_persistence_entries").fetchone()["ts"],
            "metrics": connection.execute("SELECT MAX(timestamp) AS ts FROM sentinel_system_metrics").fetchone()["ts"],
        }
    vuln_rows = await latest_matches(settings=settings, limit=5)
    return {
        "enabled": (settings or get_settings()).sentinel.enabled,
        "db_path": database_path(settings),
        "snapshots": timestamps,
        "feeds": await feeds_status(settings=settings),
        "recent_vulns": vuln_rows,
    }

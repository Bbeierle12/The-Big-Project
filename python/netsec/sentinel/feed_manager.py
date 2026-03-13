"""Bulk threat feed ingestion for Sentinel."""
from __future__ import annotations

import csv
import io
import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx

from netsec.core.config import get_settings
from netsec.sentinel import cache_dir, connect, ensure_schema, row_dicts, utcnow

THREATFOX_API = "https://threatfox-api.abuse.ch/api/v1/"
URLHAUS_CSV = "https://urlhaus.abuse.ch/downloads/csv_online/"
FEODO_CSV = "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"
SSLBL_CANDIDATES = [
    "https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv",
    "https://sslbl.abuse.ch/blacklists/ja3_fingerprints.csv",
    "https://sslbl.abuse.ch/blacklist/sslipblacklist.csv",
]
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

IOC_TABLES = (
    "sentinel_ioc_ips",
    "sentinel_ioc_domains",
    "sentinel_ioc_hashes",
    "sentinel_ioc_urls",
    "sentinel_ioc_cves",
    "sentinel_ioc_ssl",
)


def _feeds_dir(settings: Any | None = None) -> Path:
    path = cache_dir(settings) / "feeds"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _metadata_path(settings: Any | None = None) -> Path:
    return _feeds_dir(settings) / "last_updated.json"


def _load_metadata(settings: Any | None = None) -> dict[str, Any]:
    path = _metadata_path(settings)
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}


def _save_metadata(metadata: dict[str, Any], settings: Any | None = None) -> None:
    _metadata_path(settings).write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _filter_lines(text: str) -> list[str]:
    return [line for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")]


def _csv_dict_rows(text: str) -> list[dict[str, str]]:
    header = ""
    lines: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("#"):
            candidate = stripped.lstrip("#").strip()
            if candidate.count(",") >= 2:
                header = candidate
            continue
        lines.append(line)
    if header:
        lines.insert(0, header)
    if not lines:
        return []
    reader = csv.DictReader(io.StringIO("\n".join(lines)))
    return [
        {str(key).strip().lower(): str(value or "").strip() for key, value in row.items() if key is not None}
        for row in reader
    ]


def _dedupe_rows(rows: list[dict[str, Any]], *keys: str) -> list[dict[str, Any]]:
    deduped: dict[tuple[Any, ...], dict[str, Any]] = {}
    for row in rows:
        deduped[tuple(row[key] for key in keys)] = row
    return list(deduped.values())


def _replace_source_rows(connection: sqlite3.Connection, source: str, table_rows: dict[str, list[dict[str, Any]]]) -> None:
    for table in IOC_TABLES:
        connection.execute(f"DELETE FROM {table} WHERE source = ?", (source,))
    for table, rows in table_rows.items():
        if not rows:
            continue
        columns = list(rows[0].keys())
        placeholders = ", ".join("?" for _ in columns)
        values = [tuple(row[column] for column in columns) for row in rows]
        connection.executemany(
            f"INSERT INTO {table} ({', '.join(columns)}) VALUES ({placeholders})",
            values,
        )


def _counts(parsed: dict[str, list[dict[str, Any]]]) -> dict[str, int]:
    return {table: len(rows) for table, rows in parsed.items() if rows}


def _parse_urlhaus(text: str, now: str) -> dict[str, list[dict[str, Any]]]:
    rows = list(csv.reader(io.StringIO("\n".join(_filter_lines(text)))))
    url_rows: list[dict[str, Any]] = []
    domain_rows: list[dict[str, Any]] = []
    for row in rows:
        if len(row) < 6:
            continue
        url = row[2].strip()
        if not url:
            continue
        hostname = (urlparse(url).hostname or "").lower()
        first_seen = row[1].strip() or now
        threat_type = row[5].strip() or "malicious_url"
        detail = json.dumps(
            {
                "tags": row[6].strip() if len(row) > 6 else "",
                "reporter": row[8].strip() if len(row) > 8 else "",
            },
            sort_keys=True,
        )
        url_rows.append(
            {
                "url": url,
                "source": "urlhaus",
                "threat_type": threat_type,
                "first_seen": first_seen,
                "last_updated": now,
                "detail": detail,
            }
        )
        if hostname:
            domain_rows.append(
                {
                    "domain": hostname,
                    "source": "urlhaus",
                    "threat_type": threat_type,
                    "first_seen": first_seen,
                    "last_updated": now,
                    "detail": detail,
                }
            )
    return {
        "sentinel_ioc_urls": _dedupe_rows(url_rows, "url", "source"),
        "sentinel_ioc_domains": _dedupe_rows(domain_rows, "domain", "source"),
    }


def _parse_feodo(text: str, now: str) -> dict[str, list[dict[str, Any]]]:
    rows = _csv_dict_rows(text)
    ip_rows: list[dict[str, Any]] = []
    for row in rows:
        ip = row.get("dst_ip") or row.get("ip") or ""
        if not ip:
            continue
        ip_rows.append(
            {
                "ip": ip,
                "source": "feodo",
                "threat_type": row.get("malware", "botnet_c2") or "botnet_c2",
                "confidence": 90,
                "first_seen": row.get("first_seen_utc") or row.get("first_seen") or now,
                "last_updated": now,
                "detail": json.dumps(row, sort_keys=True),
            }
        )
    return {"sentinel_ioc_ips": _dedupe_rows(ip_rows, "ip", "source")}


def _parse_sslbl(text: str, now: str) -> dict[str, list[dict[str, Any]]]:
    rows = _csv_dict_rows(text)
    ip_rows: list[dict[str, Any]] = []
    ssl_rows: list[dict[str, Any]] = []
    for row in rows:
        ip = row.get("dst_ip") or row.get("ip") or row.get("host") or ""
        fingerprint = row.get("ja3_md5") or row.get("fingerprint") or row.get("ssl_sha1") or row.get("sha1_fingerprint") or ""
        reason = row.get("malware") or row.get("reason") or row.get("listingreason") or "malicious_ssl"
        detail = json.dumps(row, sort_keys=True)
        if ip:
            ip_rows.append(
                {
                    "ip": ip,
                    "source": "sslbl",
                    "threat_type": reason,
                    "confidence": 75,
                    "first_seen": row.get("listingdate") or row.get("firstseen") or row.get("first_seen") or now,
                    "last_updated": now,
                    "detail": detail,
                }
            )
        if fingerprint:
            ssl_rows.append(
                {
                    "fingerprint": fingerprint,
                    "source": "sslbl",
                    "reason": reason,
                    "last_updated": now,
                    "detail": detail,
                }
            )
    return {
        "sentinel_ioc_ips": _dedupe_rows(ip_rows, "ip", "source"),
        "sentinel_ioc_ssl": _dedupe_rows(ssl_rows, "fingerprint", "source"),
    }


def _parse_cisa_kev(text: str, now: str) -> dict[str, list[dict[str, Any]]]:
    payload = json.loads(text)
    rows: list[dict[str, Any]] = []
    for item in payload.get("vulnerabilities", []):
        cve_id = str(item.get("cveID") or "").strip()
        if not cve_id:
            continue
        rows.append(
            {
                "cve_id": cve_id,
                "vendor": str(item.get("vendorProject", "")),
                "product": str(item.get("product", "")),
                "severity": "KNOWN_EXPLOITED",
                "exploited": 1,
                "source": "cisa_kev",
                "last_updated": now,
                "detail": json.dumps(item, sort_keys=True),
            }
        )
    return {"sentinel_ioc_cves": _dedupe_rows(rows, "cve_id", "source")}


def _parse_threatfox(text: str, now: str) -> dict[str, list[dict[str, Any]]]:
    payload = json.loads(text)
    items = payload.get("data", []) if isinstance(payload, dict) else []
    ip_rows: list[dict[str, Any]] = []
    domain_rows: list[dict[str, Any]] = []
    hash_rows: list[dict[str, Any]] = []
    url_rows: list[dict[str, Any]] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        ioc = str(item.get("ioc") or "").strip()
        ioc_type = str(item.get("ioc_type") or "").strip().lower()
        first_seen = str(item.get("first_seen") or now)
        family = str(item.get("malware_printable") or item.get("malware") or "")
        detail = json.dumps(item, sort_keys=True)
        if not ioc:
            continue
        if "url" in ioc_type:
            url_rows.append(
                {
                    "url": ioc,
                    "source": "threatfox",
                    "threat_type": family or "malicious_url",
                    "first_seen": first_seen,
                    "last_updated": now,
                    "detail": detail,
                }
            )
            hostname = (urlparse(ioc).hostname or "").lower()
            if hostname:
                domain_rows.append(
                    {
                        "domain": hostname,
                        "source": "threatfox",
                        "threat_type": family or "malicious_domain",
                        "first_seen": first_seen,
                        "last_updated": now,
                        "detail": detail,
                    }
                )
        elif "domain" in ioc_type:
            domain_rows.append(
                {
                    "domain": ioc.lower(),
                    "source": "threatfox",
                    "threat_type": family or "malicious_domain",
                    "first_seen": first_seen,
                    "last_updated": now,
                    "detail": detail,
                }
            )
        elif "ip" in ioc_type:
            ip_rows.append(
                {
                    "ip": ioc.split(":")[0],
                    "source": "threatfox",
                    "threat_type": family or "malicious_ip",
                    "confidence": 80,
                    "first_seen": first_seen,
                    "last_updated": now,
                    "detail": detail,
                }
            )
        elif "sha256" in ioc_type:
            hash_rows.append(
                {
                    "sha256": ioc.lower(),
                    "md5": str(item.get("md5_hash") or ""),
                    "source": "threatfox",
                    "malware_family": family,
                    "first_seen": first_seen,
                    "last_updated": now,
                    "detail": detail,
                }
            )
    return {
        "sentinel_ioc_ips": _dedupe_rows(ip_rows, "ip", "source"),
        "sentinel_ioc_domains": _dedupe_rows(domain_rows, "domain", "source"),
        "sentinel_ioc_hashes": _dedupe_rows(hash_rows, "sha256", "source"),
        "sentinel_ioc_urls": _dedupe_rows(url_rows, "url", "source"),
    }


async def _fetch_text(client: httpx.AsyncClient, url: str, *, method: str = "GET", json_body: Any | None = None, headers: dict[str, str] | None = None) -> tuple[str, str]:
    response = await client.request(method, url, json=json_body, headers=headers, timeout=30.0, follow_redirects=True)
    response.raise_for_status()
    return response.text, str(response.url)


async def _download_and_store(connection: sqlite3.Connection, client: httpx.AsyncClient, name: str, now: str, settings: Any) -> dict[str, Any]:
    if name == "urlhaus":
        content, _ = await _fetch_text(client, URLHAUS_CSV)
        parsed = _parse_urlhaus(content, now)
        filename = "urlhaus_online.csv"
        message = ""
    elif name == "feodo":
        content, _ = await _fetch_text(client, FEODO_CSV)
        parsed = _parse_feodo(content, now)
        filename = "feodo_ipblocklist.csv"
        message = ""
    elif name == "sslbl":
        content = ""
        final_url = ""
        last_error = ""
        for candidate in SSLBL_CANDIDATES:
            try:
                content, final_url = await _fetch_text(client, candidate)
                break
            except Exception as exc:  # noqa: BLE001
                last_error = str(exc)
        if not content:
            raise RuntimeError(last_error or "sslbl download failed")
        parsed = _parse_sslbl(content, now)
        filename = "sslbl_fingerprints.csv" if "fingerprint" in final_url else "sslbl_feed.csv"
        message = final_url
    elif name == "cisa_kev":
        content, _ = await _fetch_text(client, CISA_KEV_URL)
        parsed = _parse_cisa_kev(content, now)
        filename = "cisa_kev.json"
        message = ""
    elif name == "threatfox":
        auth_key = settings.sentinel.osint.apis.threatfox_auth_key
        if not auth_key:
            return {
                "name": name,
                "status": "skipped",
                "updated_at": now,
                "counts": {},
                "file": str(_feeds_dir(settings) / "threatfox_iocs.json"),
                "message": "ThreatFox requires sentinel.osint.apis.threatfox_auth_key.",
            }
        content, _ = await _fetch_text(
            client,
            THREATFOX_API,
            method="POST",
            json_body={"query": "get_iocs", "days": 7},
            headers={"Auth-Key": auth_key},
        )
        parsed = _parse_threatfox(content, now)
        filename = "threatfox_iocs.json"
        message = ""
    else:
        raise ValueError(f"Unknown feed: {name}")

    path = _feeds_dir(settings) / filename
    path.write_text(content, encoding="utf-8")
    source = name
    _replace_source_rows(connection, source, parsed)
    return {
        "name": name,
        "status": "updated",
        "updated_at": now,
        "counts": _counts(parsed),
        "file": str(path),
        "message": message,
    }


def _should_refresh(metadata: dict[str, Any], name: str, hours: int, force: bool) -> bool:
    if force:
        return True
    updated_at = str(metadata.get(name, {}).get("updated_at", ""))
    if not updated_at:
        return True
    refreshed = datetime.fromisoformat(updated_at.replace("Z", "+00:00"))
    return refreshed + timedelta(hours=hours) <= datetime.now(timezone.utc)


async def update_all_feeds(*, force: bool = False, selected: set[str] | None = None, settings: Any | None = None) -> dict[str, Any]:
    resolved_settings = settings or get_settings()
    ensure_schema(resolved_settings)
    metadata = _load_metadata(resolved_settings)
    now = utcnow()
    refresh_hours = int(resolved_settings.sentinel.osint.feed_refresh_hours)
    enabled = {
        "urlhaus": resolved_settings.sentinel.osint.feeds.enable_urlhaus,
        "feodo": resolved_settings.sentinel.osint.feeds.enable_feodo,
        "sslbl": resolved_settings.sentinel.osint.feeds.enable_sslbl,
        "cisa_kev": resolved_settings.sentinel.osint.feeds.enable_cisa_kev,
        "threatfox": resolved_settings.sentinel.osint.feeds.enable_threatfox,
    }
    results: dict[str, Any] = {}
    async with httpx.AsyncClient() as client:
        with connect(resolved_settings) as connection:
            for name, is_enabled in enabled.items():
                if not is_enabled:
                    continue
                if selected and name not in selected:
                    continue
                if not _should_refresh(metadata, name, refresh_hours, force):
                    entry = metadata.get(name, {})
                    results[name] = {
                        "name": name,
                        "status": "skipped",
                        "updated_at": str(entry.get("updated_at", "")),
                        "counts": dict(entry.get("counts", {})),
                        "file": str(entry.get("file", "")),
                        "message": "fresh",
                    }
                    continue
                try:
                    result = await _download_and_store(connection, client, name, now, resolved_settings)
                except Exception as exc:  # noqa: BLE001
                    result = {
                        "name": name,
                        "status": "error",
                        "updated_at": now,
                        "counts": {},
                        "file": str(metadata.get(name, {}).get("file", "")),
                        "message": str(exc),
                    }
                results[name] = result
                metadata[name] = result
    _save_metadata(metadata, resolved_settings)
    return results


def _ioc_counts(connection: sqlite3.Connection) -> dict[str, int]:
    counts: dict[str, int] = {}
    for table in IOC_TABLES:
        row = connection.execute(f"SELECT COUNT(*) AS count FROM {table}").fetchone()
        counts[table] = int(row["count"]) if row is not None else 0
    return counts


async def feeds_status(*, settings: Any | None = None) -> dict[str, Any]:
    resolved_settings = settings or get_settings()
    ensure_schema(resolved_settings)
    with connect(resolved_settings) as connection:
        return {
            "metadata": _load_metadata(resolved_settings),
            "ioc_counts": _ioc_counts(connection),
        }

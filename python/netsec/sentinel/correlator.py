"""Correlate Sentinel local state against OSINT data."""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from netsec.core.config import get_settings
from netsec.sentinel import connect, ensure_schema, utcnow
from netsec.sentinel.feed_manager import update_all_feeds
from netsec.sentinel.reputation import check_ip
from netsec.sentinel.vuln_scanner import latest_matches, scan_packages


def _fingerprint(prefix: str, *parts: object) -> str:
    digest = hashlib.sha256()
    digest.update(prefix.encode("utf-8"))
    for part in parts:
        digest.update(str(part).encode("utf-8"))
        digest.update(b"|")
    return digest.hexdigest()


def _alert(*, severity: str, category: str, title: str, description: str, fingerprint: str, device_ip: str | None = None, raw_data: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "source_tool": "sentinel",
        "severity": severity,
        "category": category,
        "title": title,
        "description": description,
        "device_ip": device_ip,
        "fingerprint": fingerprint,
        "raw_data": raw_data or {},
        "timestamp": utcnow(),
    }


async def _network_alerts(settings: Any) -> list[dict[str, Any]]:
    alerts: list[dict[str, Any]] = []
    with connect(settings) as connection:
        latest = connection.execute("SELECT MAX(timestamp) AS ts FROM sentinel_network_snapshots").fetchone()["ts"]
        if not latest:
            return alerts
        rows = connection.execute(
            """
            SELECT DISTINCT remote_addr
            FROM sentinel_network_snapshots
            WHERE timestamp = ?
              AND state IN ('ESTABLISHED', 'CLOSE_WAIT')
              AND remote_addr NOT IN ('', '0.0.0.0', '::', '127.0.0.1', '::1')
            """,
            (latest,),
        ).fetchall()
    for row in rows:
        remote_ip = str(row["remote_addr"])
        reputation = await check_ip(remote_ip, settings=settings)
        if reputation.get("skipped") or not reputation.get("malicious"):
            continue
        confidence = int(reputation.get("confidence", 0))
        severity = "critical" if confidence >= 80 else ("high" if confidence >= 50 else "medium")
        alerts.append(
            _alert(
                severity=severity,
                category="network_threat",
                title="Outbound connection matched external reputation",
                description=f"{remote_ip} matched Sentinel OSINT sources: {', '.join(reputation.get('sources', [])) or 'unknown'}",
                device_ip=remote_ip,
                fingerprint=_fingerprint("sentinel-ip", remote_ip),
                raw_data=reputation,
            )
        )
    return alerts


def _hash_alerts(settings: Any) -> list[dict[str, Any]]:
    alerts: list[dict[str, Any]] = []
    with connect(settings) as connection:
        latest = connection.execute("SELECT MAX(timestamp) AS ts FROM sentinel_file_hashes").fetchone()["ts"]
        if latest:
            rows = connection.execute(
                """
                SELECT fh.path, fh.sha256, ih.source, ih.malware_family
                FROM sentinel_file_hashes AS fh
                JOIN sentinel_ioc_hashes AS ih ON ih.sha256 = fh.sha256
                WHERE fh.timestamp = ?
                """,
                (latest,),
            ).fetchall()
            for row in rows:
                alerts.append(
                    _alert(
                        severity="critical",
                        category="malware",
                        title="File hash matched known malware IOC",
                        description=f"{row['path']} matched {row['source']} ({row['malware_family']})",
                        fingerprint=_fingerprint("sentinel-file", row["path"], row["sha256"]),
                        raw_data=dict(row),
                    )
                )
    return alerts


async def _vuln_alerts(settings: Any, *, scan_vulns: bool) -> list[dict[str, Any]]:
    if scan_vulns and settings.sentinel.osint.vuln.enable_osv:
        await scan_packages(force=False, refresh_feeds=True, settings=settings)
    alerts: list[dict[str, Any]] = []
    for row in await latest_matches(settings=settings, limit=500):
        severity = str(row["severity"]).upper()
        exploited = int(row.get("exploited", 0))
        if severity not in {"CRITICAL", "HIGH"} and not exploited:
            continue
        alerts.append(
            _alert(
                severity="critical" if exploited or severity == "CRITICAL" else "high",
                category="vulnerability",
                title="Installed package matched an exploitable vulnerability",
                description=f"{row['package']} {row['version']} matched {row['cve_id']} ({row['severity']})",
                fingerprint=_fingerprint("sentinel-vuln", row["package"], row["version"], row["cve_id"]),
                raw_data=row,
            )
        )
    return alerts


async def correlate(*, refresh_feeds: bool = True, scan_vulns: bool = True, settings: Any | None = None) -> dict[str, Any]:
    resolved_settings = settings or get_settings()
    ensure_schema(resolved_settings)
    warnings: list[str] = []
    if refresh_feeds:
        feed_results = await update_all_feeds(force=False, settings=resolved_settings)
        for name, result in feed_results.items():
            if result.get("status") == "error":
                warnings.append(f"feed {name}: {result.get('message', '')}")

    alerts: list[dict[str, Any]] = []
    alerts.extend(await _network_alerts(resolved_settings))
    alerts.extend(_hash_alerts(resolved_settings))
    alerts.extend(await _vuln_alerts(resolved_settings, scan_vulns=scan_vulns))
    return {"count": len(alerts), "warnings": warnings, "alerts": alerts}

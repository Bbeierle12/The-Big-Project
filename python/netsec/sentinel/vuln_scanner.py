"""Debian package vulnerability scanning via OSV.dev and CISA KEV."""
from __future__ import annotations

import asyncio
import json
import re
import sqlite3
import subprocess
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

import httpx

from netsec.core.config import get_settings
from netsec.sentinel import connect, ensure_schema, row_dicts, utcnow

CVSS_SCORE_RE = re.compile(r"([0-9]+\.[0-9]+)")


def _packages_sync() -> list[tuple[str, str]]:
    result = subprocess.run(
        ["dpkg-query", "-W", "-f=${Package}\t${Version}\n"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        return []
    packages: list[tuple[str, str]] = []
    for line in result.stdout.splitlines():
        if not line.strip() or "\t" not in line:
            continue
        name, version = line.split("\t", 1)
        packages.append((name.strip(), version.strip()))
    return packages


async def _packages() -> list[tuple[str, str]]:
    return await asyncio.to_thread(_packages_sync)


async def _osv_query_batch(client: httpx.AsyncClient, batch: list[tuple[str, str]]) -> dict[str, Any]:
    payload = {
        "queries": [
            {"package": {"name": name, "ecosystem": "Debian"}, "version": version}
            for name, version in batch
        ]
    }
    response = await client.post("https://api.osv.dev/v1/querybatch", json=payload, timeout=60.0)
    response.raise_for_status()
    return response.json()


def _severity_from_vuln(vuln: dict[str, Any], exploited: bool) -> str:
    database_specific = vuln.get("database_specific", {}) if isinstance(vuln.get("database_specific"), dict) else {}
    candidate = str(database_specific.get("severity") or "").upper()
    if candidate in {"CRITICAL", "HIGH", "MODERATE", "MEDIUM", "LOW"}:
        if candidate == "MODERATE":
            return "MEDIUM"
        if exploited and candidate != "CRITICAL":
            return "HIGH"
        return candidate
    for severity in vuln.get("severity", []) or []:
        score = str(severity.get("score") or "")
        match = CVSS_SCORE_RE.search(score)
        if not match:
            continue
        numeric = float(match.group(1))
        if exploited and numeric >= 9.0:
            return "CRITICAL"
        if exploited or numeric >= 7.0:
            return "HIGH"
        if numeric >= 4.0:
            return "MEDIUM"
        return "LOW"
    return "HIGH" if exploited else "MEDIUM"


def _cve_ids(vuln: dict[str, Any]) -> list[str]:
    ids = [str(alias) for alias in vuln.get("aliases", []) if str(alias).startswith("CVE-")]
    if str(vuln.get("id") or "").startswith("CVE-"):
        ids.append(str(vuln["id"]))
    return sorted(set(ids))


def _latest_scan_age_hours(connection: sqlite3.Connection) -> float | None:
    row = connection.execute("SELECT MAX(timestamp) AS ts FROM sentinel_vuln_matches").fetchone()
    if row is None or row["ts"] is None:
        return None
    latest = datetime.fromisoformat(str(row["ts"]).replace("Z", "+00:00"))
    return (datetime.now(timezone.utc) - latest).total_seconds() / 3600


def _latest_matches_sync(connection: sqlite3.Connection, limit: int) -> list[dict[str, Any]]:
    row = connection.execute("SELECT MAX(timestamp) AS ts FROM sentinel_vuln_matches").fetchone()
    if row is None or row["ts"] is None:
        return []
    rows = connection.execute(
        """
        SELECT *
        FROM sentinel_vuln_matches
        WHERE timestamp = ?
        ORDER BY
            CASE severity
                WHEN 'CRITICAL' THEN 1
                WHEN 'HIGH' THEN 2
                WHEN 'MEDIUM' THEN 3
                ELSE 4
            END,
            package,
            cve_id
        LIMIT ?
        """,
        (str(row["ts"]), limit),
    ).fetchall()
    return row_dicts(rows)


async def latest_matches(*, settings: Any | None = None, limit: int = 50) -> list[dict[str, Any]]:
    resolved_settings = settings or get_settings()
    ensure_schema(resolved_settings)
    with connect(resolved_settings) as connection:
        return _latest_matches_sync(connection, limit)


async def scan_packages(*, force: bool = False, refresh_feeds: bool = True, settings: Any | None = None) -> dict[str, Any]:
    resolved_settings = settings or get_settings()
    ensure_schema(resolved_settings)

    if refresh_feeds and resolved_settings.sentinel.osint.feeds.enable_cisa_kev:
        from netsec.sentinel.feed_manager import update_all_feeds

        await update_all_feeds(force=False, selected={"cisa_kev"}, settings=resolved_settings)

    with connect(resolved_settings) as connection:
        latest_age = _latest_scan_age_hours(connection)
        if not force and latest_age is not None and latest_age < resolved_settings.sentinel.osint.vuln.scan_interval_hours:
            return {"count": len(_latest_matches_sync(connection, 500)), "rows": _latest_matches_sync(connection, 500), "skipped": True}

        packages = await _packages()
        if not packages:
            return {"count": 0, "rows": [], "warnings": ["dpkg-query returned no packages"]}

        kev_rows = connection.execute(
            "SELECT cve_id FROM sentinel_ioc_cves WHERE source = 'cisa_kev'"
        ).fetchall()
        kev_cves = {str(row["cve_id"]) for row in kev_rows}

        timestamp = utcnow()
        rows_to_insert: list[tuple[str, str, str, str, str, str, int, str, str]] = []
        async with httpx.AsyncClient() as client:
            for start in range(0, len(packages), 1000):
                batch = packages[start:start + 1000]
                response = await _osv_query_batch(client, batch)
                for (package, version), result in zip(batch, response.get("results", [])):
                    vulns = result.get("vulns", []) if isinstance(result, dict) else []
                    for vuln in vulns:
                        cve_ids = _cve_ids(vuln) or [str(vuln.get("id") or "OSV-UNKNOWN")]
                        exploited = any(cve_id in kev_cves for cve_id in cve_ids)
                        severity = _severity_from_vuln(vuln, exploited)
                        detail = json.dumps(vuln, sort_keys=True)
                        source = "osv+kev" if exploited else "osv"
                        for cve_id in cve_ids:
                            rows_to_insert.append(
                                (
                                    uuid4().hex,
                                    timestamp,
                                    package,
                                    version,
                                    cve_id,
                                    severity,
                                    source,
                                    int(exploited),
                                    detail,
                                )
                            )

        connection.executemany(
            """
            INSERT INTO sentinel_vuln_matches (id, timestamp, package, version, cve_id, severity, source, exploited, detail)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            rows_to_insert,
        )
        return {"count": len(rows_to_insert), "rows": _latest_matches_sync(connection, 500), "skipped": False}

"""Indicator reputation checks backed by local IOCs and DNSBL."""
from __future__ import annotations

import ipaddress
import json
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx

from netsec.core.config import get_settings
from netsec.sentinel import connect, ensure_schema, utcnow
from netsec.sentinel.dnsbl import check_ip_dnsbl


def _cache_valid(queried_at: str, ttl_hours: int) -> bool:
    then = datetime.fromisoformat(str(queried_at).replace("Z", "+00:00"))
    return then + timedelta(hours=ttl_hours) > datetime.now(timezone.utc)


def _cached_lookup(connection: sqlite3.Connection, indicator: str, indicator_type: str, source: str) -> dict[str, Any] | None:
    row = connection.execute(
        """
        SELECT result_json, queried_at, ttl_hours
        FROM sentinel_reputation_cache
        WHERE indicator = ? AND indicator_type = ? AND source = ?
        """,
        (indicator, indicator_type, source),
    ).fetchone()
    if row is None or not _cache_valid(str(row["queried_at"]), int(row["ttl_hours"])):
        return None
    return json.loads(str(row["result_json"]))


def _store_cache(connection: sqlite3.Connection, indicator: str, indicator_type: str, source: str, result: dict[str, Any], ttl_hours: int) -> None:
    connection.execute(
        """
        INSERT INTO sentinel_reputation_cache (indicator, indicator_type, source, result_json, queried_at, ttl_hours)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(indicator, indicator_type, source) DO UPDATE SET
            result_json = excluded.result_json,
            queried_at = excluded.queried_at,
            ttl_hours = excluded.ttl_hours
        """,
        (indicator, indicator_type, source, json.dumps(result, sort_keys=True), utcnow(), ttl_hours),
    )


def _skip_reason(settings: Any, ip: str) -> str:
    try:
        indicator = ipaddress.ip_address(ip)
    except ValueError:
        return "invalid_ip"
    if settings.sentinel.osint.skip_private_ips and (
        indicator.is_private or indicator.is_loopback or indicator.is_multicast or indicator.is_link_local or indicator.is_reserved
    ):
        return "private_or_local"
    for cidr in settings.sentinel.osint.known_good_cidrs:
        if indicator in ipaddress.ip_network(cidr):
            return f"known_good:{cidr}"
    return ""


async def _abuseipdb(ip: str, api_key: str) -> dict[str, Any]:
    async with httpx.AsyncClient(timeout=20.0) as client:
        response = await client.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Key": api_key, "Accept": "application/json"},
        )
        response.raise_for_status()
        return response.json()


async def check_ip(ip: str, *, settings: Any | None = None) -> dict[str, Any]:
    resolved_settings = settings or get_settings()
    ensure_schema(resolved_settings)
    reason = _skip_reason(resolved_settings, ip)
    if reason:
        return {
            "indicator": ip,
            "indicator_type": "ip",
            "skipped": True,
            "reason": reason,
            "malicious": False,
            "confidence": 0,
            "sources": [],
            "details": {},
        }

    with connect(resolved_settings) as connection:
        local_hits = [
            dict(row)
            for row in connection.execute(
                """
                SELECT source, threat_type, confidence, detail
                FROM sentinel_ioc_ips
                WHERE ip = ?
                """,
                (ip,),
            ).fetchall()
        ]
        confidence = 70 if local_hits else 0
        sources = sorted({str(item["source"]) for item in local_hits})
        details: dict[str, Any] = {"local_hits": local_hits}

        dnsbl_result = _cached_lookup(connection, ip, "ip", "dnsbl")
        if dnsbl_result is None and resolved_settings.sentinel.osint.dnsbl.enabled:
            dnsbl_result = await check_ip_dnsbl(ip, settings=resolved_settings)
            _store_cache(connection, ip, "ip", "dnsbl", dnsbl_result, resolved_settings.sentinel.osint.reputation_cache_ttl_hours)
        elif dnsbl_result is None:
            dnsbl_result = {"listed_on": [], "listed_count": 0, "malicious": False, "skipped": True}
        details["dnsbl"] = dnsbl_result
        if dnsbl_result.get("malicious"):
            confidence = max(confidence, 60)
            sources.extend(dnsbl_result.get("listed_on", []))
        elif int(dnsbl_result.get("listed_count", 0)) == 1:
            confidence = max(confidence, 25)

        abuseipdb_result: dict[str, Any] | None = None
        if resolved_settings.sentinel.osint.apis.abuseipdb_key:
            abuseipdb_result = _cached_lookup(connection, ip, "ip", "abuseipdb")
            if abuseipdb_result is None:
                try:
                    abuseipdb_result = await _abuseipdb(ip, resolved_settings.sentinel.osint.apis.abuseipdb_key)
                except Exception as exc:  # noqa: BLE001
                    abuseipdb_result = {"error": str(exc)}
                _store_cache(connection, ip, "ip", "abuseipdb", abuseipdb_result, resolved_settings.sentinel.osint.reputation_cache_ttl_hours)
            details["abuseipdb"] = abuseipdb_result
            data = abuseipdb_result.get("data", {}) if isinstance(abuseipdb_result, dict) else {}
            abuse_confidence = int(data.get("abuseConfidenceScore", 0) or 0)
            if abuse_confidence >= 80:
                confidence = max(confidence, 50)
                sources.append("abuseipdb")
            elif abuse_confidence >= 40:
                confidence = max(confidence, 25)
                sources.append("abuseipdb")

    malicious = bool(local_hits or dnsbl_result.get("malicious") or confidence >= 70)
    return {
        "indicator": ip,
        "indicator_type": "ip",
        "skipped": False,
        "malicious": malicious,
        "confidence": min(confidence, 100),
        "sources": sorted(set(sources)),
        "details": details,
    }

"""DNSBL lookups for public IPs."""
from __future__ import annotations

import asyncio
import ipaddress
import socket
import time
from typing import Any

from netsec.core.config import get_settings

_LAST_QUERY_AT = 0.0
_MIN_QUERY_INTERVAL = 0.25


def _throttle() -> None:
    global _LAST_QUERY_AT
    now = time.monotonic()
    sleep_for = _MIN_QUERY_INTERVAL - (now - _LAST_QUERY_AT)
    if sleep_for > 0:
        time.sleep(sleep_for)
    _LAST_QUERY_AT = time.monotonic()


def _check_sync(ip: str, dnsbl_lists: list[str]) -> dict[str, Any]:
    indicator = ipaddress.ip_address(ip)
    if indicator.is_private or indicator.is_loopback or indicator.is_multicast or indicator.is_link_local:
        return {"indicator": ip, "listed_on": [], "listed_count": 0, "malicious": False, "skipped": True}

    listed_on: list[str] = []
    reverse_name = indicator.reverse_pointer
    for zone in dnsbl_lists:
        _throttle()
        query = f"{reverse_name}.{zone}"
        try:
            socket.gethostbyname(query)
            listed_on.append(zone)
        except socket.gaierror:
            continue
    return {
        "indicator": ip,
        "listed_on": listed_on,
        "listed_count": len(listed_on),
        "malicious": len(listed_on) >= 2,
        "skipped": False,
    }


async def check_ip_dnsbl(ip: str, settings: Any | None = None) -> dict[str, Any]:
    resolved_settings = settings or get_settings()
    lists = list(resolved_settings.sentinel.osint.dnsbl.lists)
    return await asyncio.to_thread(_check_sync, ip, lists)

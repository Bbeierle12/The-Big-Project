"""Sentinel host-monitoring and OSINT adapter."""
from __future__ import annotations

import json
from typing import Any

from netsec.adapters.base import BaseAdapter, ToolCategory, ToolInfo, ToolStatus
from netsec.core.config import get_settings
from netsec.sentinel import ensure_schema, status as sentinel_status
from netsec.sentinel.collector import collect
from netsec.sentinel.correlator import correlate
from netsec.sentinel.feed_manager import feeds_status, update_all_feeds
from netsec.sentinel.reputation import check_ip
from netsec.sentinel.vuln_scanner import latest_matches, scan_packages


class Adapter(BaseAdapter):
    def __init__(self) -> None:
        self._status = ToolStatus.UNKNOWN

    def tool_info(self) -> ToolInfo:
        return ToolInfo(
            name="sentinel",
            display_name="Sentinel",
            category=ToolCategory.HOST_MONITOR,
            description="Integrated host security and OSINT monitoring",
            status=self._status,
            supported_tasks=[
                "collect",
                "status",
                "feeds_status",
                "feeds_update",
                "reputation_check",
                "vuln_scan",
                "vuln_report",
                "correlate",
            ],
        )

    async def detect(self) -> bool:
        enabled = get_settings().sentinel.enabled
        self._status = ToolStatus.AVAILABLE if enabled else ToolStatus.UNAVAILABLE
        return enabled

    async def health_check(self) -> ToolStatus:
        settings = get_settings()
        if not settings.sentinel.enabled:
            self._status = ToolStatus.UNAVAILABLE
            return self._status
        try:
            ensure_schema(settings)
            self._status = ToolStatus.AVAILABLE
        except Exception:
            self._status = ToolStatus.ERROR
        return self._status

    async def execute(self, task: str, params: dict[str, Any]) -> dict[str, Any]:
        settings = get_settings()
        if not settings.sentinel.enabled:
            raise RuntimeError("Sentinel is disabled in config")

        ensure_schema(settings)

        match task:
            case "collect":
                return collect(settings)
            case "status":
                return await sentinel_status(settings)
            case "feeds_status":
                return await feeds_status(settings=settings)
            case "feeds_update":
                force = bool(params.get("force", True))
                selected = params.get("selected")
                selected_set = {str(item) for item in selected} if isinstance(selected, list) else None
                return await update_all_feeds(force=force, selected=selected_set, settings=settings)
            case "reputation_check":
                indicator = str(params.get("indicator") or params.get("ip") or "").strip()
                if not indicator:
                    raise ValueError("indicator is required")
                return await check_ip(indicator, settings=settings)
            case "vuln_scan":
                return await scan_packages(
                    force=bool(params.get("force", False)),
                    refresh_feeds=bool(params.get("refresh_feeds", True)),
                    settings=settings,
                )
            case "vuln_report":
                limit = int(params.get("limit", 50))
                return {"rows": await latest_matches(settings=settings, limit=limit)}
            case "correlate":
                return await correlate(
                    refresh_feeds=bool(params.get("refresh_feeds", True)),
                    scan_vulns=bool(params.get("scan_vulns", True)),
                    settings=settings,
                )
            case _:
                raise ValueError(f"Unknown task: {task}")

    async def parse_output(self, raw_output: str | bytes, output_format: str = "text") -> dict[str, Any]:
        text = raw_output if isinstance(raw_output, str) else raw_output.decode(errors="replace")
        if output_format == "json":
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                return {"raw": text}
        return {"raw": text}

"""Suricata IDS/IPS adapter — EVE JSON log tailing, daemon management."""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from netsec.adapters.base import BaseAdapter, ToolCategory, ToolInfo, ToolStatus
from netsec.adapters.process import check_binary, get_binary_version, run_command
from netsec.platform.paths import find_tool_binary
from netsec.platform.service import get_service_status, ServiceState

logger = logging.getLogger(__name__)

DEFAULT_EVE_LOG = "/var/log/suricata/eve.json"
DEFAULT_RULES_DIR = "/etc/suricata/rules"


class Adapter(BaseAdapter):
    def __init__(self) -> None:
        self._binary: str | None = None
        self._version: str | None = None
        self._status = ToolStatus.UNKNOWN
        self._eve_log = Path(DEFAULT_EVE_LOG)

    def tool_info(self) -> ToolInfo:
        return ToolInfo(
            name="suricata",
            display_name="Suricata",
            category=ToolCategory.IDS_IPS,
            description="Network threat detection engine (IDS/IPS)",
            version=self._version,
            binary_path=self._binary,
            status=self._status,
            supported_tasks=["status", "tail_alerts", "rule_reload", "stats"],
        )

    async def detect(self) -> bool:
        self._binary = find_tool_binary("suricata")
        if not self._binary:
            self._binary = await check_binary("suricata")
        if self._binary:
            ver = await get_binary_version(self._binary, "--build-info")
            if ver:
                for line in ver.split("\n"):
                    if "version" in line.lower():
                        self._version = line.strip().split()[-1]
                        break
            self._status = ToolStatus.AVAILABLE
            return True
        self._status = ToolStatus.UNAVAILABLE
        return False

    async def health_check(self) -> ToolStatus:
        svc = await get_service_status("suricata")
        if svc.state == ServiceState.RUNNING:
            self._status = ToolStatus.RUNNING
        elif self._binary:
            self._status = ToolStatus.AVAILABLE
        else:
            self._status = ToolStatus.UNAVAILABLE
        return self._status

    async def execute(self, task: str, params: dict[str, Any]) -> dict[str, Any]:
        if not self._binary:
            raise RuntimeError("Suricata not available")

        match task:
            case "status":
                svc = await get_service_status("suricata")
                return {"state": svc.state.value, "pid": svc.pid}
            case "tail_alerts":
                return await self._tail_eve(params.get("lines", 100))
            case "rule_reload":
                result = await run_command(f"{self._binary} --reload-rules", timeout=30)
                return {"success": result.success, "output": result.stdout}
            case "stats":
                return await self._get_stats()
            case _:
                raise ValueError(f"Unknown task: {task}")

    async def _tail_eve(self, lines: int) -> dict[str, Any]:
        if not self._eve_log.exists():
            return {"alerts": [], "error": f"EVE log not found: {self._eve_log}"}
        result = await run_command(f"tail -n {lines} {self._eve_log}", timeout=10)
        alerts = []
        for line in result.stdout.strip().split("\n"):
            if not line:
                continue
            try:
                event = json.loads(line)
                if event.get("event_type") == "alert":
                    alerts.append(event)
            except json.JSONDecodeError:
                continue
        return {"alerts": alerts, "total": len(alerts)}

    async def _get_stats(self) -> dict[str, Any]:
        if not self._eve_log.exists():
            return {"error": "EVE log not found"}
        result = await run_command(f"tail -n 500 {self._eve_log}", timeout=10)
        stats_events = []
        for line in result.stdout.strip().split("\n"):
            try:
                event = json.loads(line)
                if event.get("event_type") == "stats":
                    stats_events.append(event)
            except json.JSONDecodeError:
                continue
        return {"stats": stats_events[-1] if stats_events else {}}

    async def parse_output(self, raw_output: str | bytes, output_format: str = "text") -> dict[str, Any]:
        text = raw_output if isinstance(raw_output, str) else raw_output.decode(errors="replace")
        events = []
        for line in text.strip().split("\n"):
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return {"events": events}

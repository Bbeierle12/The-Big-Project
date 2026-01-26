"""Zeek network analysis adapter — log watching, connection analysis."""
from __future__ import annotations

import csv
import io
import logging
from pathlib import Path
from typing import Any

from netsec.adapters.base import BaseAdapter, ToolCategory, ToolInfo, ToolStatus
from netsec.adapters.process import check_binary, get_binary_version, run_command
from netsec.platform.paths import find_tool_binary
from netsec.platform.service import get_service_status, ServiceState

logger = logging.getLogger(__name__)

DEFAULT_LOG_DIR = "/opt/zeek/logs/current"


class Adapter(BaseAdapter):
    def __init__(self) -> None:
        self._binary: str | None = None
        self._version: str | None = None
        self._status = ToolStatus.UNKNOWN
        self._log_dir = Path(DEFAULT_LOG_DIR)

    def tool_info(self) -> ToolInfo:
        return ToolInfo(
            name="zeek",
            display_name="Zeek",
            category=ToolCategory.TRAFFIC_ANALYZER,
            description="Network analysis framework for traffic inspection",
            version=self._version,
            binary_path=self._binary,
            status=self._status,
            supported_tasks=["status", "connections", "dns", "http", "notices", "capture"],
        )

    async def detect(self) -> bool:
        self._binary = find_tool_binary("zeek")
        if not self._binary:
            self._binary = await check_binary("zeek")
        if self._binary:
            ver = await get_binary_version(self._binary)
            if ver:
                self._version = ver.split()[0] if ver else None
            self._status = ToolStatus.AVAILABLE
            return True
        self._status = ToolStatus.UNAVAILABLE
        return False

    async def health_check(self) -> ToolStatus:
        svc = await get_service_status("zeek")
        if svc.state == ServiceState.RUNNING:
            self._status = ToolStatus.RUNNING
        elif self._binary:
            self._status = ToolStatus.AVAILABLE
        else:
            self._status = ToolStatus.UNAVAILABLE
        return self._status

    async def execute(self, task: str, params: dict[str, Any]) -> dict[str, Any]:
        if not self._binary:
            raise RuntimeError("Zeek not available")

        match task:
            case "status":
                result = await run_command(f"{self._binary}ctl status", timeout=10)
                return {"output": result.stdout, "success": result.success}
            case "connections":
                return await self._read_log("conn.log", params.get("lines", 100))
            case "dns":
                return await self._read_log("dns.log", params.get("lines", 100))
            case "http":
                return await self._read_log("http.log", params.get("lines", 100))
            case "notices":
                return await self._read_log("notice.log", params.get("lines", 100))
            case "capture":
                pcap = params.get("interface", "eth0")
                duration = params.get("duration", 60)
                result = await run_command(
                    f"{self._binary} -i {pcap} -C",
                    timeout=duration + 10,
                )
                return {"success": result.success, "output": result.stdout}
            case _:
                raise ValueError(f"Unknown task: {task}")

    async def _read_log(self, log_name: str, lines: int) -> dict[str, Any]:
        log_path = self._log_dir / log_name
        if not log_path.exists():
            return {"entries": [], "error": f"Log not found: {log_path}"}
        result = await run_command(f"tail -n {lines} {log_path}", timeout=10)
        return await self.parse_output(result.stdout, output_format="zeek_tsv")

    async def parse_output(self, raw_output: str | bytes, output_format: str = "text") -> dict[str, Any]:
        text = raw_output if isinstance(raw_output, str) else raw_output.decode(errors="replace")
        if output_format == "zeek_tsv":
            return self._parse_zeek_tsv(text)
        return {"raw": text}

    def _parse_zeek_tsv(self, text: str) -> dict[str, Any]:
        lines = text.strip().split("\n")
        headers: list[str] = []
        entries: list[dict[str, str]] = []
        for line in lines:
            if line.startswith("#fields"):
                headers = line.split("\t")[1:]
            elif line.startswith("#"):
                continue
            elif headers:
                values = line.split("\t")
                entry = dict(zip(headers, values))
                entries.append(entry)
        return {"entries": entries, "total": len(entries)}

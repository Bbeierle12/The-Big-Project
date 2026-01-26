"""TShark/Wireshark packet capture adapter."""
from __future__ import annotations

import json
import logging
from typing import Any

from netsec.adapters.base import BaseAdapter, ToolCategory, ToolInfo, ToolStatus
from netsec.adapters.process import check_binary, get_binary_version, run_command
from netsec.platform.paths import find_tool_binary

logger = logging.getLogger(__name__)


class Adapter(BaseAdapter):
    def __init__(self) -> None:
        self._binary: str | None = None
        self._version: str | None = None
        self._status = ToolStatus.UNKNOWN

    def tool_info(self) -> ToolInfo:
        return ToolInfo(
            name="tshark",
            display_name="TShark",
            category=ToolCategory.TRAFFIC_ANALYZER,
            description="Network protocol analyzer (Wireshark CLI)",
            version=self._version,
            binary_path=self._binary,
            status=self._status,
            supported_tasks=["capture", "read_pcap", "interfaces", "stats"],
        )

    async def detect(self) -> bool:
        self._binary = find_tool_binary("tshark")
        if not self._binary:
            self._binary = await check_binary("tshark")
        if self._binary:
            ver = await get_binary_version(self._binary)
            if ver:
                self._version = ver.split()[1] if len(ver.split()) > 1 else ver.strip()
            self._status = ToolStatus.AVAILABLE
            return True
        self._status = ToolStatus.UNAVAILABLE
        return False

    async def health_check(self) -> ToolStatus:
        if not self._binary:
            return ToolStatus.UNAVAILABLE
        result = await run_command(f"{self._binary} --version", timeout=10)
        self._status = ToolStatus.AVAILABLE if result.success else ToolStatus.ERROR
        return self._status

    async def execute(self, task: str, params: dict[str, Any]) -> dict[str, Any]:
        if not self._binary:
            raise RuntimeError("TShark not available")

        match task:
            case "capture":
                interface = params.get("interface", "any")
                duration = params.get("duration", 30)
                count = params.get("count", 100)
                display_filter = params.get("filter", "")
                cmd = f"{self._binary} -i {interface} -a duration:{duration} -c {count} -T json"
                if display_filter:
                    cmd += f" -Y '{display_filter}'"
                result = await run_command(cmd, timeout=duration + 30)
                return await self.parse_output(result.stdout, "json")
            case "read_pcap":
                pcap_file = params.get("file", "")
                if not pcap_file:
                    raise ValueError("PCAP file path required")
                display_filter = params.get("filter", "")
                cmd = f"{self._binary} -r {pcap_file} -T json"
                if display_filter:
                    cmd += f" -Y '{display_filter}'"
                result = await run_command(cmd, timeout=120)
                return await self.parse_output(result.stdout, "json")
            case "interfaces":
                result = await run_command(f"{self._binary} -D", timeout=10)
                interfaces = [line.strip() for line in result.stdout.strip().split("\n") if line.strip()]
                return {"interfaces": interfaces}
            case "stats":
                interface = params.get("interface", "any")
                duration = params.get("duration", 10)
                result = await run_command(
                    f"{self._binary} -i {interface} -a duration:{duration} -q -z io,stat,1",
                    timeout=duration + 15,
                )
                return {"stats": result.stdout}
            case _:
                raise ValueError(f"Unknown task: {task}")

    async def parse_output(self, raw_output: str | bytes, output_format: str = "text") -> dict[str, Any]:
        text = raw_output if isinstance(raw_output, str) else raw_output.decode(errors="replace")
        if output_format == "json":
            try:
                packets = json.loads(text)
                return {"packets": packets, "total": len(packets)}
            except json.JSONDecodeError:
                return {"packets": [], "raw": text[:5000]}
        return {"raw": text}

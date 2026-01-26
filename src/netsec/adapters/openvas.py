"""OpenVAS/GVM vulnerability scanner adapter."""
from __future__ import annotations

import logging
from typing import Any

from netsec.adapters.base import BaseAdapter, ToolCategory, ToolInfo, ToolStatus
from netsec.adapters.process import check_binary, run_command

logger = logging.getLogger(__name__)


class Adapter(BaseAdapter):
    def __init__(self) -> None:
        self._binary: str | None = None
        self._version: str | None = None
        self._status = ToolStatus.UNKNOWN

    def tool_info(self) -> ToolInfo:
        return ToolInfo(
            name="openvas",
            display_name="OpenVAS/GVM",
            category=ToolCategory.VULNERABILITY_SCANNER,
            description="Open vulnerability assessment scanner",
            version=self._version,
            binary_path=self._binary,
            status=self._status,
            supported_tasks=["full_scan", "list_tasks", "get_report", "update_feeds"],
        )

    async def detect(self) -> bool:
        self._binary = await check_binary("gvm-cli")
        if not self._binary:
            self._binary = await check_binary("omp")
        if self._binary:
            result = await run_command(f"{self._binary} --version", timeout=10)
            if result.success:
                self._version = result.stdout.strip().split("\n")[0]
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
            raise RuntimeError("OpenVAS/GVM not available")

        match task:
            case "full_scan":
                target = params.get("target", "")
                if not target:
                    raise ValueError("Target required")
                cmd = f"{self._binary} socket --xml '<create_target><name>netsec-scan</name><hosts>{target}</hosts></create_target>'"
                result = await run_command(cmd, timeout=params.get("timeout", 600))
                return {"success": result.success, "output": result.stdout, "stderr": result.stderr}
            case "list_tasks":
                result = await run_command(
                    f"{self._binary} socket --xml '<get_tasks/>'", timeout=30
                )
                return await self.parse_output(result.stdout, "xml")
            case "get_report":
                report_id = params.get("report_id", "")
                result = await run_command(
                    f"{self._binary} socket --xml '<get_reports report_id=\"{report_id}\"/>'",
                    timeout=60,
                )
                return await self.parse_output(result.stdout, "xml")
            case "update_feeds":
                result = await run_command("greenbone-feed-sync", timeout=600)
                return {"success": result.success, "output": result.stdout}
            case _:
                raise ValueError(f"Unknown task: {task}")

    async def parse_output(self, raw_output: str | bytes, output_format: str = "text") -> dict[str, Any]:
        text = raw_output if isinstance(raw_output, str) else raw_output.decode(errors="replace")
        if output_format == "xml":
            try:
                import xml.etree.ElementTree as ET
                root = ET.fromstring(text)
                return {"status": root.get("status", ""), "status_text": root.get("status_text", ""), "raw_xml": text[:5000]}
            except Exception:
                return {"raw": text[:5000]}
        return {"raw": text}

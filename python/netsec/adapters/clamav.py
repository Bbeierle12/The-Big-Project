"""ClamAV antivirus scanner adapter."""
from __future__ import annotations

import logging
import re
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
            name="clamav",
            display_name="ClamAV",
            category=ToolCategory.MALWARE_SCANNER,
            description="Open source antivirus engine",
            version=self._version,
            binary_path=self._binary,
            status=self._status,
            supported_tasks=["scan", "update_signatures", "version"],
        )

    async def detect(self) -> bool:
        self._binary = find_tool_binary("clamscan")
        if not self._binary:
            self._binary = await check_binary("clamscan")
        if self._binary:
            ver = await get_binary_version(self._binary)
            if ver:
                match = re.search(r"ClamAV\s+([\d.]+)", ver)
                self._version = match.group(1) if match else ver.split("\n")[0]
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
            raise RuntimeError("ClamAV not available")

        match task:
            case "scan":
                target = params.get("target", "/")
                recursive = params.get("recursive", True)
                cmd = f"{self._binary} --infected --no-summary"
                if recursive:
                    cmd += " -r"
                cmd += f" {target}"
                result = await run_command(cmd, timeout=params.get("timeout", 600))
                return await self.parse_output(result.stdout)
            case "update_signatures":
                result = await run_command("freshclam", timeout=300)
                return {"success": result.success, "output": result.stdout, "stderr": result.stderr}
            case "version":
                result = await run_command(f"{self._binary} --version", timeout=10)
                return {"version": result.stdout.strip()}
            case _:
                raise ValueError(f"Unknown task: {task}")

    async def parse_output(self, raw_output: str | bytes, output_format: str = "text") -> dict[str, Any]:
        text = raw_output if isinstance(raw_output, str) else raw_output.decode(errors="replace")
        infections: list[dict[str, str]] = []
        for line in text.strip().split("\n"):
            if ": " in line and "FOUND" in line:
                parts = line.rsplit(": ", 1)
                if len(parts) == 2:
                    infections.append({
                        "file": parts[0].strip(),
                        "signature": parts[1].replace("FOUND", "").strip(),
                    })
        return {"infections": infections, "total": len(infections)}

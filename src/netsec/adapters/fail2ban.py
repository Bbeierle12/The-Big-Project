"""Fail2Ban intrusion prevention adapter."""
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
            name="fail2ban",
            display_name="Fail2Ban",
            category=ToolCategory.ACCESS_CONTROL,
            description="Intrusion prevention — bans IPs with too many failures",
            version=self._version,
            binary_path=self._binary,
            status=self._status,
            supported_tasks=["status", "jail_status", "banned_ips", "ban", "unban"],
        )

    async def detect(self) -> bool:
        self._binary = find_tool_binary("fail2ban-client")
        if not self._binary:
            self._binary = await check_binary("fail2ban-client")
        if self._binary:
            ver = await get_binary_version(self._binary)
            if ver:
                match = re.search(r"v?([\d.]+)", ver)
                self._version = match.group(1) if match else ver.strip()
            self._status = ToolStatus.AVAILABLE
            return True
        self._status = ToolStatus.UNAVAILABLE
        return False

    async def health_check(self) -> ToolStatus:
        if not self._binary:
            return ToolStatus.UNAVAILABLE
        result = await run_command(f"{self._binary} ping", timeout=10)
        if result.success and "pong" in result.stdout.lower():
            self._status = ToolStatus.RUNNING
        elif self._binary:
            self._status = ToolStatus.AVAILABLE
        else:
            self._status = ToolStatus.ERROR
        return self._status

    async def execute(self, task: str, params: dict[str, Any]) -> dict[str, Any]:
        if not self._binary:
            raise RuntimeError("Fail2Ban not available")

        match task:
            case "status":
                result = await run_command(f"{self._binary} status", timeout=10)
                return await self.parse_output(result.stdout, "status")
            case "jail_status":
                jail = params.get("jail", "sshd")
                result = await run_command(f"{self._binary} status {jail}", timeout=10)
                return await self.parse_output(result.stdout, "jail_status")
            case "banned_ips":
                jail = params.get("jail", "")
                if jail:
                    result = await run_command(f"{self._binary} get {jail} banned", timeout=10)
                else:
                    result = await run_command(f"{self._binary} banned", timeout=10)
                return {"banned": result.stdout.strip().split("\n"), "success": result.success}
            case "ban":
                jail = params.get("jail", "sshd")
                ip = params.get("ip", "")
                if not ip:
                    raise ValueError("IP address required")
                result = await run_command(f"{self._binary} set {jail} banip {ip}", timeout=10)
                return {"success": result.success, "output": result.stdout}
            case "unban":
                jail = params.get("jail", "sshd")
                ip = params.get("ip", "")
                if not ip:
                    raise ValueError("IP address required")
                result = await run_command(f"{self._binary} set {jail} unbanip {ip}", timeout=10)
                return {"success": result.success, "output": result.stdout}
            case _:
                raise ValueError(f"Unknown task: {task}")

    async def parse_output(self, raw_output: str | bytes, output_format: str = "text") -> dict[str, Any]:
        text = raw_output if isinstance(raw_output, str) else raw_output.decode(errors="replace")

        if output_format == "status":
            jails: list[str] = []
            for line in text.strip().split("\n"):
                if "Jail list:" in line:
                    jail_str = line.split(":", 1)[1].strip()
                    jails = [j.strip() for j in jail_str.split(",") if j.strip()]
            return {"jails": jails, "total": len(jails)}

        if output_format == "jail_status":
            info: dict[str, Any] = {}
            for line in text.strip().split("\n"):
                line = line.strip()
                if "Currently failed:" in line:
                    info["currently_failed"] = int(line.split(":")[-1].strip())
                elif "Total failed:" in line:
                    info["total_failed"] = int(line.split(":")[-1].strip())
                elif "Currently banned:" in line:
                    info["currently_banned"] = int(line.split(":")[-1].strip())
                elif "Total banned:" in line:
                    info["total_banned"] = int(line.split(":")[-1].strip())
                elif "Banned IP list:" in line:
                    ips = line.split(":", 1)[-1].strip()
                    info["banned_ips"] = [ip.strip() for ip in ips.split() if ip.strip()]
            return info

        return {"raw": text}

"""OSSEC/Wazuh host-based IDS adapter."""
from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

from netsec.adapters.base import BaseAdapter, ToolCategory, ToolInfo, ToolStatus
from netsec.adapters.process import check_binary, run_command

logger = logging.getLogger(__name__)

DEFAULT_OSSEC_DIR = "/var/ossec"


class Adapter(BaseAdapter):
    def __init__(self) -> None:
        self._binary: str | None = None
        self._status = ToolStatus.UNKNOWN
        self._ossec_dir = Path(DEFAULT_OSSEC_DIR)

    def tool_info(self) -> ToolInfo:
        return ToolInfo(
            name="ossec",
            display_name="OSSEC/Wazuh",
            category=ToolCategory.LOG_ANALYZER,
            description="Host-based intrusion detection system",
            binary_path=self._binary,
            status=self._status,
            supported_tasks=["status", "alerts", "active_responses", "agent_list"],
        )

    async def detect(self) -> bool:
        control_path = self._ossec_dir / "bin" / "ossec-control"
        if control_path.exists():
            self._binary = str(control_path)
            self._status = ToolStatus.AVAILABLE
            return True
        wazuh = await check_binary("wazuh-control")
        if wazuh:
            self._binary = wazuh
            self._ossec_dir = Path(wazuh).parent.parent
            self._status = ToolStatus.AVAILABLE
            return True
        self._status = ToolStatus.UNAVAILABLE
        return False

    async def health_check(self) -> ToolStatus:
        if not self._binary:
            return ToolStatus.UNAVAILABLE
        result = await run_command(f"{self._binary} status", timeout=10)
        if result.success and "running" in result.stdout.lower():
            self._status = ToolStatus.RUNNING
        elif self._binary:
            self._status = ToolStatus.AVAILABLE
        return self._status

    async def execute(self, task: str, params: dict[str, Any]) -> dict[str, Any]:
        if not self._binary:
            raise RuntimeError("OSSEC not available")

        match task:
            case "status":
                result = await run_command(f"{self._binary} status", timeout=10)
                return {"output": result.stdout, "success": result.success}
            case "alerts":
                return await self._read_alerts(params.get("lines", 100))
            case "active_responses":
                log_path = self._ossec_dir / "logs" / "active-responses.log"
                result = await run_command(f"tail -n {params.get('lines', 50)} {log_path}", timeout=10)
                return {"responses": result.stdout.strip().split("\n")}
            case "agent_list":
                agent_bin = self._ossec_dir / "bin" / "agent_control"
                result = await run_command(f"{agent_bin} -l", timeout=10)
                return {"output": result.stdout}
            case _:
                raise ValueError(f"Unknown task: {task}")

    async def _read_alerts(self, lines: int) -> dict[str, Any]:
        alerts_log = self._ossec_dir / "logs" / "alerts" / "alerts.json"
        if not alerts_log.exists():
            alerts_log = self._ossec_dir / "logs" / "alerts" / "alerts.log"
        if not alerts_log.exists():
            return {"alerts": [], "error": "Alerts log not found"}
        result = await run_command(f"tail -n {lines} {alerts_log}", timeout=10)
        return await self.parse_output(result.stdout, "json" if alerts_log.suffix == ".json" else "text")

    async def parse_output(self, raw_output: str | bytes, output_format: str = "text") -> dict[str, Any]:
        text = raw_output if isinstance(raw_output, str) else raw_output.decode(errors="replace")
        if output_format == "json":
            alerts = []
            for line in text.strip().split("\n"):
                try:
                    alerts.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
            return {"alerts": alerts, "total": len(alerts)}
        return {"alerts": text.strip().split("\n\n"), "total": len(text.strip().split("\n\n"))}

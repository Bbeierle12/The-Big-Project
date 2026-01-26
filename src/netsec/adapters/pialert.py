"""Pi.Alert network device monitor adapter."""
from __future__ import annotations

import json
import logging
import sqlite3
from pathlib import Path
from typing import Any

from netsec.adapters.base import BaseAdapter, ToolCategory, ToolInfo, ToolStatus
from netsec.adapters.process import check_binary, run_command

logger = logging.getLogger(__name__)

DEFAULT_DB_PATH = "/opt/pialert/db/pialert.db"


class Adapter(BaseAdapter):
    def __init__(self) -> None:
        self._db_path = Path(DEFAULT_DB_PATH)
        self._status = ToolStatus.UNKNOWN

    def tool_info(self) -> ToolInfo:
        return ToolInfo(
            name="pialert",
            display_name="Pi.Alert",
            category=ToolCategory.HOST_MONITOR,
            description="Network device presence monitor",
            status=self._status,
            supported_tasks=["list_devices", "new_devices", "events"],
        )

    async def detect(self) -> bool:
        if self._db_path.exists():
            self._status = ToolStatus.AVAILABLE
            return True
        alt_paths = [Path("/home/pi/pialert/db/pialert.db"), Path("/opt/pialert/db/pialert.db")]
        for p in alt_paths:
            if p.exists():
                self._db_path = p
                self._status = ToolStatus.AVAILABLE
                return True
        self._status = ToolStatus.UNAVAILABLE
        return False

    async def health_check(self) -> ToolStatus:
        if self._db_path.exists():
            self._status = ToolStatus.AVAILABLE
        else:
            self._status = ToolStatus.UNAVAILABLE
        return self._status

    async def execute(self, task: str, params: dict[str, Any]) -> dict[str, Any]:
        if not self._db_path.exists():
            raise RuntimeError("Pi.Alert DB not found")

        match task:
            case "list_devices":
                return self._query_devices(params.get("limit", 100))
            case "new_devices":
                return self._query_new_devices(params.get("hours", 24))
            case "events":
                return self._query_events(params.get("limit", 100))
            case _:
                raise ValueError(f"Unknown task: {task}")

    def _query_devices(self, limit: int) -> dict[str, Any]:
        try:
            conn = sqlite3.connect(str(self._db_path))
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(
                "SELECT * FROM Devices ORDER BY dev_LastConnection DESC LIMIT ?", (limit,)
            )
            devices = [dict(row) for row in cursor.fetchall()]
            conn.close()
            return {"devices": devices, "total": len(devices)}
        except Exception as e:
            return {"error": str(e)}

    def _query_new_devices(self, hours: int) -> dict[str, Any]:
        try:
            conn = sqlite3.connect(str(self._db_path))
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(
                "SELECT * FROM Devices WHERE dev_FirstConnection >= datetime('now', ? || ' hours') ORDER BY dev_FirstConnection DESC",
                (f"-{hours}",),
            )
            devices = [dict(row) for row in cursor.fetchall()]
            conn.close()
            return {"devices": devices, "total": len(devices)}
        except Exception as e:
            return {"error": str(e)}

    def _query_events(self, limit: int) -> dict[str, Any]:
        try:
            conn = sqlite3.connect(str(self._db_path))
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(
                "SELECT * FROM Events ORDER BY eve_DateTime DESC LIMIT ?", (limit,)
            )
            events = [dict(row) for row in cursor.fetchall()]
            conn.close()
            return {"events": events, "total": len(events)}
        except Exception as e:
            return {"error": str(e)}

    async def parse_output(self, raw_output: str | bytes, output_format: str = "text") -> dict[str, Any]:
        text = raw_output if isinstance(raw_output, str) else raw_output.decode(errors="replace")
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return {"raw": text}

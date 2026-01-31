"""Scan orchestration service."""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netsec.adapters.base import ToolStatus
from netsec.adapters.registry import AdapterRegistry
from netsec.core.events import Event, EventBus, EventType
from netsec.models.scan import Scan
from netsec.services.device_service import DeviceService

logger = logging.getLogger(__name__)


class ScanService:
    """Orchestrates security scans across tools."""

    def __init__(
        self,
        session: AsyncSession,
        registry: AdapterRegistry,
        event_bus: EventBus,
        device_service: DeviceService | None = None,
    ) -> None:
        self.session = session
        self.registry = registry
        self.event_bus = event_bus
        self.device_service = device_service or DeviceService(session, event_bus)

    async def create_scan(
        self,
        scan_type: str,
        tool: str,
        target: str,
        parameters: dict[str, Any] | None = None,
    ) -> Scan:
        """Create and execute a scan."""
        adapter = self.registry.get(tool)
        if adapter is None:
            raise ValueError(f"Unknown tool: {tool}")

        info = adapter.tool_info()
        if info.status != ToolStatus.AVAILABLE:
            raise RuntimeError(f"Tool not available: {tool}")

        scan = Scan(
            id=uuid4().hex,
            scan_type=scan_type,
            tool=tool,
            target=target,
            status="pending",
            parameters=parameters or {},
        )
        self.session.add(scan)
        await self.session.flush()

        # Emit scan started event
        await self.event_bus.publish(Event(
            type=EventType.SCAN_STARTED,
            source="scan_service",
            data={"scan_id": scan.id, "tool": tool, "target": target},
        ))

        # Execute asynchronously
        try:
            scan.status = "running"
            scan.started_at = datetime.now(timezone.utc)
            scan.progress = 0
            await self.session.flush()

            # Emit progress event (scan started running)
            await self.event_bus.publish(Event(
                type=EventType.SCAN_PROGRESS,
                source="scan_service",
                data={"scan_id": scan.id, "progress": 0, "status": "running"},
            ))

            # Determine task type
            task = self._map_scan_type_to_task(scan_type, tool)
            params = {"target": target, **(parameters or {})}
            result = await adapter.execute(task, params)

            if "error" in result:
                scan.status = "failed"
                scan.error_message = result["error"]
            else:
                scan.status = "completed"
                scan.results = result
                scan.result_summary = self._summarize_results(result)

                # Upsert discovered devices
                hosts = result.get("hosts", [])
                for host in hosts:
                    try:
                        await self.device_service.upsert_from_scan(host)
                    except Exception as e:
                        logger.warning("Failed to upsert device: %s", e)
                scan.devices_found = len(hosts)

            scan.completed_at = datetime.now(timezone.utc)
            scan.progress = 100
            await self.session.flush()

            await self.event_bus.publish(Event(
                type=EventType.SCAN_COMPLETED if scan.status == "completed" else EventType.SCAN_FAILED,
                source="scan_service",
                data={
                    "scan_id": scan.id,
                    "status": scan.status,
                    "devices_found": scan.devices_found,
                },
            ))

        except Exception as e:
            logger.exception("Scan failed: %s", scan.id)
            scan.status = "failed"
            scan.error_message = str(e)
            scan.completed_at = datetime.now(timezone.utc)
            await self.session.flush()

            await self.event_bus.publish(Event(
                type=EventType.SCAN_FAILED,
                source="scan_service",
                data={"scan_id": scan.id, "error": str(e)},
            ))

        return scan

    async def get_scan(self, scan_id: str) -> Scan | None:
        return await self.session.get(Scan, scan_id)

    async def list_scans(
        self, *, offset: int = 0, limit: int = 50, status: str | None = None
    ) -> list[Scan]:
        stmt = select(Scan).order_by(Scan.created_at.desc()).offset(offset).limit(limit)
        if status:
            stmt = stmt.where(Scan.status == status)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def cancel_scan(self, scan_id: str) -> Scan | None:
        scan = await self.get_scan(scan_id)
        if scan and scan.status in ("pending", "running"):
            scan.status = "cancelled"
            scan.completed_at = datetime.now(timezone.utc)
            await self.session.flush()
        return scan

    def _map_scan_type_to_task(self, scan_type: str, tool: str) -> str:
        mapping = {
            ("network", "nmap"): "quick_scan",
            ("vulnerability", "nmap"): "vuln_scan",
            ("vulnerability", "openvas"): "full_scan",
            ("traffic", "tshark"): "capture",
            ("malware", "clamav"): "scan",
        }
        return mapping.get((scan_type, tool), "quick_scan")

    def _summarize_results(self, result: dict[str, Any]) -> str:
        hosts = result.get("hosts", [])
        stats = result.get("stats", {})
        if stats:
            return f"{stats.get('hosts_up', 0)} hosts up, {stats.get('hosts_down', 0)} down"
        return f"{len(hosts)} hosts found"

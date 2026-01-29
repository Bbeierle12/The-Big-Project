"""Monitoring service for device and tool status."""
from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from netsec.adapters.base import ToolStatus
from netsec.adapters.registry import AdapterRegistry
from netsec.core.events import Event, EventBus, EventType
from netsec.models.device import Device

logger = logging.getLogger(__name__)


class MonitoringService:
    """Monitors device availability and tool health status."""

    def __init__(
        self,
        session: AsyncSession,
        event_bus: EventBus,
        registry: AdapterRegistry,
    ) -> None:
        self.session = session
        self.event_bus = event_bus
        self.registry = registry
        self._previous_tool_status: dict[str, ToolStatus] = {}

    async def check_device_availability(self, offline_threshold_minutes: int = 15) -> int:
        """Check for devices that haven't been seen recently and mark them offline.

        Returns the number of devices marked offline.
        """
        threshold = datetime.now(timezone.utc) - timedelta(minutes=offline_threshold_minutes)

        # Find devices that are online but haven't been seen since threshold
        stmt = select(Device).where(
            Device.status == "online",
            Device.last_seen < threshold,
        )
        result = await self.session.execute(stmt)
        stale_devices = list(result.scalars().all())

        count = 0
        for device in stale_devices:
            device.status = "offline"
            count += 1

            await self.event_bus.publish(Event(
                type=EventType.DEVICE_OFFLINE,
                source="monitoring_service",
                data={
                    "device_id": device.id,
                    "ip": device.ip_address,
                    "hostname": device.hostname,
                    "last_seen": device.last_seen.isoformat() if device.last_seen else None,
                },
            ))

        if count > 0:
            await self.session.flush()
            logger.info("Marked %d devices as offline (threshold: %d min)", count, offline_threshold_minutes)

        return count

    async def check_tool_health(self) -> dict[str, str]:
        """Check health of all tools and emit events for status changes.

        Returns dict of tool_name -> current_status.
        """
        results = await self.registry.health_check_all()
        status_changes: dict[str, str] = {}

        for tool_name, status in results.items():
            previous = self._previous_tool_status.get(tool_name)

            if previous is not None and previous != status:
                # Status changed
                if status == ToolStatus.AVAILABLE:
                    event_type = EventType.TOOL_ONLINE
                else:
                    event_type = EventType.TOOL_OFFLINE

                await self.event_bus.publish(Event(
                    type=event_type,
                    source="monitoring_service",
                    data={
                        "tool": tool_name,
                        "status": status.value,
                        "previous_status": previous.value if previous else None,
                    },
                ))
                status_changes[tool_name] = status.value
                logger.info("Tool %s status changed: %s -> %s", tool_name, previous.value if previous else "unknown", status.value)

            self._previous_tool_status[tool_name] = status

        return {name: status.value for name, status in results.items()}


async def run_device_availability_check(
    session: AsyncSession,
    event_bus: EventBus,
    registry: AdapterRegistry,
    offline_threshold_minutes: int = 15,
) -> int:
    """Standalone function to run device availability check (for scheduler)."""
    service = MonitoringService(session, event_bus, registry)
    return await service.check_device_availability(offline_threshold_minutes)


async def run_tool_health_check(
    session: AsyncSession,
    event_bus: EventBus,
    registry: AdapterRegistry,
) -> dict[str, str]:
    """Standalone function to run tool health check (for scheduler)."""
    service = MonitoringService(session, event_bus, registry)
    return await service.check_tool_health()

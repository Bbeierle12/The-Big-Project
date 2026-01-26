"""Device management service."""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from sqlalchemy import select, or_
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from netsec.core.events import Event, EventBus, EventType
from netsec.models.device import Device, Port

logger = logging.getLogger(__name__)


class DeviceService:
    """Manages network devices and their ports."""

    def __init__(self, session: AsyncSession, event_bus: EventBus) -> None:
        self.session = session
        self.event_bus = event_bus

    async def upsert_from_scan(self, host_data: dict[str, Any]) -> Device:
        """Create or update a device from scan results.

        Merges data if device already exists (matched by IP or MAC).
        """
        addresses = host_data.get("addresses", {})
        ip = addresses.get("ipv4", "")
        mac = addresses.get("mac")
        vendor = addresses.get("vendor")
        hostnames = host_data.get("hostnames", [])
        hostname = hostnames[0]["name"] if hostnames else None

        # Try to find existing device
        device = await self._find_device(ip, mac)
        now = datetime.now(timezone.utc)

        if device is None:
            device = Device(
                id=uuid4().hex,
                ip_address=ip,
                mac_address=mac,
                hostname=hostname,
                vendor=vendor,
                status=host_data.get("status", "online"),
                first_seen=now,
                last_seen=now,
            )
            self.session.add(device)
            event_type = EventType.DEVICE_DISCOVERED
        else:
            # Merge data
            if mac and not device.mac_address:
                device.mac_address = mac
            if hostname and not device.hostname:
                device.hostname = hostname
            if vendor and not device.vendor:
                device.vendor = vendor
            device.last_seen = now
            device.status = host_data.get("status", device.status)
            event_type = EventType.DEVICE_UPDATED

        # Update OS info
        os_info = host_data.get("os", {})
        if os_info.get("name"):
            device.os_family = os_info["name"]

        # Update ports
        for port_data in host_data.get("ports", []):
            await self._upsert_port(device, port_data)

        await self.session.flush()

        await self.event_bus.publish(Event(
            type=event_type,
            source="device_service",
            data={
                "device_id": device.id,
                "ip": device.ip_address,
                "hostname": device.hostname,
            },
        ))

        return device

    async def get_device(self, device_id: str) -> Device | None:
        stmt = select(Device).options(selectinload(Device.ports)).where(Device.id == device_id)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def list_devices(
        self,
        *,
        offset: int = 0,
        limit: int = 100,
        status: str | None = None,
    ) -> list[Device]:
        stmt = (
            select(Device)
            .options(selectinload(Device.ports))
            .order_by(Device.last_seen.desc())
            .offset(offset)
            .limit(limit)
        )
        if status:
            stmt = stmt.where(Device.status == status)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def update_device(self, device_id: str, **kwargs: Any) -> Device | None:
        device = await self.get_device(device_id)
        if device is None:
            return None
        for key, value in kwargs.items():
            if value is not None and hasattr(device, key):
                setattr(device, key, value)
        await self.session.flush()
        return device

    async def delete_device(self, device_id: str) -> bool:
        device = await self.get_device(device_id)
        if device is None:
            return False
        await self.session.delete(device)
        await self.session.flush()
        return True

    async def _find_device(self, ip: str, mac: str | None) -> Device | None:
        conditions = [Device.ip_address == ip]
        if mac:
            conditions.append(Device.mac_address == mac)
        stmt = (
            select(Device)
            .options(selectinload(Device.ports))
            .where(or_(*conditions))
        )
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def _upsert_port(self, device: Device, port_data: dict[str, Any]) -> Port:
        port_num = port_data.get("port", 0)
        protocol = port_data.get("protocol", "tcp")

        # Find existing port
        existing = None
        for p in device.ports:
            if p.port_number == port_num and p.protocol == protocol:
                existing = p
                break

        if existing is None:
            port = Port(
                id=uuid4().hex,
                device_id=device.id,
                port_number=port_num,
                protocol=protocol,
                state=port_data.get("state", "open"),
                service_name=port_data.get("service"),
                service_version=port_data.get("version"),
                banner=port_data.get("product"),
            )
            self.session.add(port)
            device.ports.append(port)
            return port
        else:
            existing.state = port_data.get("state", existing.state)
            if port_data.get("service"):
                existing.service_name = port_data["service"]
            if port_data.get("version"):
                existing.service_version = port_data["version"]
            return existing

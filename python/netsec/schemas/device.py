"""Device API schemas."""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel


class PortOut(BaseModel):
    id: str
    port_number: int
    protocol: str
    state: str
    service_name: Optional[str] = None
    service_version: Optional[str] = None
    banner: Optional[str] = None

    model_config = {"from_attributes": True}


class DeviceOut(BaseModel):
    id: str
    ip_address: str
    mac_address: Optional[str] = None
    hostname: Optional[str] = None
    vendor: Optional[str] = None
    os_family: Optional[str] = None
    os_version: Optional[str] = None
    device_type: Optional[str] = None
    status: str
    first_seen: datetime
    last_seen: datetime
    notes: Optional[str] = None
    ports: list[PortOut] = []
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class DeviceUpdate(BaseModel):
    hostname: Optional[str] = None
    device_type: Optional[str] = None
    notes: Optional[str] = None
    status: Optional[str] = None

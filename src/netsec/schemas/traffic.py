"""Traffic flow API schemas."""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel


class TrafficFlowOut(BaseModel):
    id: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str
    bytes_sent: int
    bytes_received: int
    packets_sent: int
    packets_received: int
    started_at: datetime
    ended_at: Optional[datetime] = None
    application: Optional[str] = None
    country_src: Optional[str] = None
    country_dst: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}

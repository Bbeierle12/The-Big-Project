"""Alert API schemas."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel


class AlertOut(BaseModel):
    id: str
    title: str
    description: Optional[str] = None
    severity: str
    status: str
    source_tool: str
    source_event_id: Optional[str] = None
    category: Optional[str] = None
    device_ip: Optional[str] = None
    device_id: Optional[str] = None
    fingerprint: Optional[str] = None
    count: int
    first_seen: datetime
    last_seen: datetime
    raw_data: Optional[dict[str, Any]] = None
    correlation_id: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class AlertUpdate(BaseModel):
    status: Optional[str] = None
    severity: Optional[str] = None
    notes: Optional[str] = None

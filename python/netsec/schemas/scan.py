"""Scan API schemas."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel


class ScanCreate(BaseModel):
    scan_type: str  # network, vulnerability, traffic, malware
    tool: str
    target: str
    parameters: Optional[dict[str, Any]] = None


class ScanOut(BaseModel):
    id: str
    scan_type: str
    tool: str
    target: str
    status: str
    progress: int
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    result_summary: Optional[str] = None
    error_message: Optional[str] = None
    parameters: Optional[dict[str, Any]] = None
    results: Optional[dict[str, Any]] = None
    devices_found: int
    alerts_generated: int
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}

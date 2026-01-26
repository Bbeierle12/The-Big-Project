"""Scan model."""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, Integer, String, Text, JSON
from sqlalchemy.orm import Mapped, mapped_column

from netsec.models.base import Base


class Scan(Base):
    __tablename__ = "scans"

    scan_type: Mapped[str] = mapped_column(String(50), index=True)  # network, vulnerability, traffic, malware
    tool: Mapped[str] = mapped_column(String(50))
    target: Mapped[str] = mapped_column(String(500))
    status: Mapped[str] = mapped_column(String(20), default="pending", index=True)  # pending, running, completed, failed, cancelled
    progress: Mapped[int] = mapped_column(Integer, default=0)  # 0-100
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    result_summary: Mapped[Optional[str]] = mapped_column(Text)
    error_message: Mapped[Optional[str]] = mapped_column(Text)
    parameters: Mapped[Optional[dict]] = mapped_column(JSON)
    results: Mapped[Optional[dict]] = mapped_column(JSON)
    devices_found: Mapped[int] = mapped_column(Integer, default=0)
    alerts_generated: Mapped[int] = mapped_column(Integer, default=0)

"""Alert model."""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, Integer, String, Text, JSON
from sqlalchemy.orm import Mapped, mapped_column

from netsec.models.base import Base


class Alert(Base):
    __tablename__ = "alerts"

    title: Mapped[str] = mapped_column(String(500))
    description: Mapped[Optional[str]] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(20), index=True)  # critical, high, medium, low, info
    status: Mapped[str] = mapped_column(String(20), default="open", index=True)  # open, acknowledged, resolved, false_positive
    source_tool: Mapped[str] = mapped_column(String(50), index=True)
    source_event_id: Mapped[Optional[str]] = mapped_column(String(255))
    category: Mapped[Optional[str]] = mapped_column(String(100))
    device_ip: Mapped[Optional[str]] = mapped_column(String(45), index=True)
    device_id: Mapped[Optional[str]] = mapped_column(String(32), index=True)
    fingerprint: Mapped[Optional[str]] = mapped_column(String(64), index=True)  # dedup hash
    count: Mapped[int] = mapped_column(Integer, default=1)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    raw_data: Mapped[Optional[dict]] = mapped_column(JSON)
    correlation_id: Mapped[Optional[str]] = mapped_column(String(32), index=True)
    notes: Mapped[Optional[str]] = mapped_column(Text)  # User-added notes/comments

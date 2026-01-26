"""Traffic flow model."""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import BigInteger, DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from netsec.models.base import Base


class TrafficFlow(Base):
    __tablename__ = "traffic_flows"

    src_ip: Mapped[str] = mapped_column(String(45), index=True)
    src_port: Mapped[int] = mapped_column(Integer)
    dst_ip: Mapped[str] = mapped_column(String(45), index=True)
    dst_port: Mapped[int] = mapped_column(Integer)
    protocol: Mapped[str] = mapped_column(String(10))
    bytes_sent: Mapped[int] = mapped_column(BigInteger, default=0)
    bytes_received: Mapped[int] = mapped_column(BigInteger, default=0)
    packets_sent: Mapped[int] = mapped_column(BigInteger, default=0)
    packets_received: Mapped[int] = mapped_column(BigInteger, default=0)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    ended_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    application: Mapped[Optional[str]] = mapped_column(String(100))
    country_src: Mapped[Optional[str]] = mapped_column(String(2))
    country_dst: Mapped[Optional[str]] = mapped_column(String(2))

"""Device and Port models."""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from netsec.models.base import Base


class Device(Base):
    __tablename__ = "devices"

    ip_address: Mapped[str] = mapped_column(String(45), index=True)
    mac_address: Mapped[Optional[str]] = mapped_column(String(17), index=True)
    hostname: Mapped[Optional[str]] = mapped_column(String(255))
    vendor: Mapped[Optional[str]] = mapped_column(String(255))
    os_family: Mapped[Optional[str]] = mapped_column(String(100))
    os_version: Mapped[Optional[str]] = mapped_column(String(100))
    device_type: Mapped[Optional[str]] = mapped_column(String(50))
    status: Mapped[str] = mapped_column(String(20), default="online")
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    notes: Mapped[Optional[str]] = mapped_column(Text)

    ports: Mapped[list[Port]] = relationship(back_populates="device", cascade="all, delete-orphan")


class Port(Base):
    __tablename__ = "ports"

    device_id: Mapped[str] = mapped_column(String(32), ForeignKey("devices.id"), index=True)
    port_number: Mapped[int] = mapped_column(Integer)
    protocol: Mapped[str] = mapped_column(String(10), default="tcp")
    state: Mapped[str] = mapped_column(String(20), default="open")
    service_name: Mapped[Optional[str]] = mapped_column(String(100))
    service_version: Mapped[Optional[str]] = mapped_column(String(255))
    banner: Mapped[Optional[str]] = mapped_column(Text)

    device: Mapped[Device] = relationship(back_populates="ports")

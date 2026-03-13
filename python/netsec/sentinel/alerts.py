"""Helpers to ingest Sentinel findings into the main alert pipeline."""
from __future__ import annotations

from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from netsec.core.events import EventBus
from netsec.services.alert_service import AlertService


async def ingest_raw_alerts(
    *,
    session: AsyncSession,
    event_bus: EventBus,
    alerts: list[dict[str, Any]],
    source_tool: str = "sentinel",
) -> dict[str, Any]:
    service = AlertService(session=session, event_bus=event_bus)
    created_ids: list[str] = []
    deduped = 0

    for alert in alerts:
        created = await service.process_raw_alert(source_tool, alert)
        if created is None:
            deduped += 1
        else:
            created_ids.append(created.id)

    return {
        "submitted": len(alerts),
        "created": len(created_ids),
        "deduped": deduped,
        "alert_ids": created_ids,
    }

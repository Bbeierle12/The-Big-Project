"""Overview aggregator — single endpoint for the overview dashboard."""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from netsec import __version__
from netsec.db.session import get_session
from netsec.schemas.alert import AlertOut
from netsec.schemas.scan import ScanOut
from netsec.services.alert_service import AlertService
from netsec.services.scan_service import ScanService

router = APIRouter()


@router.get("/")
async def get_overview(
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Aggregated overview for the dashboard — replaces 6 parallel fetches."""
    event_bus = request.app.state.event_bus
    registry = request.app.state.adapter_registry

    alert_service = AlertService(session=session, event_bus=event_bus)
    scan_service = ScanService(session=session, registry=registry, event_bus=event_bus)

    # Run all queries concurrently
    alerts_task = alert_service.list_alerts(offset=0, limit=6)
    stats_task = alert_service.get_alert_stats()
    scans_task = scan_service.list_scans(offset=0, limit=6)
    tools_task = registry.health_check_all()

    sentinel_adapter = registry.get("sentinel")
    sentinel_task = (
        sentinel_adapter.execute("status", {})
        if sentinel_adapter is not None
        else asyncio.sleep(0, result=None)
    )

    alerts, alert_stats, scans, tools_health, sentinel = await asyncio.gather(
        alerts_task, stats_task, scans_task, tools_task, sentinel_task,
    )

    return {
        "health": {
            "status": "healthy",
            "version": __version__,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
        "alerts": [AlertOut.model_validate(a).model_dump() for a in alerts],
        "alert_stats": alert_stats,
        "scans": [ScanOut.model_validate(s).model_dump() for s in scans],
        "sentinel": sentinel or {},
        "tools_health": [
            {"name": name, "status": status.value}
            for name, status in tools_health.items()
        ],
    }

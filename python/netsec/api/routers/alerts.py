"""Alerts router."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession

from netsec.db.session import get_session
from netsec.schemas.alert import AlertOut, AlertUpdate
from netsec.services.alert_service import AlertService

router = APIRouter()


def _get_alert_service(request: Request, session: AsyncSession = Depends(get_session)) -> AlertService:
    return AlertService(session=session, event_bus=request.app.state.event_bus)


@router.get("/", response_model=list[AlertOut])
async def list_alerts(
    offset: int = 0,
    limit: int = 50,
    severity: str | None = None,
    status: str | None = None,
    source_tool: str | None = None,
    service: AlertService = Depends(_get_alert_service),
) -> list[AlertOut]:
    """List alerts with optional filters."""
    alerts = await service.list_alerts(
        offset=offset, limit=limit, severity=severity, status=status, source_tool=source_tool,
    )
    return [AlertOut.model_validate(a) for a in alerts]


@router.get("/stats")
async def alert_stats(service: AlertService = Depends(_get_alert_service)) -> dict:
    """Get alert statistics."""
    return await service.get_alert_stats()


@router.get("/{alert_id}", response_model=AlertOut)
async def get_alert(
    alert_id: str,
    service: AlertService = Depends(_get_alert_service),
) -> AlertOut:
    """Get alert details."""
    alert = await service.get_alert(alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return AlertOut.model_validate(alert)


@router.patch("/{alert_id}", response_model=AlertOut)
async def update_alert(
    alert_id: str,
    body: AlertUpdate,
    service: AlertService = Depends(_get_alert_service),
) -> AlertOut:
    """Update alert status."""
    if body.status:
        alert = await service.update_alert_status(alert_id, body.status)
    else:
        alert = await service.get_alert(alert_id)
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return AlertOut.model_validate(alert)

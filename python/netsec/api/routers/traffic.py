"""Traffic flow router."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netsec.db.session import get_session
from netsec.models.traffic import TrafficFlow
from netsec.schemas.traffic import TrafficFlowOut

router = APIRouter()


@router.get("/", response_model=list[TrafficFlowOut])
async def list_traffic_flows(
    offset: int = 0,
    limit: int = 100,
    src_ip: str | None = None,
    dst_ip: str | None = None,
    protocol: str | None = None,
    session: AsyncSession = Depends(get_session),
) -> list[TrafficFlowOut]:
    stmt = select(TrafficFlow).order_by(TrafficFlow.started_at.desc()).offset(offset).limit(limit)
    if src_ip:
        stmt = stmt.where(TrafficFlow.src_ip == src_ip)
    if dst_ip:
        stmt = stmt.where(TrafficFlow.dst_ip == dst_ip)
    if protocol:
        stmt = stmt.where(TrafficFlow.protocol == protocol)
    result = await session.execute(stmt)
    return [TrafficFlowOut.model_validate(f) for f in result.scalars().all()]

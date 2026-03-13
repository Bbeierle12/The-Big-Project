"""Sentinel router."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from netsec.db.session import get_session
from netsec.sentinel.alerts import ingest_raw_alerts

router = APIRouter()


class FeedRefreshRequest(BaseModel):
    force: bool = True


class VulnScanRequest(BaseModel):
    force: bool = False
    refresh_feeds: bool = True


class CorrelateRequest(BaseModel):
    refresh_feeds: bool = True
    scan_vulns: bool = True
    ingest_alerts: bool = True


def _get_sentinel_adapter(request: Request):
    registry = getattr(request.app.state, "adapter_registry", None)
    if registry is None:
        raise HTTPException(status_code=503, detail="Adapter registry not initialized")
    adapter = registry.get("sentinel")
    if adapter is None:
        raise HTTPException(status_code=503, detail="Sentinel adapter not available")
    return adapter


@router.post("/collect")
async def run_collect(request: Request) -> dict:
    adapter = _get_sentinel_adapter(request)
    return await adapter.execute("collect", {})


@router.get("/status")
async def get_status(request: Request) -> dict:
    adapter = _get_sentinel_adapter(request)
    return await adapter.execute("status", {})


@router.get("/osint/feeds")
async def get_feed_status(request: Request) -> dict:
    adapter = _get_sentinel_adapter(request)
    return await adapter.execute("feeds_status", {})


@router.post("/osint/feeds")
async def refresh_feeds(body: FeedRefreshRequest, request: Request) -> dict:
    adapter = _get_sentinel_adapter(request)
    return await adapter.execute("feeds_update", body.model_dump())


@router.get("/osint/reputation/{ip}")
async def check_reputation(ip: str, request: Request) -> dict:
    adapter = _get_sentinel_adapter(request)
    return await adapter.execute("reputation_check", {"indicator": ip})


@router.get("/vulns")
async def list_vulns(
    request: Request,
    limit: int = Query(default=50, ge=1, le=500),
) -> dict:
    adapter = _get_sentinel_adapter(request)
    return await adapter.execute("vuln_report", {"limit": limit})


@router.post("/vulns/scan")
async def run_vuln_scan(body: VulnScanRequest, request: Request) -> dict:
    adapter = _get_sentinel_adapter(request)
    return await adapter.execute("vuln_scan", body.model_dump())


@router.post("/correlate")
async def run_correlation(
    body: CorrelateRequest,
    request: Request,
    session: AsyncSession = Depends(get_session),
) -> dict:
    adapter = _get_sentinel_adapter(request)
    params = body.model_dump()
    ingest_alerts = params.pop("ingest_alerts")
    result = await adapter.execute("correlate", params)
    if ingest_alerts:
        result["ingestion"] = await ingest_raw_alerts(
            session=session,
            event_bus=request.app.state.event_bus,
            alerts=list(result.get("alerts", [])),
            source_tool="sentinel",
        )
    return result

"""Scans router."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession

from netsec.db.session import get_session
from netsec.schemas.scan import ScanCreate, ScanOut
from netsec.services.scan_service import ScanService

router = APIRouter()


def _get_scan_service(request: Request, session: AsyncSession = Depends(get_session)) -> ScanService:
    return ScanService(
        session=session,
        registry=request.app.state.adapter_registry,
        event_bus=request.app.state.event_bus,
    )


@router.post("/", response_model=ScanOut, status_code=201)
async def create_scan(
    body: ScanCreate,
    service: ScanService = Depends(_get_scan_service),
) -> ScanOut:
    """Launch a new scan."""
    try:
        scan = await service.create_scan(
            scan_type=body.scan_type,
            tool=body.tool,
            target=body.target,
            parameters=body.parameters,
        )
        return ScanOut.model_validate(scan)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except RuntimeError as e:
        raise HTTPException(status_code=503, detail=str(e))


@router.get("/", response_model=list[ScanOut])
async def list_scans(
    offset: int = 0,
    limit: int = 50,
    status: str | None = None,
    service: ScanService = Depends(_get_scan_service),
) -> list[ScanOut]:
    """List scans."""
    scans = await service.list_scans(offset=offset, limit=limit, status=status)
    return [ScanOut.model_validate(s) for s in scans]


@router.get("/{scan_id}", response_model=ScanOut)
async def get_scan(
    scan_id: str,
    service: ScanService = Depends(_get_scan_service),
) -> ScanOut:
    """Get scan details."""
    scan = await service.get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return ScanOut.model_validate(scan)


@router.post("/{scan_id}/cancel", response_model=ScanOut)
async def cancel_scan(
    scan_id: str,
    service: ScanService = Depends(_get_scan_service),
) -> ScanOut:
    """Cancel a running scan."""
    scan = await service.cancel_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return ScanOut.model_validate(scan)

"""Vulnerabilities router."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netsec.db.session import get_session
from netsec.models.vulnerability import Vulnerability
from netsec.schemas.vulnerability import VulnerabilityOut, VulnerabilityUpdate

router = APIRouter()


@router.get("/", response_model=list[VulnerabilityOut])
async def list_vulnerabilities(
    offset: int = 0,
    limit: int = 50,
    severity: str | None = None,
    status: str | None = None,
    session: AsyncSession = Depends(get_session),
) -> list[VulnerabilityOut]:
    stmt = select(Vulnerability).order_by(Vulnerability.created_at.desc()).offset(offset).limit(limit)
    if severity:
        stmt = stmt.where(Vulnerability.severity == severity)
    if status:
        stmt = stmt.where(Vulnerability.status == status)
    result = await session.execute(stmt)
    return [VulnerabilityOut.model_validate(v) for v in result.scalars().all()]


@router.get("/{vuln_id}", response_model=VulnerabilityOut)
async def get_vulnerability(
    vuln_id: str,
    session: AsyncSession = Depends(get_session),
) -> VulnerabilityOut:
    vuln = await session.get(Vulnerability, vuln_id)
    if vuln is None:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    return VulnerabilityOut.model_validate(vuln)


@router.patch("/{vuln_id}", response_model=VulnerabilityOut)
async def update_vulnerability(
    vuln_id: str,
    body: VulnerabilityUpdate,
    session: AsyncSession = Depends(get_session),
) -> VulnerabilityOut:
    vuln = await session.get(Vulnerability, vuln_id)
    if vuln is None:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    update_data = body.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(vuln, key, value)
    await session.flush()
    return VulnerabilityOut.model_validate(vuln)

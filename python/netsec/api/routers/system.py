"""System router — health checks and server info."""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter

from netsec import __version__

router = APIRouter()


@router.get("/health")
async def health_check() -> dict:
    """System health check."""
    return {
        "status": "healthy",
        "version": __version__,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/info")
async def system_info() -> dict:
    """System information."""
    import platform
    import sys

    return {
        "version": __version__,
        "python_version": sys.version,
        "platform": platform.platform(),
        "hostname": platform.node(),
    }

"""Authentication middleware — API key validation."""
from __future__ import annotations

import logging
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from netsec.core.config import get_settings

logger = logging.getLogger(__name__)

# Paths that don't require authentication
PUBLIC_PATHS = {"/api/system/health", "/docs", "/openapi.json", "/redoc"}


class ApiKeyMiddleware(BaseHTTPMiddleware):
    """Validates API key in X-API-Key header or api_key query param."""

    async def dispatch(self, request: Request, call_next):
        settings = get_settings()

        if not settings.auth.enabled:
            return await call_next(request)

        # Skip auth for public paths
        if request.url.path in PUBLIC_PATHS:
            return await call_next(request)

        # Skip WebSocket (handled separately)
        if request.url.path.startswith("/ws"):
            return await call_next(request)

        # Check API key
        api_key = request.headers.get("X-API-Key") or request.query_params.get("api_key")

        if not api_key:
            return JSONResponse(
                status_code=401,
                content={"detail": "Missing API key. Provide X-API-Key header or api_key query param."},
            )

        if api_key != settings.auth.api_key:
            logger.warning("Invalid API key attempt from %s", request.client.host if request.client else "unknown")
            return JSONResponse(
                status_code=403,
                content={"detail": "Invalid API key."},
            )

        return await call_next(request)

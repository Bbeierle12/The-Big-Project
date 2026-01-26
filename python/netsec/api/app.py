"""FastAPI application factory."""
from __future__ import annotations

from contextlib import asynccontextmanager
from collections.abc import AsyncGenerator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from netsec.core.config import get_settings
from netsec.core.events import EventBus
from netsec.core.logging import setup_logging
from netsec.core.scheduler import Scheduler
from netsec.db.session import init_db, close_db
from netsec.adapters.registry import AdapterRegistry
from netsec.api.websocket import register_ws_forwarding


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan: startup and shutdown."""
    settings = get_settings()
    setup_logging(level=settings.logging.level, fmt=settings.logging.format)

    # Initialize database
    await init_db()

    # Start event bus
    event_bus = EventBus()
    await event_bus.start()
    app.state.event_bus = event_bus

    # Register WebSocket forwarding
    register_ws_forwarding(event_bus)

    # Discover and initialize adapters
    registry = AdapterRegistry()
    await registry.discover()
    await registry.init_all()
    app.state.adapter_registry = registry

    # Start scheduler
    scheduler = Scheduler()
    await scheduler.start()
    app.state.scheduler = scheduler

    yield

    # Shutdown
    await scheduler.stop()
    await registry.shutdown_all()
    await event_bus.stop()
    await close_db()


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    settings = get_settings()

    app = FastAPI(
        title="NetSec Orchestrator",
        description="Security orchestration backend for network monitoring tools",
        version="0.1.0",
        lifespan=lifespan,
    )

    # CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # API key auth middleware (only active when auth.enabled=true)
    if settings.auth.enabled:
        from netsec.api.middleware import ApiKeyMiddleware
        app.add_middleware(ApiKeyMiddleware)

    # Register routers
    from netsec.api.routers import (
        system, tools, scans, devices, alerts,
        scheduler, vulnerabilities, traffic, ws,
    )
    app.include_router(system.router, prefix="/api/system", tags=["system"])
    app.include_router(tools.router, prefix="/api/tools", tags=["tools"])
    app.include_router(scans.router, prefix="/api/scans", tags=["scans"])
    app.include_router(devices.router, prefix="/api/devices", tags=["devices"])
    app.include_router(alerts.router, prefix="/api/alerts", tags=["alerts"])
    app.include_router(scheduler.router, prefix="/api/scheduler", tags=["scheduler"])
    app.include_router(vulnerabilities.router, prefix="/api/vulnerabilities", tags=["vulnerabilities"])
    app.include_router(traffic.router, prefix="/api/traffic", tags=["traffic"])
    app.include_router(ws.router)

    return app

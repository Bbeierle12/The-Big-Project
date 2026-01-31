"""FastAPI application factory."""
from __future__ import annotations

from contextlib import asynccontextmanager
from collections.abc import AsyncGenerator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from netsec.core.config import get_settings
from netsec.core.events import Event, EventBus, EventType
from netsec.core.logging import setup_logging
from netsec.core.scheduler import Scheduler
from netsec.db.session import init_db, close_db, get_session_context
from netsec.adapters.registry import AdapterRegistry
from netsec.api.websocket import register_ws_forwarding
from netsec.services.monitoring_service import MonitoringService


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

    # Start scheduler with task handler
    scheduler = Scheduler()

    # Create shared monitoring service state for tool health tracking
    _tool_status_cache: dict[str, str] = {}

    async def task_handler(task_type: str, task_params: dict) -> None:
        """Handle scheduled tasks."""
        async with get_session_context() as session:
            if task_type == "device_availability_check":
                service = MonitoringService(session, event_bus, registry)
                service._previous_tool_status = {}  # Device check doesn't need tool state
                await service.check_device_availability(
                    offline_threshold_minutes=task_params.get("offline_threshold_minutes", 15)
                )
            elif task_type == "tool_health_check":
                service = MonitoringService(session, event_bus, registry)
                # Restore previous state for delta detection
                from netsec.adapters.base import ToolStatus
                service._previous_tool_status = {
                    k: ToolStatus(v) for k, v in _tool_status_cache.items()
                }
                await service.check_tool_health()
                # Save current state
                _tool_status_cache.clear()
                _tool_status_cache.update({
                    k: v.value for k, v in service._previous_tool_status.items()
                })
            elif task_type == "scan":
                # For future scheduled scans
                pass

    scheduler.set_task_handler(task_handler)
    await scheduler.start()
    app.state.scheduler = scheduler

    # Register default monitoring jobs
    scheduler.add_job(
        name="Device Availability Monitor",
        trigger_type="interval",
        trigger_args={"minutes": 5},
        task_type="device_availability_check",
        task_params={"offline_threshold_minutes": 15},
    )
    scheduler.add_job(
        name="Tool Health Monitor",
        trigger_type="interval",
        trigger_args={"minutes": 2},
        task_type="tool_health_check",
        task_params={},
    )

    # Publish system startup event
    await event_bus.publish(Event(
        type=EventType.SYSTEM_STARTUP,
        source="app",
        data={"version": "0.1.0"},
    ))

    yield

    # Publish system shutdown event
    await event_bus.publish(Event(
        type=EventType.SYSTEM_SHUTDOWN,
        source="app",
        data={},
    ))

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
        scheduler, vulnerabilities, traffic, ws, terminal,
    )
    app.include_router(system.router, prefix="/api/system", tags=["system"])
    app.include_router(tools.router, prefix="/api/tools", tags=["tools"])
    app.include_router(scans.router, prefix="/api/scans", tags=["scans"])
    app.include_router(devices.router, prefix="/api/devices", tags=["devices"])
    app.include_router(alerts.router, prefix="/api/alerts", tags=["alerts"])
    app.include_router(scheduler.router, prefix="/api/scheduler", tags=["scheduler"])
    app.include_router(vulnerabilities.router, prefix="/api/vulnerabilities", tags=["vulnerabilities"])
    app.include_router(traffic.router, prefix="/api/traffic", tags=["traffic"])
    app.include_router(terminal.router, prefix="/api/terminal", tags=["terminal"])
    app.include_router(ws.router)

    return app

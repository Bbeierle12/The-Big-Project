"""WebSocket connection manager and event forwarding."""
from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass, field

from fastapi import WebSocket, WebSocketDisconnect

from netsec.core.events import Event, EventBus

logger = logging.getLogger(__name__)


class ConnectionManager:
    """Manages active WebSocket connections."""

    def __init__(self) -> None:
        self._connections: list[WebSocket] = []
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        async with self._lock:
            self._connections.append(websocket)
        logger.info("WebSocket client connected, total: %d", len(self._connections))

    async def disconnect(self, websocket: WebSocket) -> None:
        async with self._lock:
            if websocket in self._connections:
                self._connections.remove(websocket)
        logger.info("WebSocket client disconnected, total: %d", len(self._connections))

    async def broadcast(self, message: dict) -> None:
        """Send message to all connected clients."""
        payload = json.dumps(message, default=str)
        async with self._lock:
            stale: list[WebSocket] = []
            for ws in self._connections:
                try:
                    await ws.send_text(payload)
                except Exception:
                    stale.append(ws)
            for ws in stale:
                self._connections.remove(ws)

    @property
    def active_count(self) -> int:
        return len(self._connections)


# Singleton manager
ws_manager = ConnectionManager()


async def event_to_ws_handler(event: Event) -> None:
    """EventBus handler that forwards events to WebSocket clients."""
    await ws_manager.broadcast({
        "type": event.type.value,
        "id": event.id,
        "timestamp": event.timestamp.isoformat(),
        "source": event.source,
        "data": event.data,
    })


def register_ws_forwarding(event_bus: EventBus) -> None:
    """Subscribe the WS forwarder to all events."""
    event_bus.subscribe_all(event_to_ws_handler)

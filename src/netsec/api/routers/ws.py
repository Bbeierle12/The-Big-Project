"""WebSocket endpoint."""
from __future__ import annotations

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from netsec.api.websocket import ws_manager

router = APIRouter()


@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket) -> None:
    """WebSocket endpoint for real-time event streaming."""
    await ws_manager.connect(websocket)
    try:
        while True:
            # Keep connection alive, handle client messages
            data = await websocket.receive_text()
            # Could handle client commands here (subscribe/unsubscribe, etc.)
    except WebSocketDisconnect:
        await ws_manager.disconnect(websocket)

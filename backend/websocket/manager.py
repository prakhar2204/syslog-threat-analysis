"""
SysLog Threat Analysis — WebSocket Connection Manager

Manages WebSocket client connections and broadcasts events
from the backend pipeline to all connected frontends.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import Any

from fastapi import WebSocket

logger = logging.getLogger(__name__)


class ConnectionManager:
    """
    Tracks active WebSocket connections and broadcasts messages.

    Message format sent to clients:
    {
        "type": "new_logs" | "new_alert" | "new_incident" | "stats_update" | "status",
        "data": { ... },
        "timestamp": "..."
    }
    """

    def __init__(self) -> None:
        self._connections: list[WebSocket] = []

    @property
    def client_count(self) -> int:
        return len(self._connections)

    async def connect(self, websocket: WebSocket) -> None:
        """Accept and register a WebSocket connection."""
        await websocket.accept()
        self._connections.append(websocket)
        logger.info("WebSocket client connected. Total: %d", len(self._connections))

    def disconnect(self, websocket: WebSocket) -> None:
        """Remove a WebSocket connection."""
        if websocket in self._connections:
            self._connections.remove(websocket)
        logger.info("WebSocket client disconnected. Total: %d", len(self._connections))

    async def broadcast(self, msg_type: str, data: Any) -> None:
        """
        Broadcast a message to all connected clients.

        Silently removes clients that have disconnected.
        """
        if not self._connections:
            return

        message = json.dumps({
            "type": msg_type,
            "data": self._serialize(data),
            "timestamp": datetime.now().isoformat(),
        }, default=str)

        disconnected: list[WebSocket] = []
        for ws in self._connections:
            try:
                await ws.send_text(message)
            except Exception:
                disconnected.append(ws)

        for ws in disconnected:
            self.disconnect(ws)

    async def send_personal(self, websocket: WebSocket, msg_type: str, data: Any) -> None:
        """Send a message to a specific client."""
        message = json.dumps({
            "type": msg_type,
            "data": self._serialize(data),
            "timestamp": datetime.now().isoformat(),
        }, default=str)
        try:
            await websocket.send_text(message)
        except Exception:
            self.disconnect(websocket)

    def _serialize(self, obj: Any) -> Any:
        """Convert Pydantic models and other objects to JSON-safe dicts."""
        if hasattr(obj, "model_dump"):
            return obj.model_dump(mode="json")
        if isinstance(obj, list):
            return [self._serialize(item) for item in obj]
        if isinstance(obj, dict):
            return {k: self._serialize(v) for k, v in obj.items()}
        return obj


# Global instance used by the application
ws_manager = ConnectionManager()

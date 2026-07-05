"""
SysLog Threat Analysis — FastAPI Application Entry Point

Configures CORS, mounts API routes, initializes the WebSocket
endpoint, and manages the log watcher lifecycle via lifespan.
"""

from __future__ import annotations

import logging
import sys
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from api.routes import router as api_router, set_watcher
from config import CORS_ORIGINS, PROJECT_DESCRIPTION, PROJECT_NAME, PROJECT_VERSION
from services.log_watcher import LogWatcher
from websocket.manager import ws_manager

# ---------------------------------------------------------------------------
# Logging configuration
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("syslog_threat_analysis")

# ---------------------------------------------------------------------------
# Lifespan — manage background services
# ---------------------------------------------------------------------------

watcher = LogWatcher()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown lifecycle."""
    logger.info("Starting %s v%s", PROJECT_NAME, PROJECT_VERSION)

    # Inject watcher into routes
    set_watcher(watcher)

    yield

    # Shutdown
    if watcher.is_active:
        await watcher.stop()
    logger.info("Shutdown complete")


# ---------------------------------------------------------------------------
# Application
# ---------------------------------------------------------------------------

app = FastAPI(
    title=PROJECT_NAME,
    description=PROJECT_DESCRIPTION,
    version=PROJECT_VERSION,
    lifespan=lifespan,
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount REST routes
app.include_router(api_router)


# ---------------------------------------------------------------------------
# WebSocket endpoint
# ---------------------------------------------------------------------------

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """
    WebSocket endpoint for real-time dashboard updates.

    The backend pushes messages of types:
    - new_logs: batch of recently parsed entries
    - new_alert: a single new alert
    - new_incident: a new or updated incident
    - stats_update: refreshed dashboard statistics
    """
    await ws_manager.connect(websocket)
    try:
        while True:
            # Keep connection alive; client may send pings or commands
            data = await websocket.receive_text()
            # Currently no client→server commands needed
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception:
        ws_manager.disconnect(websocket)


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------

@app.get("/health")
async def health():
    return {"status": "ok", "service": PROJECT_NAME, "version": PROJECT_VERSION}

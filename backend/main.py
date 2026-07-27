"""
SysLog Threat Analysis - FastAPI Application Entry Point

Configures CORS, mounts API routes, initializes the WebSocket
endpoint, and manages the monitoring lifecycle via lifespan.
"""

from __future__ import annotations

import logging
import os
import sys
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from api.routes import router as api_router, set_monitor, set_simulator
from config import CORS_ORIGINS, PROJECT_DESCRIPTION, PROJECT_NAME, PROJECT_VERSION
from services.monitoring import monitor_manager
from services.simulator import simulator
from websocket.manager import ws_manager

# ---------------------------------------------------------------------------
# Logging configuration
# ---------------------------------------------------------------------------

LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO").upper()

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("syslog_threat_analysis")

# ---------------------------------------------------------------------------
# Lifespan - manage background services
# ---------------------------------------------------------------------------

_startup_time: float = 0.0


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown lifecycle."""
    global _startup_time
    _startup_time = time.time()
    logger.info("Starting %s v%s", PROJECT_NAME, PROJECT_VERSION)

    # Inject instances into routes
    set_monitor(monitor_manager)
    set_simulator(simulator)

    # Auto-start folder monitoring
    await monitor_manager.auto_start()

    yield

    # Shutdown
    if simulator.is_active:
        await simulator.stop()
    if monitor_manager.is_active:
        await monitor_manager.stop_monitoring()
    logger.info("Shutdown complete")


# ---------------------------------------------------------------------------
# Application
# ---------------------------------------------------------------------------

ENVIRONMENT = os.environ.get("ENVIRONMENT", "development")

app = FastAPI(
    title=PROJECT_NAME,
    description=PROJECT_DESCRIPTION,
    version=PROJECT_VERSION,
    lifespan=lifespan,
    docs_url="/docs" if ENVIRONMENT != "production" else None,
    redoc_url="/redoc" if ENVIRONMENT != "production" else None,
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=list(CORS_ORIGINS),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Global exception handler
# ---------------------------------------------------------------------------

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Catch-all handler to prevent stack trace leakage."""
    logger.error("Unhandled exception on %s %s: %s", request.method, request.url.path, exc, exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"},
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
            await websocket.receive_text()  # client heartbeat pings
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception:
        ws_manager.disconnect(websocket)


# ---------------------------------------------------------------------------
# Health / Version / Ready
# ---------------------------------------------------------------------------

@app.get("/health")
async def health():
    """Health check - always returns ok if the process is alive."""
    return {
        "status": "healthy",
        "service": PROJECT_NAME,
        "version": PROJECT_VERSION,
        "environment": ENVIRONMENT,
    }


@app.get("/version")
async def version():
    """Return project metadata."""
    return {
        "project": PROJECT_NAME,
        "version": PROJECT_VERSION,
        "description": PROJECT_DESCRIPTION,
        "environment": ENVIRONMENT,
    }


@app.get("/ready")
async def ready():
    """Readiness probe - checks that core subsystems are initialized."""
    uptime = round(time.time() - _startup_time, 1) if _startup_time else 0
    status = monitor_manager.get_status()
    return {
        "status": "ready",
        "uptime_seconds": uptime,
        "monitoring": status,
        "websocket": {
            "connected_clients": ws_manager.client_count,
        },
    }

"""
SysLog Threat Analysis - Monitoring Intelligence Layer

Central abstraction for all log sources. Manages monitoring sessions,
folder watching, and provides the unified monitoring status used by
the dashboard and API.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
import uuid
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Optional

from config import SAMPLE_LOGS_DIR, LOG_WATCH_DIRS
from services.log_watcher import LogWatcher
from services.pipeline import pipeline

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class SourceType(str, Enum):
    LIVE_FOLDER = "live_folder"
    SIMULATION = "simulation"
    HISTORICAL = "historical"


class SessionStatus(str, Enum):
    ACTIVE = "active"
    COMPLETED = "completed"
    STOPPED = "stopped"
    PAUSED = "paused"


# ---------------------------------------------------------------------------
# Session model
# ---------------------------------------------------------------------------

class MonitoringSession:
    """Tracks one monitoring activity."""

    def __init__(self, source_type: SourceType, source_path: str) -> None:
        self.session_id: str = uuid.uuid4().hex[:16]
        self.source_type: SourceType = source_type
        self.source_path: str = source_path
        self.status: SessionStatus = SessionStatus.ACTIVE
        self.start_time: float = time.time()
        self.end_time: Optional[float] = None
        self.events_at_start: int = len(pipeline.log_entries)
        self._last_event_count: int = 0
        self._last_eps_time: float = time.time()
        self._current_eps: float = 0.0

    @property
    def events_processed(self) -> int:
        return len(pipeline.log_entries) - self.events_at_start

    @property
    def alerts_generated(self) -> int:
        return len([
            a for a in pipeline.alerts
            if a.timestamp.timestamp() >= self.start_time
        ])

    @property
    def incidents_generated(self) -> int:
        return len([
            i for i in pipeline.incidents
            if i.first_seen.timestamp() >= self.start_time
        ])

    @property
    def duration_seconds(self) -> float:
        end = self.end_time or time.time()
        return round(end - self.start_time, 1)

    @property
    def events_per_second(self) -> float:
        now = time.time()
        elapsed = now - self._last_eps_time
        if elapsed >= 2.0:
            current_count = self.events_processed
            delta = current_count - self._last_event_count
            self._current_eps = round(delta / elapsed, 1) if elapsed > 0 else 0.0
            self._last_event_count = current_count
            self._last_eps_time = now
        return self._current_eps

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "source_type": self.source_type.value,
            "source_path": self.source_path,
            "status": self.status.value,
            "start_time": datetime.fromtimestamp(self.start_time).isoformat(),
            "end_time": datetime.fromtimestamp(self.end_time).isoformat() if self.end_time else None,
            "duration_seconds": self.duration_seconds,
            "events_processed": self.events_processed,
            "alerts_generated": self.alerts_generated,
            "incidents_generated": self.incidents_generated,
            "events_per_second": self.events_per_second,
        }

    def finish(self, status: SessionStatus = SessionStatus.COMPLETED) -> None:
        self.status = status
        self.end_time = time.time()


# ---------------------------------------------------------------------------
# Monitor Manager
# ---------------------------------------------------------------------------

class MonitorManager:
    """
    Orchestrates monitoring across all source types.

    Manages the LogWatcher, tracks sessions, and provides the unified
    monitoring status that the dashboard and API consume.
    """

    def __init__(self) -> None:
        self.watcher = LogWatcher()
        self._current_session: Optional[MonitoringSession] = None
        self._session_history: list[MonitoringSession] = []
        self._paused: bool = False
        self._pause_file: str = ""
        self._startup_time: float = 0.0
        self._files_monitored: int = 0

    # -- Properties --

    @property
    def is_active(self) -> bool:
        return self.watcher.is_active

    @property
    def is_paused(self) -> bool:
        return self._paused

    @property
    def current_session(self) -> Optional[MonitoringSession]:
        return self._current_session

    # -- Session lifecycle --

    async def start_folder_monitoring(self, folder: Optional[str] = None) -> dict:
        """Start monitoring all log files in a folder."""
        folder_path = Path(folder) if folder else SAMPLE_LOGS_DIR
        if not folder_path.exists():
            folder_path.mkdir(parents=True, exist_ok=True)

        # Find first log file in folder
        log_file = self._find_log_file(folder_path)
        if not log_file:
            return {"status": "no_files", "message": f"No log files found in {folder_path}"}

        if self.watcher.is_active:
            await self.stop_monitoring()

        # Start session
        session = MonitoringSession(
            source_type=SourceType.LIVE_FOLDER,
            source_path=str(folder_path),
        )
        self._current_session = session
        self._files_monitored = len(self._list_log_files(folder_path))

        # Start watcher on the file
        await self.watcher.start(
            str(log_file),
            on_new_lines=pipeline.process_lines,
            from_beginning=True,
        )
        pipeline.monitoring.active = True
        pipeline.monitoring.file_path = str(log_file)
        self._startup_time = time.time()
        self._paused = False

        logger.info("Folder monitoring started: %s (%d files)", folder_path, self._files_monitored)
        return {"status": "started", "folder": str(folder_path), "file": str(log_file)}

    async def start_file_monitoring(self, file_path: str, from_beginning: bool = True) -> dict:
        """Start monitoring a specific file."""
        path = Path(file_path)
        if not path.exists():
            return {"status": "error", "message": f"File not found: {file_path}"}

        if self.watcher.is_active:
            await self.stop_monitoring()

        session = MonitoringSession(
            source_type=SourceType.LIVE_FOLDER,
            source_path=file_path,
        )
        self._current_session = session

        await self.watcher.start(
            file_path,
            on_new_lines=pipeline.process_lines,
            from_beginning=from_beginning,
        )
        pipeline.monitoring.active = True
        pipeline.monitoring.file_path = file_path
        self._startup_time = time.time()
        self._paused = False
        self._files_monitored = 1

        logger.info("File monitoring started: %s", file_path)
        return {"status": "started", "file": file_path}

    async def stop_monitoring(self) -> dict:
        """Stop current monitoring and close the session."""
        lines = self.watcher.lines_processed
        if self.watcher.is_active:
            await self.watcher.stop()
        pipeline.monitoring.active = False
        self._paused = False

        if self._current_session:
            self._current_session.finish(SessionStatus.STOPPED)
            self._session_history.append(self._current_session)
            self._current_session = None

        logger.info("Monitoring stopped: %d lines processed", lines)
        return {"status": "stopped", "lines_processed": lines}

    async def pause_monitoring(self) -> dict:
        """Pause monitoring without ending the session."""
        if not self.watcher.is_active:
            return {"status": "not_active"}
        self._pause_file = self.watcher.file_path
        await self.watcher.stop()
        self._paused = True
        if self._current_session:
            self._current_session.status = SessionStatus.PAUSED
        logger.info("Monitoring paused")
        return {"status": "paused"}

    async def resume_monitoring(self) -> dict:
        """Resume a paused monitoring session."""
        if not self._paused or not self._pause_file:
            return {"status": "not_paused"}
        await self.watcher.start(
            self._pause_file,
            on_new_lines=pipeline.process_lines,
            from_beginning=False,  # Resume from where we left off
        )
        pipeline.monitoring.active = True
        self._paused = False
        if self._current_session:
            self._current_session.status = SessionStatus.ACTIVE
        logger.info("Monitoring resumed: %s", self._pause_file)
        return {"status": "resumed", "file": self._pause_file}

    # -- Status --

    def get_status(self) -> dict:
        """Full monitoring status for the dashboard."""
        session = self._current_session
        uptime = round(time.time() - self._startup_time, 1) if self._startup_time else 0

        return {
            "active": self.watcher.is_active,
            "paused": self._paused,
            "mode": session.source_type.value if session else None,
            "folder": session.source_path if session else None,
            "current_file": self.watcher.file_path if self.watcher.is_active else None,
            "files_monitored": self._files_monitored,
            "lines_processed": self.watcher.lines_processed,
            "watcher_uptime_seconds": uptime,
            "events_per_second": session.events_per_second if session else 0,
            "last_event_time": (
                pipeline.monitoring.last_event_time.isoformat()
                if pipeline.monitoring.last_event_time else None
            ),
            "session": session.to_dict() if session else None,
            "pipeline": {
                "logs_buffered": len(pipeline.log_entries),
                "alerts_buffered": len(pipeline.alerts),
                "incidents_buffered": len(pipeline.incidents),
            },
        }

    def get_session_history(self) -> list[dict]:
        """Return all completed sessions."""
        return [s.to_dict() for s in reversed(self._session_history)]

    def get_pipeline_stats(self) -> dict:
        """Live pipeline flow statistics."""
        return {
            "events_in": len(pipeline.log_entries),
            "events_parsed": len(pipeline.log_entries),
            "rules_triggered": len(pipeline.alerts),
            "alerts_generated": len(pipeline.alerts),
            "incidents_generated": len(pipeline.incidents),
        }

    # -- Auto-start --

    async def auto_start(self) -> None:
        """Auto-start folder monitoring if log files exist in sample_logs/."""
        log_file = self._find_log_file(SAMPLE_LOGS_DIR)
        if log_file:
            await self.start_folder_monitoring()
            logger.info("Auto-started monitoring: %s", SAMPLE_LOGS_DIR)
        else:
            logger.info("No log files found for auto-start in %s", SAMPLE_LOGS_DIR)

    # -- Helpers --

    def _find_log_file(self, folder: Path) -> Optional[Path]:
        """Find the first suitable log file in a folder."""
        for f in self._list_log_files(folder):
            return f
        return None

    def _list_log_files(self, folder: Path) -> list[Path]:
        """List all log files in a folder."""
        if not folder.exists():
            return []
        log_names = {"syslog", "auth.log", "kern.log", "messages"}
        files = []
        for entry in folder.iterdir():
            if entry.is_file() and (
                entry.suffix == ".log" or entry.name in log_names
            ):
                files.append(entry)
        return sorted(files, key=lambda f: f.name)


# Global instance
monitor_manager = MonitorManager()

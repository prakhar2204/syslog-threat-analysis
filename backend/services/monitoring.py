"""
SysLog Threat Analysis - Monitoring Intelligence Layer

Central abstraction for all log sources. Manages monitoring sessions,
folder watching, and provides the unified monitoring status used by
the dashboard and API.

Redesigned for true multi-file monitoring: every log file in a
monitored folder is watched simultaneously, new files are detected
automatically, and all events flow through the shared pipeline.
"""

from __future__ import annotations

import logging
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

    Uses the multi-file LogWatcher to monitor every log file in a folder
    simultaneously. Tracks sessions and provides unified monitoring
    status for the dashboard and API.
    """

    def __init__(self) -> None:
        self.watcher = LogWatcher()
        self._current_session: Optional[MonitoringSession] = None
        self._session_history: list[MonitoringSession] = []
        self._paused: bool = False
        self._pause_folder: Optional[str] = None
        self._startup_time: float = 0.0

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
        """Start monitoring ALL log files in a folder."""
        folder_path = Path(folder) if folder else SAMPLE_LOGS_DIR
        if not folder_path.exists():
            folder_path.mkdir(parents=True, exist_ok=True)

        if self.watcher.is_active:
            await self.stop_monitoring()

        # Start session
        session = MonitoringSession(
            source_type=SourceType.LIVE_FOLDER,
            source_path=str(folder_path),
        )
        self._current_session = session

        # Start multi-file watcher — monitors ALL files, not just the first
        discovered = await self.watcher.start_folder(
            str(folder_path),
            on_new_lines=pipeline.process_lines,
            from_beginning=True,
        )

        pipeline.monitoring.active = True
        pipeline.monitoring.file_path = str(folder_path)
        self._startup_time = time.time()
        self._paused = False

        file_names = [Path(f).name for f in discovered]
        logger.info(
            "Folder monitoring started: %s (%d files: %s)",
            folder_path, len(discovered), ", ".join(file_names),
        )
        return {
            "status": "started",
            "folder": str(folder_path),
            "files": file_names,
            "file_count": len(discovered),
        }

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

        await self.watcher.start_single(
            file_path,
            on_new_lines=pipeline.process_lines,
            from_beginning=from_beginning,
        )
        pipeline.monitoring.active = True
        pipeline.monitoring.file_path = file_path
        self._startup_time = time.time()
        self._paused = False

        logger.info("File monitoring started: %s", file_path)
        return {"status": "started", "file": file_path}

    async def stop_monitoring(self) -> dict:
        """Stop current monitoring and close the session."""
        lines = self.watcher.total_lines_processed
        if self.watcher.is_active:
            await self.watcher.stop()
        pipeline.monitoring.active = False
        self._paused = False

        if self._current_session:
            self._current_session.finish(SessionStatus.STOPPED)
            self._session_history.append(self._current_session)
            self._current_session = None

        logger.info("Monitoring stopped: %d total lines processed", lines)
        return {"status": "stopped", "lines_processed": lines}

    async def pause_monitoring(self) -> dict:
        """Pause monitoring without ending the session."""
        if not self.watcher.is_active:
            return {"status": "not_active"}
        # Remember the folder for resume
        self._pause_folder = self.watcher._folder
        await self.watcher.stop()
        self._paused = True
        if self._current_session:
            self._current_session.status = SessionStatus.PAUSED
        logger.info("Monitoring paused")
        return {"status": "paused"}

    async def resume_monitoring(self) -> dict:
        """Resume a paused monitoring session."""
        if not self._paused:
            return {"status": "not_paused"}

        if self._pause_folder:
            # Resume folder monitoring — continues from current offsets
            await self.watcher.start_folder(
                self._pause_folder,
                on_new_lines=pipeline.process_lines,
                from_beginning=False,  # Resume from where we left off
            )
        pipeline.monitoring.active = True
        self._paused = False
        if self._current_session:
            self._current_session.status = SessionStatus.ACTIVE
        logger.info("Monitoring resumed: %s", self._pause_folder)
        return {"status": "resumed"}

    # -- Status --

    def get_status(self) -> dict:
        """Full monitoring status for the dashboard."""
        session = self._current_session
        uptime = round(time.time() - self._startup_time, 1) if self._startup_time else 0

        # Build per-file status
        active_files = [
            wf.to_dict() for wf in self.watcher.watched_files if wf.active
        ]

        return {
            "active": self.watcher.is_active,
            "paused": self._paused,
            "mode": session.source_type.value if session else None,
            "folder": session.source_path if session else None,
            "files_monitored": self.watcher.active_file_count,
            "active_files": active_files,
            "lines_processed": self.watcher.total_lines_processed,
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
        if SAMPLE_LOGS_DIR.exists():
            from services.log_watcher import is_log_file
            has_files = any(is_log_file(f) for f in SAMPLE_LOGS_DIR.iterdir())
            if has_files:
                await self.start_folder_monitoring()
                logger.info("Auto-started monitoring: %s", SAMPLE_LOGS_DIR)
            else:
                logger.info("No log files found for auto-start in %s", SAMPLE_LOGS_DIR)
        else:
            logger.info("Sample logs directory does not exist: %s", SAMPLE_LOGS_DIR)


# Global instance
monitor_manager = MonitorManager()

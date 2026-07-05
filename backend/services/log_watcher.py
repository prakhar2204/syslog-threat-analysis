"""
SysLog Threat Analysis — Log Watcher Service

Asynchronous file tailer that monitors a log file for new lines.
Runs as a background task started via FastAPI's lifespan.
Reads only new content using byte-offset tracking.
Handles log rotation (file shrink detection).
"""

from __future__ import annotations

import asyncio
import logging
import os
from pathlib import Path
from typing import Callable, Optional

from config import LOG_TAIL_POLL_INTERVAL

logger = logging.getLogger(__name__)


class LogWatcher:
    """
    Watches a single log file and invokes a callback with new lines.

    Usage:
        watcher = LogWatcher()
        await watcher.start("/var/log/auth.log", on_new_lines=callback)
        ...
        await watcher.stop()
    """

    def __init__(self) -> None:
        self._active: bool = False
        self._file_path: str = ""
        self._offset: int = 0
        self._task: Optional[asyncio.Task] = None
        self._lines_processed: int = 0
        self._callback: Optional[Callable] = None

    @property
    def is_active(self) -> bool:
        return self._active

    @property
    def file_path(self) -> str:
        return self._file_path

    @property
    def lines_processed(self) -> int:
        return self._lines_processed

    async def start(
        self,
        file_path: str,
        on_new_lines: Callable,
        from_beginning: bool = True,
    ) -> None:
        """
        Start watching a log file.

        Args:
            file_path: Path to the log file.
            on_new_lines: Async callback receiving a list of new lines.
            from_beginning: If True, process the entire file first.
        """
        if self._active:
            await self.stop()

        if not Path(file_path).exists():
            raise FileNotFoundError(f"Log file not found: {file_path}")

        self._file_path = file_path
        self._callback = on_new_lines
        self._lines_processed = 0

        if from_beginning:
            self._offset = 0
        else:
            self._offset = os.path.getsize(file_path)

        self._active = True
        self._task = asyncio.create_task(self._watch_loop())
        logger.info("Started watching: %s (from offset %d)", file_path, self._offset)

    async def stop(self) -> None:
        """Stop watching the current file."""
        self._active = False
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        self._task = None
        logger.info("Stopped watching: %s (processed %d lines)", self._file_path, self._lines_processed)

    async def _watch_loop(self) -> None:
        """Main polling loop that checks for new file content."""
        while self._active:
            try:
                new_lines, new_offset = self._read_new_lines()
                if new_lines and self._callback:
                    self._offset = new_offset
                    self._lines_processed += len(new_lines)
                    await self._callback(new_lines)
            except Exception as exc:
                logger.error("Error in watch loop: %s", exc, exc_info=True)

            await asyncio.sleep(LOG_TAIL_POLL_INTERVAL)

    def _read_new_lines(self) -> tuple[list[str], int]:
        """
        Read new lines from the file starting at the current offset.
        Handles log rotation by detecting file size decrease.
        """
        try:
            file_size = os.path.getsize(self._file_path)
        except OSError:
            return [], self._offset

        # Log rotation detection
        if file_size < self._offset:
            logger.info("Log rotation detected: %s", self._file_path)
            self._offset = 0

        if file_size == self._offset:
            return [], self._offset

        lines: list[str] = []
        try:
            with open(self._file_path, "r", encoding="utf-8", errors="replace") as f:
                f.seek(self._offset)
                raw = f.read()
                new_offset = f.tell()

            for line in raw.splitlines():
                stripped = line.strip()
                if stripped:
                    lines.append(stripped)
        except OSError as exc:
            logger.error("Failed to read %s: %s", self._file_path, exc)
            return [], self._offset

        return lines, new_offset

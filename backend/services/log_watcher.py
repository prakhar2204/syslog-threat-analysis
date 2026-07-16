"""
SysLog Threat Analysis — Multi-File Log Watcher

Asynchronous file tailer that monitors MULTIPLE log files simultaneously.
Each file maintains independent offset, size, and metadata tracking.
Automatically detects new files appearing in watched folders and
gracefully handles removed files and log rotation.
"""

from __future__ import annotations

import asyncio
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from config import LOG_TAIL_POLL_INTERVAL

logger = logging.getLogger(__name__)

# Supported file names and extensions for auto-discovery
SUPPORTED_EXTENSIONS = {".log"}
SUPPORTED_NAMES = {"syslog", "auth.log", "kern.log", "messages", "nginx_access.log", "apache_access.log"}


def is_log_file(path: Path) -> bool:
    """Check if a file should be monitored."""
    return path.is_file() and (path.suffix in SUPPORTED_EXTENSIONS or path.name in SUPPORTED_NAMES)


@dataclass
class WatchedFile:
    """Per-file tracking state."""
    path: str
    offset: int = 0
    lines_processed: int = 0
    last_size: int = 0
    last_modified: float = 0.0
    active: bool = True

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "filename": Path(self.path).name,
            "offset": self.offset,
            "lines_processed": self.lines_processed,
            "last_size": self.last_size,
            "active": self.active,
        }


class LogWatcher:
    """
    Watches multiple log files simultaneously.

    Each file has independent offset tracking. Supports:
    - Multi-file monitoring from a folder
    - Auto-discovery of new files appearing in the folder
    - Graceful removal when files disappear
    - Per-file log rotation detection
    """

    def __init__(self) -> None:
        self._active: bool = False
        self._watched: dict[str, WatchedFile] = {}  # path -> WatchedFile
        self._folder: Optional[str] = None
        self._task: Optional[asyncio.Task] = None
        self._callback: Optional[Callable] = None
        self._discovery_counter: int = 0

    @property
    def is_active(self) -> bool:
        return self._active

    @property
    def watched_files(self) -> list[WatchedFile]:
        """Return all currently watched files."""
        return list(self._watched.values())

    @property
    def active_file_count(self) -> int:
        return len([w for w in self._watched.values() if w.active])

    @property
    def total_lines_processed(self) -> int:
        return sum(w.lines_processed for w in self._watched.values())

    @property
    def lines_processed(self) -> int:
        """Backward-compatible alias."""
        return self.total_lines_processed

    @property
    def file_path(self) -> str:
        """Backward-compatible: return folder or first file."""
        if self._folder:
            return self._folder
        paths = list(self._watched.keys())
        return paths[0] if paths else ""

    # -- Start / Stop --

    async def start_folder(
        self,
        folder: str,
        on_new_lines: Callable,
        from_beginning: bool = True,
    ) -> list[str]:
        """
        Start monitoring all log files in a folder.

        Returns list of initially discovered file paths.
        Continues to auto-discover new files while active.
        """
        if self._active:
            await self.stop()

        folder_path = Path(folder)
        if not folder_path.exists():
            raise FileNotFoundError(f"Folder not found: {folder}")

        self._folder = folder
        self._callback = on_new_lines
        self._watched.clear()

        # Discover initial files
        discovered = self._discover_files(folder_path)
        for file_path in discovered:
            wf = WatchedFile(path=str(file_path))
            if from_beginning:
                wf.offset = 0
            else:
                wf.offset = os.path.getsize(file_path)
            wf.last_size = os.path.getsize(file_path)
            self._watched[str(file_path)] = wf

        self._active = True
        self._discovery_counter = 0
        self._task = asyncio.create_task(self._watch_loop())

        file_names = [Path(p).name for p in self._watched]
        logger.info(
            "Started multi-file monitoring: %s (%d files: %s)",
            folder, len(discovered), ", ".join(file_names),
        )
        return [str(f) for f in discovered]

    async def start_single(
        self,
        file_path: str,
        on_new_lines: Callable,
        from_beginning: bool = True,
    ) -> None:
        """Start monitoring a single file (backward compatible)."""
        if self._active:
            await self.stop()

        if not Path(file_path).exists():
            raise FileNotFoundError(f"Log file not found: {file_path}")

        self._folder = None
        self._callback = on_new_lines
        self._watched.clear()

        wf = WatchedFile(path=file_path)
        if from_beginning:
            wf.offset = 0
        else:
            wf.offset = os.path.getsize(file_path)
        wf.last_size = os.path.getsize(file_path)
        self._watched[file_path] = wf

        self._active = True
        self._task = asyncio.create_task(self._watch_loop())
        logger.info("Started watching: %s (from offset %d)", file_path, wf.offset)

    async def stop(self) -> None:
        """Stop watching all files."""
        self._active = False
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        self._task = None

        total = self.total_lines_processed
        count = len(self._watched)
        logger.info("Stopped watching %d files (total %d lines processed)", count, total)

    # -- Main loop --

    async def _watch_loop(self) -> None:
        """Main polling loop: reads all files and discovers new ones."""
        while self._active:
            try:
                # Read new lines from all watched files
                for wf in list(self._watched.values()):
                    if not wf.active:
                        continue
                    new_lines = self._read_file(wf)
                    if new_lines and self._callback:
                        await self._callback(new_lines)

                # Auto-discover new files every ~5 polls (~1 second at 200ms)
                self._discovery_counter += 1
                if self._folder and self._discovery_counter >= 5:
                    self._discovery_counter = 0
                    self._check_for_new_files()

            except Exception as exc:
                logger.error("Error in watch loop: %s", exc, exc_info=True)

            await asyncio.sleep(LOG_TAIL_POLL_INTERVAL)

    # -- Per-file reading --

    def _read_file(self, wf: WatchedFile) -> list[str]:
        """Read new lines from a single watched file."""
        try:
            file_size = os.path.getsize(wf.path)
        except OSError:
            # File was removed
            if wf.active:
                wf.active = False
                logger.info("Stopped watching removed file: %s", Path(wf.path).name)
            return []

        # Log rotation detection: file shrunk
        if file_size < wf.offset:
            logger.info("Log rotation detected: %s (size %d < offset %d)",
                        Path(wf.path).name, file_size, wf.offset)
            wf.offset = 0

        if file_size == wf.offset:
            wf.last_size = file_size
            return []

        lines: list[str] = []
        try:
            with open(wf.path, "r", encoding="utf-8", errors="replace") as f:
                f.seek(wf.offset)
                raw = f.read()
                wf.offset = f.tell()

            for line in raw.splitlines():
                stripped = line.strip()
                if stripped:
                    lines.append(stripped)

            if lines:
                wf.lines_processed += len(lines)
                wf.last_size = file_size
                wf.last_modified = os.path.getmtime(wf.path)

        except OSError as exc:
            logger.error("Failed to read %s: %s", wf.path, exc)

        return lines

    # -- Auto-discovery --

    def _discover_files(self, folder: Path) -> list[Path]:
        """Discover all log files in a folder."""
        if not folder.exists():
            return []
        return sorted([f for f in folder.iterdir() if is_log_file(f)], key=lambda f: f.name)

    def _check_for_new_files(self) -> None:
        """Check the monitored folder for newly created log files."""
        if not self._folder:
            return

        folder_path = Path(self._folder)
        current_files = self._discover_files(folder_path)

        for file_path in current_files:
            fp = str(file_path)
            if fp not in self._watched:
                # New file discovered!
                wf = WatchedFile(path=fp, offset=0)
                try:
                    wf.last_size = os.path.getsize(fp)
                except OSError:
                    continue
                self._watched[fp] = wf
                logger.info("Detected new log file: %s — started monitoring", file_path.name)

        # Check for removed files
        for fp, wf in list(self._watched.items()):
            if wf.active and not Path(fp).exists():
                wf.active = False
                logger.info("Stopped watching removed file: %s", Path(fp).name)

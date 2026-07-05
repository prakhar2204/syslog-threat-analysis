"""
SysLog Threat Analysis — Utility Helpers

Shared utility functions used across the backend modules.
"""

from __future__ import annotations

import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


def format_timestamp(dt: Optional[datetime], fmt: str = "%Y-%m-%d %H:%M:%S") -> str:
    """Format a datetime to a consistent string."""
    if dt is None:
        return ""
    return dt.strftime(fmt)


def get_log_files(directories: list[Path]) -> list[dict]:
    """
    Scan directories for log files and return metadata.

    Returns a list of dicts with 'name', 'path', and 'size_bytes' keys.
    """
    log_extensions = {".log", ""}  # syslog has no extension
    log_files = []

    for directory in directories:
        if not directory.exists():
            continue
        for entry in directory.iterdir():
            if entry.is_file() and (entry.suffix in log_extensions or entry.name in (
                "syslog", "auth.log", "kern.log", "messages",
            )):
                log_files.append({
                    "name": entry.name,
                    "path": str(entry),
                    "size_bytes": entry.stat().st_size,
                })

    return sorted(log_files, key=lambda x: x["name"])


def tail_file(filepath: str, offset: int = 0) -> tuple[list[str], int]:
    """
    Read new lines from a file starting at the given byte offset.

    Returns (new_lines, new_offset). Handles log rotation by
    detecting if the file shrunk since last read.
    """
    try:
        file_size = os.path.getsize(filepath)
    except OSError:
        return [], offset

    # Detect log rotation (file shrunk)
    if file_size < offset:
        logger.info("Log rotation detected for %s (size %d < offset %d)", filepath, file_size, offset)
        offset = 0

    if file_size == offset:
        return [], offset

    lines = []
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            f.seek(offset)
            raw = f.read()
            new_offset = f.tell()

        for line in raw.splitlines():
            stripped = line.strip()
            if stripped:
                lines.append(stripped)
    except OSError as exc:
        logger.error("Error reading %s: %s", filepath, exc)
        return [], offset

    return lines, new_offset


def validate_ip(ip: str) -> bool:
    """Basic IPv4 address validation."""
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)

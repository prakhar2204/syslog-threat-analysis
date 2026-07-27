"""
SysLog Threat Analysis — Utility Helpers

Shared utility functions used across the backend modules.
"""

from __future__ import annotations

import logging
from pathlib import Path

logger = logging.getLogger(__name__)


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

"""
SysLog Threat Analysis - IOC Extractor

Deterministic indicator-of-compromise extraction from log entries.
Uses regex patterns to extract structured IOCs. No enrichment, no
classification — only extraction.
"""

from __future__ import annotations

import re
from typing import Optional

from models.events import ExtractedIOC, LogEntry

# ---------------------------------------------------------------------------
# Compiled patterns
# ---------------------------------------------------------------------------

_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
)

_IPV6 = re.compile(
    r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"
    r"|\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b"
    r"|\b::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}\b"
)

_URL = re.compile(
    r"https?://[^\s\"'<>]+",
    re.IGNORECASE,
)

_EMAIL = re.compile(
    r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"
)

_DOMAIN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)"
    r"+(?:com|net|org|io|dev|xyz|ru|cn|info|biz|me|co|uk|de|fr|example)\b",
    re.IGNORECASE,
)

_FILEPATH = re.compile(
    r"(?:/(?:etc|var|tmp|usr|home|opt|bin|sbin|root|www|proc|dev)"
    r"(?:/[^\s\"'<>;|&]+)+)"
)

_COMMAND = re.compile(
    r"COMMAND=(.+?)$",
    re.MULTILINE,
)

_HASH_SHA256 = re.compile(r"\b[0-9a-fA-F]{64}\b")
_HASH_MD5 = re.compile(r"\b[0-9a-fA-F]{32}\b")

_PORT = re.compile(r"\bDPT=(\d+)\b")


# ---------------------------------------------------------------------------
# Extractor
# ---------------------------------------------------------------------------

def extract_iocs(entry: LogEntry) -> list[ExtractedIOC]:
    """
    Extract all IOCs from a single log entry.

    Sources:
    - Parsed fields (source_ip, username, hostname, etc.)
    - Raw log text (regex-based extraction)

    Returns a deduplicated list of ExtractedIOC objects.
    """
    iocs: list[ExtractedIOC] = []
    seen: set[tuple[str, str]] = set()
    eid = entry.event_id
    text = entry.raw_log or entry.message

    def _add(ioc_type: str, value: Optional[str]) -> None:
        if not value or not value.strip():
            return
        val = value.strip()
        key = (ioc_type, val)
        if key not in seen:
            seen.add(key)
            iocs.append(ExtractedIOC(ioc_type=ioc_type, value=val, source_event_id=eid))

    # --- From parsed fields ---
    _add("ipv4", entry.source_ip)
    _add("ipv4", entry.destination_ip)
    _add("username", entry.username)
    _add("hostname", entry.hostname)
    _add("service", entry.service)
    _add("process", entry.process)

    # --- From raw text ---

    # IPv4
    for m in _IPV4.finditer(text):
        _add("ipv4", m.group())

    # IPv6
    for m in _IPV6.finditer(text):
        _add("ipv6", m.group())

    # URLs
    for m in _URL.finditer(text):
        _add("url", m.group())

    # Email
    for m in _EMAIL.finditer(text):
        _add("email", m.group())

    # Domains
    for m in _DOMAIN.finditer(text):
        _add("domain", m.group())

    # File paths
    for m in _FILEPATH.finditer(text):
        _add("filepath", m.group())

    # Commands (from sudo lines)
    for m in _COMMAND.finditer(text):
        _add("command", m.group(1).strip())

    # Ports
    for m in _PORT.finditer(text):
        _add("port", m.group(1))

    # Hashes
    for m in _HASH_SHA256.finditer(text):
        _add("hash", m.group())
    for m in _HASH_MD5.finditer(text):
        # Avoid matching strings already captured as SHA256 substrings
        val = m.group()
        if ("hash", val) not in seen and len(val) == 32:
            _add("hash", val)

    return iocs

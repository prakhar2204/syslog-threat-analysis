"""
SysLog Threat Analysis — Log Parser

Multi-format log parser that normalizes raw syslog lines into a common
LogEntry schema. Supports auth.log, generic syslog, Apache access/error
logs, and custom syslog formats.

Each regex uses named groups for field extraction. The parser auto-detects
the format when not specified, and gracefully skips malformed lines.
"""

from __future__ import annotations

import logging
import re
from datetime import datetime
from typing import Optional

from models.events import EventType, LogEntry, Severity

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Compiled regex patterns (compiled once at module load for performance)
# ---------------------------------------------------------------------------

# auth.log / BSD syslog: "Jul  5 09:14:23 server sshd[12345]: message"
_RE_AUTH = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<service>\S+?)(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<message>.+)$"
)

# Generic syslog (same format as auth, reused)
_RE_SYSLOG = _RE_AUTH

# Apache access log (Combined format):
# 192.168.1.10 - frank [10/Oct/2000:13:55:36 -0700] "GET /index.html HTTP/1.0" 200 2326 "http://ref" "Mozilla/5.0"
_RE_APACHE_ACCESS = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>\w+)\s+(?P<path>\S+)\s+\S+"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\d+|-)'
    r'(?:\s+"(?P<referrer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?'
)

# Apache error log: "[Sun Jul 05 09:14:23.123456 2026] [error] [client 1.2.3.4:1234] msg"
_RE_APACHE_ERROR = re.compile(
    r'^\[(?P<timestamp>[^\]]+)\]\s+'
    r'\[(?:(?P<module>\w+):)?(?P<level>\w+)\]\s+'
    r'(?:\[pid\s+\d+\]\s+)?'
    r'(?:\[client\s+(?P<client_ip>[^\]]+)\]\s+)?'
    r'(?P<message>.+)$'
)

# IP address extraction helper
_RE_IP = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')

# Username extraction helpers
_RE_USER_FOR = re.compile(r'(?:for|user)\s+(?:invalid\s+user\s+)?(\S+)')
_RE_USER_BY = re.compile(r'by\s+(\S+)')


# ---------------------------------------------------------------------------
# Format definitions
# ---------------------------------------------------------------------------

LOG_FORMATS = {
    "auth": _RE_AUTH,
    "syslog": _RE_SYSLOG,
    "apache_access": _RE_APACHE_ACCESS,
    "apache_error": _RE_APACHE_ERROR,
}


class LogParser:
    """
    Parses raw log lines into normalized LogEntry objects.

    Usage::

        parser = LogParser()
        entry = parser.parse_line("Jul  5 09:14:23 server sshd[1234]: Failed password for root")
        if entry:
            logger.info("%s %s", entry.severity, entry.event_type)
    """

    def __init__(self) -> None:
        self._format_order = ["auth", "apache_access", "apache_error", "syslog"]
        self._current_year = datetime.now().year

    def detect_format(self, line: str) -> Optional[str]:
        """Determine which log format a line matches."""
        for fmt in self._format_order:
            if LOG_FORMATS[fmt].match(line):
                return fmt
        return None

    def parse_line(self, line: str, fmt: Optional[str] = None) -> Optional[LogEntry]:
        """
        Parse a single raw log line into a normalized LogEntry.

        Returns None if the line cannot be parsed (malformed or empty).
        """
        line = line.strip()
        if not line:
            return None

        if fmt is None:
            fmt = self.detect_format(line)
        if fmt is None:
            return self._fallback_parse(line)

        match = LOG_FORMATS[fmt].match(line)
        if not match:
            return self._fallback_parse(line)

        groups = match.groupdict()

        if fmt == "apache_access":
            return self._parse_apache_access(groups, line, fmt)
        elif fmt == "apache_error":
            return self._parse_apache_error(groups, line, fmt)
        else:
            return self._parse_syslog(groups, line, fmt)

    def parse_lines(self, lines: list[str], fmt: Optional[str] = None) -> list[LogEntry]:
        """Parse multiple lines, skipping any that fail."""
        entries = []
        for line in lines:
            entry = self.parse_line(line, fmt)
            if entry is not None:
                entries.append(entry)
        return entries

    # -------------------------------------------------------------------
    # Format-specific parsers
    # -------------------------------------------------------------------

    def _parse_syslog(self, groups: dict, raw: str, fmt: str) -> LogEntry:
        """Parse auth.log or generic syslog format."""
        timestamp = self._parse_bsd_timestamp(groups.get("timestamp", ""))
        service = groups.get("service", "")
        message = groups.get("message", "")
        hostname = groups.get("hostname", "")

        source_ip = self._extract_ip(message)
        username = self._extract_username(message)
        event_type = self._classify_syslog_event(service, message)
        severity = self._assess_syslog_severity(message)

        return LogEntry(
            timestamp=timestamp,
            hostname=hostname,
            source_ip=source_ip,
            username=username,
            service=service,
            process=groups.get("pid") or "",
            event_type=event_type,
            message=message,
            raw_log=raw,
            severity=severity,
            log_format=fmt,
        )

    def _parse_apache_access(self, groups: dict, raw: str, fmt: str) -> LogEntry:
        """Parse Apache combined access log format."""
        timestamp = self._parse_apache_timestamp(groups.get("timestamp", ""))
        status_code = int(groups.get("status", "0"))
        path = groups.get("path", "")
        method = groups.get("method", "")
        user_agent = groups.get("user_agent", "")
        ip = groups.get("ip", "")

        severity = self._assess_http_severity(status_code, path, user_agent)
        message = f'{method} {path} → {status_code}'
        if user_agent:
            message += f' [{user_agent[:60]}]'

        return LogEntry(
            timestamp=timestamp,
            hostname="webserver",
            source_ip=ip,
            username=groups.get("user") if groups.get("user") != "-" else None,
            service="apache",
            process="httpd",
            event_type=EventType.WEB_SERVER,
            message=message,
            raw_log=raw,
            severity=severity,
            log_format=fmt,
        )

    def _parse_apache_error(self, groups: dict, raw: str, fmt: str) -> LogEntry:
        """Parse Apache error log format."""
        timestamp = self._parse_apache_error_timestamp(groups.get("timestamp", ""))
        level = groups.get("level", "error").lower()
        client_raw = groups.get("client_ip", "")
        client_ip = client_raw.split(":")[0] if client_raw else None
        message = groups.get("message", "")

        severity_map = {
            "emerg": Severity.CRITICAL,
            "alert": Severity.CRITICAL,
            "crit": Severity.CRITICAL,
            "error": Severity.HIGH,
            "warn": Severity.MEDIUM,
            "notice": Severity.LOW,
            "info": Severity.INFO,
            "debug": Severity.INFO,
        }

        return LogEntry(
            timestamp=timestamp,
            hostname="webserver",
            source_ip=client_ip,
            service="apache",
            process="httpd",
            event_type=EventType.WEB_SERVER,
            message=message,
            raw_log=raw,
            severity=severity_map.get(level, Severity.MEDIUM),
            log_format=fmt,
        )

    def _fallback_parse(self, raw: str) -> LogEntry:
        """Create a minimal LogEntry for lines that match no known format."""
        source_ip = self._extract_ip(raw)
        return LogEntry(
            timestamp=datetime.now(),
            message=raw[:500],
            raw_log=raw,
            source_ip=source_ip,
            event_type=EventType.UNKNOWN,
            severity=Severity.INFO,
            log_format="unknown",
        )

    # -------------------------------------------------------------------
    # Timestamp parsers
    # -------------------------------------------------------------------

    def _parse_bsd_timestamp(self, ts: str) -> datetime:
        """Parse BSD syslog timestamp like 'Jul  5 09:14:23'."""
        try:
            parsed = datetime.strptime(ts, "%b %d %H:%M:%S")
            return parsed.replace(year=self._current_year)
        except (ValueError, TypeError):
            return datetime.now()

    def _parse_apache_timestamp(self, ts: str) -> datetime:
        """Parse Apache access log timestamp like '10/Oct/2000:13:55:36 -0700'."""
        try:
            return datetime.strptime(ts.split()[0], "%d/%b/%Y:%H:%M:%S")
        except (ValueError, TypeError, IndexError):
            return datetime.now()

    def _parse_apache_error_timestamp(self, ts: str) -> datetime:
        """Parse Apache error log timestamp."""
        for pattern in [
            "%a %b %d %H:%M:%S.%f %Y",
            "%a %b %d %H:%M:%S %Y",
        ]:
            try:
                return datetime.strptime(ts.strip(), pattern)
            except ValueError:
                continue
        return datetime.now()

    # -------------------------------------------------------------------
    # Field extraction helpers
    # -------------------------------------------------------------------

    def _extract_ip(self, text: str) -> Optional[str]:
        """Extract the first IPv4 address from text."""
        match = _RE_IP.search(text)
        return match.group(1) if match else None

    def _extract_username(self, text: str) -> Optional[str]:
        """Extract a username from syslog messages."""
        match = _RE_USER_FOR.search(text)
        if match:
            username = match.group(1)
            if username not in ("port", "from", "on", "to"):
                return username
        match = _RE_USER_BY.search(text)
        if match:
            return match.group(1)
        return None

    # -------------------------------------------------------------------
    # Event classification
    # -------------------------------------------------------------------

    def _classify_syslog_event(self, service: str, message: str) -> EventType:
        """Classify a syslog entry into an event type based on service and message."""
        service_lower = service.lower()
        message_lower = message.lower()

        if any(s in service_lower for s in ("sshd", "pam", "login", "su", "sudo")):
            return EventType.AUTHENTICATION
        if any(s in service_lower for s in ("ufw", "iptables", "firewalld")):
            return EventType.FIREWALL
        if any(s in service_lower for s in ("kernel",)):
            return EventType.KERNEL
        if any(s in service_lower for s in ("systemd", "cron", "anacron")):
            return EventType.SYSTEM
        if any(s in service_lower for s in ("apache", "nginx", "httpd")):
            return EventType.WEB_SERVER
        if "network" in message_lower or "interface" in message_lower:
            return EventType.NETWORK

        # Message-based fallback
        if any(kw in message_lower for kw in ("password", "authentication", "login", "session")):
            return EventType.AUTHENTICATION
        if any(kw in message_lower for kw in ("blocked", "denied", "drop", "reject")):
            return EventType.FIREWALL

        return EventType.SYSTEM

    # -------------------------------------------------------------------
    # Severity assessment
    # -------------------------------------------------------------------

    def _assess_syslog_severity(self, message: str) -> Severity:
        """Determine initial severity from syslog message content."""
        msg = message.lower()

        if any(kw in msg for kw in ("panic", "oops", "critical", "emergency")):
            return Severity.CRITICAL
        if any(kw in msg for kw in ("failed password", "authentication failure",
                                     "invalid user", "error", "not allowed")):
            return Severity.MEDIUM
        if any(kw in msg for kw in ("warning", "disk full", "no space")):
            return Severity.HIGH
        if any(kw in msg for kw in ("accepted", "session opened", "started", "loaded")):
            return Severity.INFO
        return Severity.LOW

    def _assess_http_severity(self, status: int, path: str, ua: str) -> Severity:
        """Determine initial severity from HTTP status, path, and user-agent."""
        path_lower = path.lower()
        ua_lower = ua.lower() if ua else ""

        # Known attack tools
        if any(tool in ua_lower for tool in ("sqlmap", "nikto", "nmap", "masscan", "dirbuster")):
            return Severity.HIGH

        # Traversal or injection patterns in path
        if "../" in path or "etc/passwd" in path_lower:
            return Severity.HIGH
        if any(kw in path_lower for kw in ("union", "select", "drop", "1=1", "or+1")):
            return Severity.CRITICAL

        # Status-based
        if status >= 500:
            return Severity.HIGH
        if status in (401, 403):
            return Severity.MEDIUM
        if status == 404:
            return Severity.LOW
        return Severity.INFO

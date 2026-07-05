"""
SysLog Threat Analysis — Threat Detection Engine

Evaluates every normalized LogEntry against the detection rule set.
Returns Alert objects when patterns match. The engine maintains internal
state for frequency-based rules (e.g., brute force counting).
"""

from __future__ import annotations

import logging
import re
from collections import defaultdict
from datetime import datetime
from typing import Optional

from detection.rules import DETECTION_RULES, RULES_BY_ID
from models.events import Alert, AlertStatus, LogEntry, Severity

logger = logging.getLogger(__name__)

# Pre-compiled patterns for message matching
_PATTERNS = {
    "failed_password": re.compile(r"failed password", re.IGNORECASE),
    "accepted_password": re.compile(r"accepted password", re.IGNORECASE),
    "invalid_user": re.compile(r"invalid user", re.IGNORECASE),
    "root_login": re.compile(r"failed password for root", re.IGNORECASE),
    "sudo_command": re.compile(r"sudo:?\s+.*COMMAND", re.IGNORECASE),
    "su_session": re.compile(r"su[\[:\s].*session opened", re.IGNORECASE),
    "priv_esc": re.compile(r"(sudo|su).*?(COMMAND|session opened)", re.IGNORECASE),
    "sql_injection": re.compile(
        r"(union\s+select|or\s+1\s*=\s*1|drop\s+table|select\s+.*from|"
        r"insert\s+into|delete\s+from|update\s+.*set|;\s*--|'--)",
        re.IGNORECASE,
    ),
    "dir_traversal": re.compile(r"\.\./|\.\.\\|etc/passwd|etc/shadow", re.IGNORECASE),
    "suspicious_ua": re.compile(
        r"(sqlmap|nikto|nmap|masscan|dirbuster|gobuster|wfuzz|hydra|medusa)",
        re.IGNORECASE,
    ),
    "firewall_block": re.compile(r"(UFW\s+BLOCK|iptables.*DROP|DENIED|firewall.*block)", re.IGNORECASE),
    "kernel_panic": re.compile(r"kernel:?.*(panic|oops|BUG|segfault|critical)", re.IGNORECASE),
    "disk_full": re.compile(r"(no space left|disk full|filesystem.*full)", re.IGNORECASE),
    "service_crash": re.compile(
        r"(segfault|core dump|failed.*start|exited.*error|terminated|abort)", re.IGNORECASE
    ),
    "http_404": re.compile(r"→\s*404\b"),
    "http_5xx": re.compile(r"→\s*5\d{2}\b"),
}


class ThreatEngine:
    """
    Evaluates log entries against detection rules.

    The engine is stateful: it tracks per-IP event counts for
    frequency-based detections (brute force, 404 floods, etc.).
    """

    def __init__(self) -> None:
        self._rules = DETECTION_RULES
        self._rules_by_id = RULES_BY_ID
        self._alerts: list[Alert] = []
        # Frequency tracking: ip -> list of timestamps
        self._failed_logins: dict[str, list[datetime]] = defaultdict(list)
        self._404_counts: dict[str, list[datetime]] = defaultdict(list)

    def analyze(self, entry: LogEntry) -> list[Alert]:
        """
        Run all detection rules against a single log entry.
        Returns a list of alerts generated (may be empty).
        """
        alerts: list[Alert] = []

        for check in [
            self._check_failed_password,
            self._check_accepted_after_failures,
            self._check_invalid_user,
            self._check_root_login,
            self._check_privilege_escalation,
            self._check_sql_injection,
            self._check_directory_traversal,
            self._check_suspicious_ua,
            self._check_firewall_block,
            self._check_kernel_panic,
            self._check_disk_full,
            self._check_service_crash,
            self._check_excessive_404,
        ]:
            alert = check(entry)
            if alert is not None:
                self._alerts.append(alert)
                alerts.append(alert)

        return alerts

    def get_alerts(self) -> list[Alert]:
        """Return all generated alerts."""
        return list(self._alerts)

    def get_active_alerts(self) -> list[Alert]:
        """Return only currently active alerts."""
        return [a for a in self._alerts if a.status == AlertStatus.ACTIVE]

    def acknowledge_alert(self, alert_id: str) -> bool:
        """Mark an alert as acknowledged. Returns True if found."""
        for alert in self._alerts:
            if alert.alert_id == alert_id:
                alert.status = AlertStatus.ACKNOWLEDGED
                return True
        return False

    def resolve_alert(self, alert_id: str) -> bool:
        """Mark an alert as resolved. Returns True if found."""
        for alert in self._alerts:
            if alert.alert_id == alert_id:
                alert.status = AlertStatus.RESOLVED
                return True
        return False

    def clear(self) -> None:
        """Reset all engine state."""
        self._alerts.clear()
        self._failed_logins.clear()
        self._404_counts.clear()

    # -------------------------------------------------------------------
    # Individual rule checks
    # -------------------------------------------------------------------

    def _make_alert(
        self,
        rule_id: str,
        entry: LogEntry,
        description: Optional[str] = None,
        event_count: int = 1,
    ) -> Alert:
        """Create an Alert from a rule match."""
        rule = self._rules_by_id[rule_id]
        return Alert(
            rule_id=rule_id,
            rule_name=rule.name,
            severity=rule.severity,
            source_ip=entry.source_ip,
            username=entry.username,
            description=description or rule.description,
            matched_event_id=entry.event_id,
            timestamp=entry.timestamp,
            mitre=rule.mitre,
            event_count=event_count,
        )

    def _check_failed_password(self, entry: LogEntry) -> Optional[Alert]:
        """R001 / R014: SSH brute force and multiple auth failures."""
        if not _PATTERNS["failed_password"].search(entry.message):
            return None

        ip = entry.source_ip or "unknown"
        self._failed_logins[ip].append(entry.timestamp)

        # Clean old entries (60-second window)
        cutoff = entry.timestamp.timestamp() - 60
        self._failed_logins[ip] = [
            t for t in self._failed_logins[ip] if t.timestamp() > cutoff
        ]

        count = len(self._failed_logins[ip])

        if count >= 5:
            return self._make_alert(
                "R001", entry,
                f"SSH brute force: {count} failed login attempts from {ip} in 60 seconds.",
                event_count=count,
            )
        elif count >= 3:
            return self._make_alert(
                "R014", entry,
                f"Multiple authentication failures: {count} from {ip}.",
                event_count=count,
            )
        return None

    def _check_accepted_after_failures(self, entry: LogEntry) -> Optional[Alert]:
        """R002: Successful login from an IP that previously had failures."""
        if not _PATTERNS["accepted_password"].search(entry.message):
            return None

        ip = entry.source_ip or "unknown"
        prior_failures = len(self._failed_logins.get(ip, []))

        if prior_failures >= 3:
            alert = self._make_alert(
                "R002", entry,
                f"Successful login from {ip} after {prior_failures} failed attempts. "
                f"Possible credential compromise.",
                event_count=prior_failures + 1,
            )
            # Clear failures for this IP after raising the alert
            self._failed_logins[ip].clear()
            return alert
        return None

    def _check_invalid_user(self, entry: LogEntry) -> Optional[Alert]:
        """R003: Login attempt for a non-existent user."""
        if _PATTERNS["invalid_user"].search(entry.message):
            return self._make_alert("R003", entry)
        return None

    def _check_root_login(self, entry: LogEntry) -> Optional[Alert]:
        """R004: Direct root login attempt."""
        if _PATTERNS["root_login"].search(entry.message):
            return self._make_alert("R004", entry)
        return None

    def _check_privilege_escalation(self, entry: LogEntry) -> Optional[Alert]:
        """R005: Privilege escalation via sudo or su."""
        if _PATTERNS["priv_esc"].search(entry.message):
            return self._make_alert("R005", entry)
        return None

    def _check_sql_injection(self, entry: LogEntry) -> Optional[Alert]:
        """R006: SQL injection patterns in request."""
        if _PATTERNS["sql_injection"].search(entry.message):
            return self._make_alert("R006", entry)
        return None

    def _check_directory_traversal(self, entry: LogEntry) -> Optional[Alert]:
        """R007: Directory traversal sequences in request."""
        if _PATTERNS["dir_traversal"].search(entry.message):
            return self._make_alert("R007", entry)
        return None

    def _check_suspicious_ua(self, entry: LogEntry) -> Optional[Alert]:
        """R008: Known attack tool user agents."""
        if _PATTERNS["suspicious_ua"].search(entry.message):
            return self._make_alert("R008", entry)
        return None

    def _check_firewall_block(self, entry: LogEntry) -> Optional[Alert]:
        """R010: Firewall block events."""
        if _PATTERNS["firewall_block"].search(entry.message):
            return self._make_alert("R010", entry)
        return None

    def _check_kernel_panic(self, entry: LogEntry) -> Optional[Alert]:
        """R011: Kernel panic or critical kernel errors."""
        if _PATTERNS["kernel_panic"].search(entry.message):
            return self._make_alert("R011", entry)
        return None

    def _check_disk_full(self, entry: LogEntry) -> Optional[Alert]:
        """R012: Disk space exhaustion."""
        if _PATTERNS["disk_full"].search(entry.message):
            return self._make_alert("R012", entry)
        return None

    def _check_service_crash(self, entry: LogEntry) -> Optional[Alert]:
        """R013: Service crash or unexpected termination."""
        if _PATTERNS["service_crash"].search(entry.message):
            return self._make_alert("R013", entry)
        return None

    def _check_excessive_404(self, entry: LogEntry) -> Optional[Alert]:
        """R015: Excessive 404 errors indicating directory enumeration."""
        if not _PATTERNS["http_404"].search(entry.message):
            return None

        ip = entry.source_ip or "unknown"
        self._404_counts[ip].append(entry.timestamp)

        cutoff = entry.timestamp.timestamp() - 30
        self._404_counts[ip] = [
            t for t in self._404_counts[ip] if t.timestamp() > cutoff
        ]

        count = len(self._404_counts[ip])
        if count >= 10:
            return self._make_alert(
                "R015", entry,
                f"Excessive 404 errors: {count} from {ip} in 30 seconds. "
                f"Possible directory enumeration.",
                event_count=count,
            )
        return None

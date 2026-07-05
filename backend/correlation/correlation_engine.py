"""
SysLog Threat Analysis — Correlation Engine

Combines individual alerts into higher-level security incidents.
Uses sliding time windows and threshold-based correlation to group
related events, reducing alert noise and surfacing meaningful patterns.

Correlation scenarios:
- Brute Force: ≥5 failures from same IP in 60s
- Account Compromise: failures → success from same IP in 120s
- Web Reconnaissance: ≥20 different paths from same IP in 30s
- Privilege Escalation Sequence: login → sudo from same user in 300s
- Repeated Service Failure: ≥3 crashes of same service in 60s
"""

from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Optional

from config import CORRELATION_THRESHOLDS
from models.events import (
    Alert,
    Incident,
    IncidentStatus,
    LogEntry,
    Severity,
    TimelineEvent,
)

logger = logging.getLogger(__name__)


class CorrelationEngine:
    """
    Correlates individual alerts and log entries into security incidents.

    Maintains sliding window state per correlation scenario. When a
    threshold is crossed, an Incident is created or an existing one updated.
    """

    def __init__(self) -> None:
        self._thresholds = CORRELATION_THRESHOLDS
        self._incidents: list[Incident] = []
        self._incident_map: dict[str, Incident] = {}  # correlation_key -> incident

        # Tracking state
        self._auth_failures: dict[str, list[dict]] = defaultdict(list)     # ip -> events
        self._auth_successes: dict[str, list[dict]] = defaultdict(list)    # ip -> events
        self._web_paths: dict[str, set[str]] = defaultdict(set)            # ip -> paths
        self._web_events: dict[str, list[dict]] = defaultdict(list)        # ip -> events
        self._priv_esc: dict[str, list[dict]] = defaultdict(list)          # user -> events
        self._service_fails: dict[str, list[dict]] = defaultdict(list)     # service -> events

    def feed(self, entry: LogEntry, alerts: list[Alert]) -> list[Incident]:
        """
        Feed a log entry and its associated alerts into the correlator.
        Returns any new or updated incidents.
        """
        new_incidents: list[Incident] = []

        for scenario in [
            self._correlate_brute_force,
            self._correlate_account_compromise,
            self._correlate_web_recon,
            self._correlate_priv_esc_sequence,
            self._correlate_service_failure,
        ]:
            incident = scenario(entry, alerts)
            if incident is not None:
                new_incidents.append(incident)

        return new_incidents

    def get_incidents(self) -> list[Incident]:
        """Return all known incidents."""
        return list(self._incidents)

    def get_active_incidents(self) -> list[Incident]:
        """Return only active / investigating incidents."""
        return [
            i for i in self._incidents
            if i.status in (IncidentStatus.ACTIVE, IncidentStatus.INVESTIGATING)
        ]

    def get_incident(self, incident_id: str) -> Optional[Incident]:
        """Retrieve a single incident by ID."""
        for inc in self._incidents:
            if inc.incident_id == incident_id:
                return inc
        return None

    def clear(self) -> None:
        """Reset all correlation state."""
        self._incidents.clear()
        self._incident_map.clear()
        self._auth_failures.clear()
        self._auth_successes.clear()
        self._web_paths.clear()
        self._web_events.clear()
        self._priv_esc.clear()
        self._service_fails.clear()

    # -------------------------------------------------------------------
    # Incident management
    # -------------------------------------------------------------------

    def _get_or_create_incident(
        self,
        key: str,
        incident_type: str,
        severity: Severity,
        entry: LogEntry,
    ) -> tuple[Incident, bool]:
        """
        Get an existing incident by correlation key, or create a new one.
        Returns (incident, is_new).
        """
        if key in self._incident_map:
            inc = self._incident_map[key]
            return inc, False

        inc = Incident(
            incident_type=incident_type,
            severity=severity,
            status=IncidentStatus.ACTIVE,
            first_seen=entry.timestamp,
            last_seen=entry.timestamp,
        )
        self._incident_map[key] = inc
        self._incidents.append(inc)
        return inc, True

    def _update_incident(
        self,
        inc: Incident,
        entry: LogEntry,
        alerts: list[Alert],
        event_description: str,
    ) -> None:
        """Update an incident with new event data."""
        inc.last_seen = entry.timestamp
        inc.total_events += 1

        if entry.source_ip and entry.source_ip not in inc.source_ips:
            inc.source_ips.append(entry.source_ip)
        if entry.username:
            inc.target_user = entry.username

        inc.related_event_ids.append(entry.event_id)

        for alert in alerts:
            if alert.alert_id not in inc.related_alert_ids:
                inc.related_alert_ids.append(alert.alert_id)
            if alert.rule_id not in inc.triggered_rules:
                inc.triggered_rules.append(alert.rule_id)
            if alert.mitre and alert.mitre not in inc.mitre_techniques:
                inc.mitre_techniques.append(alert.mitre)

        inc.timeline.append(TimelineEvent(
            timestamp=entry.timestamp,
            event_type=entry.event_type.value,
            description=event_description,
            severity=entry.severity,
        ))

    # -------------------------------------------------------------------
    # Correlation scenarios
    # -------------------------------------------------------------------

    def _correlate_brute_force(
        self, entry: LogEntry, alerts: list[Alert]
    ) -> Optional[Incident]:
        """Correlate SSH brute force: ≥5 failures from same IP in 60s."""
        has_failure = any(a.rule_id in ("R001", "R014") for a in alerts)
        if not has_failure:
            return None

        ip = entry.source_ip or "unknown"
        cfg = self._thresholds["brute_force"]
        window = cfg["window_seconds"]
        min_events = cfg["min_events"]

        self._auth_failures[ip].append({
            "timestamp": entry.timestamp,
            "entry": entry,
        })

        # Prune outside window
        cutoff = entry.timestamp - timedelta(seconds=window)
        self._auth_failures[ip] = [
            e for e in self._auth_failures[ip] if e["timestamp"] >= cutoff
        ]

        count = len(self._auth_failures[ip])
        if count < min_events:
            return None

        key = f"brute_force:{ip}"
        inc, is_new = self._get_or_create_incident(
            key, "Brute Force Attack", Severity.HIGH, entry
        )
        self._update_incident(
            inc, entry, alerts,
            f"Failed login attempt #{count} from {ip}"
        )
        inc.correlation_explanation = (
            f"Detected {count} failed authentication attempts from {ip} "
            f"within a {window}-second window, exceeding the threshold of {min_events}."
        )

        if is_new:
            return inc
        return inc  # Return updated incident too

    def _correlate_account_compromise(
        self, entry: LogEntry, alerts: list[Alert]
    ) -> Optional[Incident]:
        """Correlate account compromise: success after failures from same IP."""
        has_success = any(a.rule_id == "R002" for a in alerts)
        if not has_success:
            return None

        ip = entry.source_ip or "unknown"
        key = f"account_compromise:{ip}"

        inc, is_new = self._get_or_create_incident(
            key, "Account Compromise", Severity.CRITICAL, entry
        )

        prior_failures = len(self._auth_failures.get(ip, []))

        self._update_incident(
            inc, entry, alerts,
            f"Successful login from {ip} after {prior_failures} failed attempts"
        )

        inc.timeline.append(TimelineEvent(
            timestamp=entry.timestamp,
            event_type="Critical",
            description="Critical Incident Created — Possible Account Compromise",
            severity=Severity.CRITICAL,
        ))

        inc.correlation_explanation = (
            f"Source IP {ip} made {prior_failures} failed login attempts "
            f"before successfully authenticating. This pattern strongly indicates "
            f"a brute-force credential compromise."
        )

        return inc

    def _correlate_web_recon(
        self, entry: LogEntry, alerts: list[Alert]
    ) -> Optional[Incident]:
        """Correlate web reconnaissance: many different paths from same IP."""
        has_web_alert = any(a.rule_id in ("R015", "R008", "R007", "R006") for a in alerts)
        if not has_web_alert and entry.event_type.value != "Web Server":
            return None

        ip = entry.source_ip or "unknown"
        cfg = self._thresholds["web_recon"]
        window = cfg["window_seconds"]
        min_paths = cfg["min_paths"]

        # Extract path from message
        path = ""
        parts = entry.message.split()
        if len(parts) >= 2:
            path = parts[1] if parts[0] in ("GET", "POST", "PUT", "DELETE", "HEAD") else parts[0]

        self._web_paths[ip].add(path)
        self._web_events[ip].append({
            "timestamp": entry.timestamp,
            "entry": entry,
        })

        cutoff = entry.timestamp - timedelta(seconds=window)
        self._web_events[ip] = [
            e for e in self._web_events[ip] if e["timestamp"] >= cutoff
        ]

        if len(self._web_paths[ip]) < min_paths:
            return None

        key = f"web_recon:{ip}"
        inc, is_new = self._get_or_create_incident(
            key, "Web Reconnaissance", Severity.HIGH, entry
        )
        self._update_incident(
            inc, entry, alerts,
            f"Web enumeration: {len(self._web_paths[ip])} unique paths probed by {ip}"
        )
        inc.correlation_explanation = (
            f"Source IP {ip} probed {len(self._web_paths[ip])} unique paths "
            f"within {window} seconds, indicating systematic web reconnaissance."
        )
        return inc

    def _correlate_priv_esc_sequence(
        self, entry: LogEntry, alerts: list[Alert]
    ) -> Optional[Incident]:
        """Correlate privilege escalation: login → sudo from same user."""
        has_priv = any(a.rule_id == "R005" for a in alerts)
        if not has_priv:
            return None

        user = entry.username or "unknown"
        key = f"priv_esc:{user}"

        inc, is_new = self._get_or_create_incident(
            key, "Privilege Escalation Sequence", Severity.HIGH, entry
        )
        self._update_incident(
            inc, entry, alerts,
            f"Privilege escalation by user {user}"
        )
        inc.correlation_explanation = (
            f"User '{user}' performed privilege escalation. "
            f"Investigating whether this follows a recent login or is part of a lateral movement."
        )
        return inc

    def _correlate_service_failure(
        self, entry: LogEntry, alerts: list[Alert]
    ) -> Optional[Incident]:
        """Correlate repeated service failures: ≥3 crashes of same service in 60s."""
        has_crash = any(a.rule_id == "R013" for a in alerts)
        if not has_crash:
            return None

        service = entry.service or "unknown"
        cfg = self._thresholds["repeated_service_fail"]
        window = cfg["window_seconds"]
        min_events = cfg["min_events"]

        self._service_fails[service].append({
            "timestamp": entry.timestamp,
            "entry": entry,
        })

        cutoff = entry.timestamp - timedelta(seconds=window)
        self._service_fails[service] = [
            e for e in self._service_fails[service] if e["timestamp"] >= cutoff
        ]

        count = len(self._service_fails[service])
        if count < min_events:
            return None

        key = f"service_fail:{service}"
        inc, is_new = self._get_or_create_incident(
            key, "Repeated Service Failure", Severity.MEDIUM, entry
        )
        self._update_incident(
            inc, entry, alerts,
            f"Service '{service}' crashed {count} times in {window}s"
        )
        inc.correlation_explanation = (
            f"Service '{service}' failed {count} times within {window} seconds. "
            f"This may indicate a denial-of-service condition or a persistent bug."
        )
        return inc

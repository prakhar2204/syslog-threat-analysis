"""
SysLog Threat Analysis — IOC Relationship Engine

Builds relationships between IOCs instead of treating them as isolated
indicators. Tracks: IP→User→Host→Service→Rule→Incident relationships,
frequency, confidence, and timeline.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Optional

from models.events import Alert, LogEntry

logger = logging.getLogger(__name__)


class IOCRelationship:
    """An IOC with tracked relationships and metadata."""

    def __init__(self, ioc_type: str, value: str) -> None:
        self.ioc_type = ioc_type
        self.value = value
        self.first_seen: Optional[datetime] = None
        self.last_seen: Optional[datetime] = None
        self.occurrences: int = 0
        self.related_alerts: set[str] = set()
        self.related_incidents: set[str] = set()
        self.related_users: set[str] = set()
        self.related_services: set[str] = set()
        self.related_hosts: set[str] = set()
        self.related_rules: set[str] = set()
        self.related_ips: set[str] = set()
        self.confidence: float = 0.0

    def update(self, timestamp: datetime) -> None:
        """Update occurrence tracking."""
        self.occurrences += 1
        if self.first_seen is None or timestamp < self.first_seen:
            self.first_seen = timestamp
        if self.last_seen is None or timestamp > self.last_seen:
            self.last_seen = timestamp
        self._recalc_confidence()

    def _recalc_confidence(self) -> None:
        """Recalculate IOC confidence based on accumulated data."""
        score = 0.0
        score += min(self.occurrences * 3, 30)
        score += min(len(self.related_incidents) * 15, 30)
        score += min(len(self.related_rules) * 10, 20)
        score += min(len(self.related_alerts) * 2, 10)
        score += 10  # base
        self.confidence = min(score, 100.0)

    def to_dict(self) -> dict:
        """Serialize for API response."""
        return {
            "ioc_type": self.ioc_type,
            "value": self.value,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "occurrences": self.occurrences,
            "related_alerts": len(self.related_alerts),
            "related_incidents": len(self.related_incidents),
            "related_users": sorted(self.related_users),
            "related_services": sorted(self.related_services),
            "related_hosts": sorted(self.related_hosts),
            "related_rules": sorted(self.related_rules),
            "related_ips": sorted(self.related_ips),
            "confidence": round(self.confidence, 1),
        }


class IOCRelationshipEngine:
    """
    Builds and maintains IOC relationship graph.
    Tracks relationships between IPs, users, hosts, services, and rules.
    """

    def __init__(self) -> None:
        # (ioc_type, value) -> IOCRelationship
        self._iocs: dict[tuple[str, str], IOCRelationship] = {}

    def track_event(
        self,
        entry: LogEntry,
        alerts: list[Alert],
        incident_id: Optional[str] = None,
    ) -> None:
        """Track IOCs from a log entry and build relationships."""
        timestamp = entry.timestamp

        # Collect all IOC values from the entry
        ioc_pairs: list[tuple[str, str]] = []
        if entry.source_ip:
            ioc_pairs.append(("ipv4", entry.source_ip))
        if entry.username:
            ioc_pairs.append(("username", entry.username))
        if entry.hostname:
            ioc_pairs.append(("hostname", entry.hostname))
        if entry.service:
            ioc_pairs.append(("service", entry.service))

        # Get or create IOC entries and update metadata
        for ioc_type, value in ioc_pairs:
            ioc = self._get_or_create(ioc_type, value)
            ioc.update(timestamp)

            # Add cross-relationships
            if entry.source_ip and ioc_type != "ipv4":
                ioc.related_ips.add(entry.source_ip)
            if entry.username and ioc_type != "username":
                ioc.related_users.add(entry.username)
            if entry.hostname and ioc_type != "hostname":
                ioc.related_hosts.add(entry.hostname)
            if entry.service and ioc_type != "service":
                ioc.related_services.add(entry.service)

            for alert in alerts:
                ioc.related_alerts.add(alert.alert_id)
                ioc.related_rules.add(alert.rule_id)

            if incident_id:
                ioc.related_incidents.add(incident_id)

    def get_ioc(self, ioc_type: str, value: str) -> Optional[dict]:
        """Get a single IOC with all its relationships."""
        ioc = self._iocs.get((ioc_type, value))
        return ioc.to_dict() if ioc else None

    def get_top_iocs(self, limit: int = 20) -> list[dict]:
        """Get top IOCs ranked by confidence."""
        ranked = sorted(
            self._iocs.values(),
            key=lambda i: (i.confidence, i.occurrences),
            reverse=True,
        )
        return [i.to_dict() for i in ranked[:limit]]

    def get_iocs_for_incident(self, incident_id: str) -> list[dict]:
        """Get all IOCs related to a specific incident."""
        return [
            ioc.to_dict()
            for ioc in self._iocs.values()
            if incident_id in ioc.related_incidents
        ]

    def get_related_iocs(self, ioc_type: str, value: str) -> list[dict]:
        """Get IOCs related to a given IOC through shared context."""
        source = self._iocs.get((ioc_type, value))
        if not source:
            return []

        related = set()
        # Find IOCs that share incidents, rules, or IPs
        for key, ioc in self._iocs.items():
            if key == (ioc_type, value):
                continue
            shared_incidents = source.related_incidents & ioc.related_incidents
            shared_rules = source.related_rules & ioc.related_rules
            shared_ips = source.related_ips & ioc.related_ips
            if shared_incidents or shared_rules or shared_ips:
                related.add(key)

        return [self._iocs[k].to_dict() for k in related]

    def clear(self) -> None:
        """Reset all IOC state."""
        self._iocs.clear()

    def _get_or_create(self, ioc_type: str, value: str) -> IOCRelationship:
        """Get or create an IOCRelationship."""
        key = (ioc_type, value)
        if key not in self._iocs:
            self._iocs[key] = IOCRelationship(ioc_type, value)
        return self._iocs[key]

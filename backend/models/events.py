"""
SysLog Threat Analysis — Event Models

Pydantic models representing every entity in the processing pipeline:
log entries, alerts, incidents, and dashboard statistics.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class EventType(str, Enum):
    AUTHENTICATION = "Authentication"
    NETWORK = "Network"
    FIREWALL = "Firewall"
    WEB_SERVER = "Web Server"
    SYSTEM = "System"
    KERNEL = "Kernel"
    APPLICATION = "Application"
    FILE_ACCESS = "File Access"
    UNKNOWN = "Unknown"


class AlertStatus(str, Enum):
    ACTIVE = "ACTIVE"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    RESOLVED = "RESOLVED"


class IncidentStatus(str, Enum):
    ACTIVE = "ACTIVE"
    INVESTIGATING = "INVESTIGATING"
    RESOLVED = "RESOLVED"
    CLOSED = "CLOSED"


# ---------------------------------------------------------------------------
# Log Entry — normalized output from the parser
# ---------------------------------------------------------------------------

class LogEntry(BaseModel):
    """A single normalized log entry produced by the parser."""

    event_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    timestamp: datetime = Field(default_factory=datetime.now)
    hostname: str = ""
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    username: Optional[str] = None
    service: str = ""
    process: str = ""
    event_type: EventType = EventType.UNKNOWN
    message: str = ""
    raw_log: str = ""
    severity: Severity = Severity.INFO
    log_format: str = ""


# ---------------------------------------------------------------------------
# Detection Rule definition
# ---------------------------------------------------------------------------

class DetectionRule(BaseModel):
    """Definition of a single threat detection rule."""

    rule_id: str
    name: str
    description: str
    severity: Severity
    mitre: Optional[str] = None
    recommendation: str = ""


# ---------------------------------------------------------------------------
# Alert — produced when a detection rule matches
# ---------------------------------------------------------------------------

class Alert(BaseModel):
    """An alert generated when a detection rule triggers on a log entry."""

    alert_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    rule_id: str
    rule_name: str
    severity: Severity
    source_ip: Optional[str] = None
    username: Optional[str] = None
    description: str = ""
    matched_event_id: str = ""
    timestamp: datetime = Field(default_factory=datetime.now)
    status: AlertStatus = AlertStatus.ACTIVE
    mitre: Optional[str] = None
    event_count: int = 1


# ---------------------------------------------------------------------------
# Timeline Event — a single point in an incident timeline
# ---------------------------------------------------------------------------

class TimelineEvent(BaseModel):
    """One step in an incident's chronological timeline."""

    timestamp: datetime
    event_type: str
    description: str
    severity: Severity = Severity.INFO


# ---------------------------------------------------------------------------
# Incident — a correlated collection of related alerts
# ---------------------------------------------------------------------------

class Incident(BaseModel):
    """A security incident composed of correlated alerts and events."""

    incident_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:16])
    incident_type: str
    severity: Severity
    confidence: float = 0.0
    risk: str = "LOW"
    status: IncidentStatus = IncidentStatus.ACTIVE
    source_ips: list[str] = Field(default_factory=list)
    target_user: Optional[str] = None
    first_seen: datetime = Field(default_factory=datetime.now)
    last_seen: datetime = Field(default_factory=datetime.now)
    total_events: int = 0
    description: str = ""
    reasoning: str = ""
    recommendations: list[str] = Field(default_factory=list)
    timeline: list[TimelineEvent] = Field(default_factory=list)
    related_alert_ids: list[str] = Field(default_factory=list)
    related_event_ids: list[str] = Field(default_factory=list)
    triggered_rules: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    correlation_explanation: str = ""


# ---------------------------------------------------------------------------
# Dashboard Statistics
# ---------------------------------------------------------------------------

class DashboardStats(BaseModel):
    """Aggregate statistics shown on the dashboard summary cards."""

    total_logs: int = 0
    info_events: int = 0
    warning_events: int = 0
    high_events: int = 0
    critical_events: int = 0
    total_alerts: int = 0
    active_alerts: int = 0
    total_incidents: int = 0
    active_incidents: int = 0
    top_source_ips: list[dict] = Field(default_factory=list)
    top_event_types: list[dict] = Field(default_factory=list)
    severity_distribution: list[dict] = Field(default_factory=list)
    logs_over_time: list[dict] = Field(default_factory=list)
    rule_frequency: list[dict] = Field(default_factory=list)
    threat_trend: list[dict] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Monitoring Status
# ---------------------------------------------------------------------------

class MonitoringStatus(BaseModel):
    """Current state of the log file watcher."""

    active: bool = False
    file_path: str = ""
    lines_processed: int = 0
    last_event_time: Optional[datetime] = None

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
    evidence_id: Optional[str] = None  # Link to Evidence object

    # --- Phase 5.4: Advanced Intelligence Fields ---
    attack_chain_id: Optional[str] = None
    attack_chain_stage: str = ""
    attack_chain_progress: float = 0.0
    attack_chain_stages_completed: list[str] = Field(default_factory=list)
    attack_chain_stages_missing: list[str] = Field(default_factory=list)
    estimated_objective: str = ""
    threat_score: float = 0.0
    threat_score_breakdown: dict = Field(default_factory=dict)
    priority: int = 0
    behavioural_findings: list[str] = Field(default_factory=list)
    root_cause: str = ""
    smart_recommendations: list[dict] = Field(default_factory=list)
    executive_summary: str = ""
    technical_summary: str = ""
    attack_narrative: str = ""
    affected_assets: list[str] = Field(default_factory=list)
    mitre_summary: str = ""
    merged_incident_ids: list[str] = Field(default_factory=list)
    is_merged: bool = False



# ---------------------------------------------------------------------------
# Evidence Intelligence Engine — Matched Conditions
# ---------------------------------------------------------------------------

class MatchedCondition(BaseModel):
    """A single condition evaluated during rule matching."""

    condition: str
    matched: bool
    value: str = ""


# ---------------------------------------------------------------------------
# Evidence Intelligence Engine — Extracted IOC
# ---------------------------------------------------------------------------

class ExtractedIOC(BaseModel):
    """An indicator of compromise extracted from log evidence."""

    ioc_type: str  # ipv4, ipv6, username, hostname, port, service, process, filepath, command, url, email, domain, hash
    value: str
    source_event_id: str = ""


# ---------------------------------------------------------------------------
# Evidence Intelligence Engine — Raw Log Reference
# ---------------------------------------------------------------------------

class RawLogRef(BaseModel):
    """Reference to a raw log entry with parsed fields preserved."""

    event_id: str
    raw_log: str
    timestamp: datetime
    hostname: str = ""
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    username: Optional[str] = None
    service: str = ""
    process: str = ""
    event_type: str = ""
    message: str = ""
    severity: str = ""
    detection_rule_ids: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Evidence Object
# ---------------------------------------------------------------------------

class Evidence(BaseModel):
    """Structured evidence collected for a security detection."""

    evidence_id: str = Field(default_factory=lambda: f"EV-{uuid.uuid4().hex[:12]}")
    incident_id: Optional[str] = None
    rule_id: str = ""
    rule_name: str = ""
    severity: Severity = Severity.INFO

    # Matched conditions — explicit WHY
    matched_conditions: list[MatchedCondition] = Field(default_factory=list)

    # Context
    source_ips: list[str] = Field(default_factory=list)
    destination_ips: list[str] = Field(default_factory=list)
    hostnames: list[str] = Field(default_factory=list)
    usernames: list[str] = Field(default_factory=list)
    processes: list[str] = Field(default_factory=list)
    services: list[str] = Field(default_factory=list)
    protocols: list[str] = Field(default_factory=list)
    ports: list[int] = Field(default_factory=list)

    # Time
    first_seen: datetime = Field(default_factory=datetime.now)
    last_seen: datetime = Field(default_factory=datetime.now)

    # References
    related_event_ids: list[str] = Field(default_factory=list)
    related_alert_ids: list[str] = Field(default_factory=list)
    raw_log_refs: list[RawLogRef] = Field(default_factory=list)

    # IOCs
    extracted_iocs: list[ExtractedIOC] = Field(default_factory=list)

    # Counts
    event_count: int = 0
    unique_source_count: int = 0
    unique_dest_count: int = 0

    # Confidence in evidence completeness (0-100)
    collection_confidence: float = 0.0


# ---------------------------------------------------------------------------
# Observation — sub-threshold detection
# ---------------------------------------------------------------------------

class ObservationStatus(str, Enum):
    OPEN = "OPEN"
    PROMOTED = "PROMOTED"
    DISMISSED = "DISMISSED"


class Observation(BaseModel):
    """A low-confidence detection that may promote to an Incident."""

    observation_id: str = Field(default_factory=lambda: f"OBS-{uuid.uuid4().hex[:10]}")
    status: ObservationStatus = ObservationStatus.OPEN
    rule_id: str = ""
    rule_name: str = ""
    severity: Severity = Severity.INFO

    matched_conditions: list[MatchedCondition] = Field(default_factory=list)

    source_ips: list[str] = Field(default_factory=list)
    usernames: list[str] = Field(default_factory=list)
    services: list[str] = Field(default_factory=list)
    hostnames: list[str] = Field(default_factory=list)

    first_seen: datetime = Field(default_factory=datetime.now)
    last_seen: datetime = Field(default_factory=datetime.now)

    related_event_ids: list[str] = Field(default_factory=list)
    related_alert_ids: list[str] = Field(default_factory=list)
    raw_log_refs: list[RawLogRef] = Field(default_factory=list)
    extracted_iocs: list[ExtractedIOC] = Field(default_factory=list)

    event_count: int = 0
    unique_source_count: int = 0

    collection_confidence: float = 0.0

    # Promotion tracking
    promoted: bool = False
    promoted_to_incident_id: Optional[str] = None


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

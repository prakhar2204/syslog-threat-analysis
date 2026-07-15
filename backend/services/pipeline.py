"""
SysLog Threat Analysis — Processing Pipeline

Orchestrates the full processing chain:
  Raw Lines → Parser → Detection → Correlation → Incident Builder → WebSocket Push

This is the central nervous system of the backend. The LogWatcher
calls the pipeline whenever new lines appear in the monitored file.
"""

from __future__ import annotations

import logging
from collections import Counter, defaultdict
from datetime import datetime
from typing import Optional

from analysis.evidence_engine import EvidenceEngine
from analysis.evidence_graph import EvidenceGraph, NodeType, EdgeType
from analysis.incident_builder import IncidentBuilder
from config import MAX_ALERTS_BUFFER, MAX_INCIDENTS_BUFFER, MAX_LOG_BUFFER
from correlation.correlation_engine import CorrelationEngine
from detection.threat_engine import ThreatEngine
from models.events import (
    Alert,
    DashboardStats,
    Evidence,
    Incident,
    LogEntry,
    MonitoringStatus,
    Observation,
    Severity,
)
from parser.log_parser import LogParser
from websocket.manager import ws_manager

logger = logging.getLogger(__name__)


class Pipeline:
    """
    Central processing pipeline that ties all backend modules together.

    Maintains in-memory buffers of parsed logs, alerts, and incidents.
    Broadcasts updates through the WebSocket manager.
    """

    def __init__(self) -> None:
        self.parser = LogParser()
        self.threat_engine = ThreatEngine()
        self.correlation_engine = CorrelationEngine()
        self.incident_builder = IncidentBuilder()
        self.evidence_engine = EvidenceEngine()
        self.evidence_graph = EvidenceGraph()

        # In-memory buffers (bounded)
        self.log_entries: list[LogEntry] = []
        self.alerts: list[Alert] = []
        self.incidents: list[Incident] = []

        # Monitoring state
        self.monitoring = MonitoringStatus()

    async def process_lines(self, lines: list[str]) -> None:
        """
        Process a batch of raw log lines through the full pipeline.

        1. Parse each line
        2. Run detection rules
        3. Feed to correlation engine
        4. Build/enrich incidents
        5. Broadcast updates via WebSocket
        """
        if not lines:
            return

        new_entries: list[LogEntry] = []
        new_alerts: list[Alert] = []
        new_incidents: list[Incident] = []

        for line in lines:
            # Step 1: Parse
            entry = self.parser.parse_line(line)
            if entry is None:
                continue

            new_entries.append(entry)
            self.log_entries.append(entry)

            # Step 2: Detection
            alerts = self.threat_engine.analyze(entry)
            for alert in alerts:
                new_alerts.append(alert)
                self.alerts.append(alert)

            # Step 3: Correlation
            incidents = self.correlation_engine.feed(entry, alerts)
            for incident in incidents:
                # Step 4: Enrich with confidence, risk, reasoning
                self.incident_builder.enrich(incident)

                # Step 4.5: Collect evidence
                evidence = self.evidence_engine.collect(incident, entry, alerts)

                # Update evidence graph
                self.evidence_graph.add_event(
                    entry.event_id, entry.hostname, entry.source_ip,
                    entry.username, entry.service,
                )
                for a in alerts:
                    self.evidence_graph.add_alert(a.alert_id, entry.event_id, a.rule_id)
                self.evidence_graph.add_incident(
                    incident.incident_id,
                    [a.alert_id for a in alerts],
                    [entry.event_id],
                )

                if incident.incident_id not in {i.incident_id for i in self.incidents}:
                    self.incidents.append(incident)
                    new_incidents.append(incident)
                else:
                    # Update existing — re-enrich
                    for idx, existing in enumerate(self.incidents):
                        if existing.incident_id == incident.incident_id:
                            self.incidents[idx] = incident
                            break
                    new_incidents.append(incident)

            # Step 4.6: Create observations for alerts without incidents
            if alerts and not incidents:
                self.evidence_engine.create_observation(entry, alerts)
                # Graph nodes for non-incident events
                self.evidence_graph.add_event(
                    entry.event_id, entry.hostname, entry.source_ip,
                    entry.username, entry.service,
                )
                for a in alerts:
                    self.evidence_graph.add_alert(a.alert_id, entry.event_id, a.rule_id)

        # Step 4.7: Check observation promotions
        promoted = self.evidence_engine.check_promotion()

        # Enforce buffer limits
        self._enforce_limits()

        # Update monitoring status
        self.monitoring.lines_processed += len(new_entries)
        if new_entries:
            self.monitoring.last_event_time = new_entries[-1].timestamp

        # Step 5: Broadcast via WebSocket
        if new_entries:
            await ws_manager.broadcast("new_logs", new_entries[-50:])  # Last 50 only

        for alert in new_alerts:
            await ws_manager.broadcast("new_alert", alert)

        for incident in new_incidents:
            await ws_manager.broadcast("new_incident", incident)

        # Broadcast evidence and observation events
        for incident in new_incidents:
            evidence = self.evidence_engine.get_evidence_by_incident(incident.incident_id)
            if evidence:
                await ws_manager.broadcast("evidence_created", evidence)

        for obs in promoted:
            await ws_manager.broadcast("observation_promoted", obs)

        if new_entries:
            stats = self.compute_stats()
            await ws_manager.broadcast("stats_update", stats)

    def compute_stats(self) -> DashboardStats:
        """Compute current dashboard statistics from the in-memory buffers."""
        severity_counts = Counter(e.severity.value for e in self.log_entries)
        event_type_counts = Counter(e.event_type.value for e in self.log_entries)
        ip_counts = Counter(e.source_ip for e in self.log_entries if e.source_ip)
        rule_counts = Counter(a.rule_id for a in self.alerts)

        # Logs over time (group by minute)
        time_buckets: dict[str, int] = defaultdict(int)
        for entry in self.log_entries:
            bucket = entry.timestamp.strftime("%H:%M")
            time_buckets[bucket] += 1

        # Threat trend (alerts over time by minute)
        threat_buckets: dict[str, int] = defaultdict(int)
        for alert in self.alerts:
            bucket = alert.timestamp.strftime("%H:%M")
            threat_buckets[bucket] += 1

        from detection.rules import RULES_BY_ID

        return DashboardStats(
            total_logs=len(self.log_entries),
            info_events=severity_counts.get("INFO", 0),
            warning_events=severity_counts.get("MEDIUM", 0) + severity_counts.get("LOW", 0),
            high_events=severity_counts.get("HIGH", 0),
            critical_events=severity_counts.get("CRITICAL", 0),
            total_alerts=len(self.alerts),
            active_alerts=len(self.threat_engine.get_active_alerts()),
            total_incidents=len(self.incidents),
            active_incidents=len(self.correlation_engine.get_active_incidents()),
            top_source_ips=[
                {"ip": ip, "count": cnt}
                for ip, cnt in ip_counts.most_common(10)
            ],
            top_event_types=[
                {"type": et, "count": cnt}
                for et, cnt in event_type_counts.most_common(10)
            ],
            severity_distribution=[
                {"severity": sev, "count": severity_counts.get(sev, 0)}
                for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
            ],
            logs_over_time=[
                {"time": t, "count": c}
                for t, c in sorted(time_buckets.items())
            ],
            rule_frequency=[
                {"rule_id": rid, "rule_name": RULES_BY_ID[rid].name if rid in RULES_BY_ID else rid, "count": cnt}
                for rid, cnt in rule_counts.most_common(10)
            ],
            threat_trend=[
                {"time": t, "count": c}
                for t, c in sorted(threat_buckets.items())
            ],
        )

    def get_entries(
        self,
        search: Optional[str] = None,
        severity: Optional[str] = None,
        event_type: Optional[str] = None,
        source_ip: Optional[str] = None,
        username: Optional[str] = None,
        service: Optional[str] = None,
        limit: int = 200,
        offset: int = 0,
    ) -> tuple[list[LogEntry], int]:
        """
        Query log entries with optional filters.
        Returns (filtered_entries, total_count).
        """
        filtered = self.log_entries

        if search:
            search_lower = search.lower()
            filtered = [
                e for e in filtered
                if search_lower in e.message.lower()
                or search_lower in (e.source_ip or "").lower()
                or search_lower in (e.username or "").lower()
                or search_lower in e.service.lower()
                or search_lower in e.raw_log.lower()
            ]

        if severity:
            filtered = [e for e in filtered if e.severity.value == severity.upper()]

        if event_type:
            filtered = [e for e in filtered if e.event_type.value == event_type]

        if source_ip:
            filtered = [e for e in filtered if e.source_ip == source_ip]

        if username:
            filtered = [e for e in filtered if e.username and username.lower() in e.username.lower()]

        if service:
            filtered = [e for e in filtered if service.lower() in e.service.lower()]

        total = len(filtered)

        # Sort newest first and paginate
        filtered = sorted(filtered, key=lambda e: e.timestamp, reverse=True)
        filtered = filtered[offset: offset + limit]

        return filtered, total

    def get_entry_detail(self, event_id: str) -> Optional[dict]:
        """Get detailed information about a single log entry including triggered rules."""
        entry = next((e for e in self.log_entries if e.event_id == event_id), None)
        if entry is None:
            return None

        # Find alerts triggered by this entry
        triggered_alerts = [a for a in self.alerts if a.matched_event_id == event_id]
        from detection.rules import RULES_BY_ID
        triggered_rules = []
        for alert in triggered_alerts:
            rule = RULES_BY_ID.get(alert.rule_id)
            if rule:
                triggered_rules.append(rule.model_dump())

        return {
            "entry": entry.model_dump(mode="json"),
            "triggered_alerts": [a.model_dump(mode="json") for a in triggered_alerts],
            "triggered_rules": triggered_rules,
        }

    def clear(self) -> None:
        """Reset all pipeline state."""
        self.log_entries.clear()
        self.alerts.clear()
        self.incidents.clear()
        self.threat_engine.clear()
        self.correlation_engine.clear()
        self.evidence_engine.clear()
        self.evidence_graph.clear()
        self.monitoring = MonitoringStatus()
        logger.info("Pipeline state cleared")

    def _enforce_limits(self) -> None:
        """Trim buffers to prevent unbounded memory growth."""
        if len(self.log_entries) > MAX_LOG_BUFFER:
            trim = len(self.log_entries) - MAX_LOG_BUFFER
            self.log_entries = self.log_entries[trim:]

        if len(self.alerts) > MAX_ALERTS_BUFFER:
            trim = len(self.alerts) - MAX_ALERTS_BUFFER
            self.alerts = self.alerts[trim:]

        if len(self.incidents) > MAX_INCIDENTS_BUFFER:
            trim = len(self.incidents) - MAX_INCIDENTS_BUFFER
            self.incidents = self.incidents[trim:]


# Global instance
pipeline = Pipeline()

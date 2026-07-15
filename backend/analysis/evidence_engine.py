"""
SysLog Threat Analysis - Evidence Engine

Collects, organizes, and preserves all supporting evidence for
every detection. Never performs reasoning — only gathers facts.

Responsibilities:
- Create/update Evidence objects for incidents
- Create Observations for sub-threshold detections
- Auto-promote Observations to Incidents when evidence grows
- Build matched conditions for each rule
- Extract and store IOCs
- Preserve raw log references
"""

from __future__ import annotations

import logging
import re
from collections import defaultdict
from datetime import datetime
from typing import Optional

from analysis.ioc_extractor import extract_iocs
from detection.rules import RULES_BY_ID
from models.events import (
    Alert,
    Evidence,
    ExtractedIOC,
    Incident,
    LogEntry,
    MatchedCondition,
    Observation,
    ObservationStatus,
    RawLogRef,
    Severity,
)

logger = logging.getLogger(__name__)

MAX_RAW_LOG_REFS = 50  # Max raw logs stored per evidence/observation


# ---------------------------------------------------------------------------
# Matched condition builders — one per rule pattern
# ---------------------------------------------------------------------------

def _build_conditions_brute_force(entry: LogEntry, alerts: list[Alert]) -> list[MatchedCondition]:
    """Build matched conditions for SSH brute force rules (R001, R014)."""
    alert = next((a for a in alerts if a.rule_id in ("R001", "R014")), None)
    if not alert:
        return []
    return [
        MatchedCondition(condition="Same source IP", matched=bool(entry.source_ip), value=entry.source_ip or ""),
        MatchedCondition(condition="Same username", matched=bool(entry.username), value=entry.username or ""),
        MatchedCondition(condition=f"{alert.event_count} failures", matched=alert.event_count >= 3, value=str(alert.event_count)),
        MatchedCondition(condition="Within 60 seconds", matched=True, value="60s window"),
        MatchedCondition(condition="Authentication success", matched=False, value="No"),
    ]


def _build_conditions_account_compromise(entry: LogEntry, alerts: list[Alert]) -> list[MatchedCondition]:
    """Build matched conditions for account compromise (R002)."""
    alert = next((a for a in alerts if a.rule_id == "R002"), None)
    if not alert:
        return []
    return [
        MatchedCondition(condition="Prior failed logins", matched=True, value=f"{alert.event_count - 1} failures"),
        MatchedCondition(condition="Successful login", matched=True, value="Accepted password"),
        MatchedCondition(condition="Same source IP", matched=bool(entry.source_ip), value=entry.source_ip or ""),
        MatchedCondition(condition="Within 120 seconds", matched=True, value="120s window"),
    ]


def _build_conditions_invalid_user(entry: LogEntry, alerts: list[Alert]) -> list[MatchedCondition]:
    """Build conditions for invalid user login (R003)."""
    return [
        MatchedCondition(condition="User does not exist", matched=True, value=entry.username or "unknown"),
        MatchedCondition(condition="Login attempt", matched=True, value="Failed password"),
        MatchedCondition(condition="External source", matched=bool(entry.source_ip), value=entry.source_ip or ""),
    ]


def _build_conditions_root_login(entry: LogEntry, alerts: list[Alert]) -> list[MatchedCondition]:
    """Build conditions for root login attempt (R004)."""
    return [
        MatchedCondition(condition="Target user is root", matched=True, value="root"),
        MatchedCondition(condition="Login attempt", matched=True, value="Failed password"),
        MatchedCondition(condition="External source", matched=bool(entry.source_ip), value=entry.source_ip or ""),
    ]


def _build_conditions_priv_esc(entry: LogEntry, alerts: list[Alert]) -> list[MatchedCondition]:
    """Build conditions for privilege escalation (R005)."""
    cmd_match = re.search(r"COMMAND=(.+?)$", entry.raw_log or entry.message, re.MULTILINE)
    return [
        MatchedCondition(condition="Privilege escalation command", matched=True, value="sudo/su"),
        MatchedCondition(condition="User identified", matched=bool(entry.username), value=entry.username or ""),
        MatchedCondition(condition="Command executed", matched=bool(cmd_match), value=cmd_match.group(1).strip() if cmd_match else ""),
    ]


def _build_conditions_sqli(entry: LogEntry, alerts: list[Alert]) -> list[MatchedCondition]:
    """Build conditions for SQL injection (R006)."""
    return [
        MatchedCondition(condition="SQL keyword detected", matched=True, value="UNION/SELECT/OR 1=1"),
        MatchedCondition(condition="Web request", matched=True, value=entry.message[:80]),
        MatchedCondition(condition="Source IP", matched=bool(entry.source_ip), value=entry.source_ip or ""),
    ]


def _build_conditions_traversal(entry: LogEntry, alerts: list[Alert]) -> list[MatchedCondition]:
    """Build conditions for directory traversal (R007)."""
    return [
        MatchedCondition(condition="Path traversal pattern", matched=True, value="../ or %2f"),
        MatchedCondition(condition="Target path", matched=True, value=entry.message[:80]),
        MatchedCondition(condition="Source IP", matched=bool(entry.source_ip), value=entry.source_ip or ""),
    ]


def _build_conditions_suspicious_ua(entry: LogEntry, alerts: list[Alert]) -> list[MatchedCondition]:
    """Build conditions for suspicious user agent (R008)."""
    ua_match = re.search(r"(sqlmap|nikto|nmap|dirbuster|gobuster|wfuzz|hydra|medusa)", entry.message, re.IGNORECASE)
    return [
        MatchedCondition(condition="Known attack tool UA", matched=bool(ua_match), value=ua_match.group(1) if ua_match else ""),
        MatchedCondition(condition="Web request", matched=True, value="HTTP request"),
        MatchedCondition(condition="Source IP", matched=bool(entry.source_ip), value=entry.source_ip or ""),
    ]


def _build_conditions_firewall(entry: LogEntry, alerts: list[Alert]) -> list[MatchedCondition]:
    """Build conditions for firewall block (R010)."""
    port_match = re.search(r"DPT=(\d+)", entry.raw_log or entry.message)
    return [
        MatchedCondition(condition="Firewall action", matched=True, value="BLOCK"),
        MatchedCondition(condition="Source IP", matched=bool(entry.source_ip), value=entry.source_ip or ""),
        MatchedCondition(condition="Destination port", matched=bool(port_match), value=port_match.group(1) if port_match else ""),
        MatchedCondition(condition="Protocol", matched=True, value="TCP"),
    ]


def _build_conditions_generic(entry: LogEntry, alerts: list[Alert]) -> list[MatchedCondition]:
    """Build generic conditions for rules without specific builders."""
    conditions = []
    if entry.source_ip:
        conditions.append(MatchedCondition(condition="Source IP", matched=True, value=entry.source_ip))
    if entry.username:
        conditions.append(MatchedCondition(condition="Username", matched=True, value=entry.username))
    if entry.service:
        conditions.append(MatchedCondition(condition="Service", matched=True, value=entry.service))
    conditions.append(MatchedCondition(condition="Pattern match", matched=True, value=entry.message[:80]))
    return conditions


# Rule ID -> condition builder mapping
_CONDITION_BUILDERS = {
    "R001": _build_conditions_brute_force,
    "R002": _build_conditions_account_compromise,
    "R003": _build_conditions_invalid_user,
    "R004": _build_conditions_root_login,
    "R005": _build_conditions_priv_esc,
    "R006": _build_conditions_sqli,
    "R007": _build_conditions_traversal,
    "R008": _build_conditions_suspicious_ua,
    "R010": _build_conditions_firewall,
    "R014": _build_conditions_brute_force,
}


# ---------------------------------------------------------------------------
# Evidence Engine
# ---------------------------------------------------------------------------

class EvidenceEngine:
    """
    Collects evidence for every detection. Never reasons — only gathers.

    Integration point: called from pipeline after correlation and
    incident enrichment.
    """

    def __init__(self) -> None:
        self._evidence: dict[str, Evidence] = {}         # incident_id -> Evidence
        self._observations: list[Observation] = []
        self._obs_by_key: dict[str, Observation] = {}    # correlation_key -> Observation

    # -- Properties --

    @property
    def evidence_list(self) -> list[Evidence]:
        return list(self._evidence.values())

    @property
    def observations(self) -> list[Observation]:
        return list(self._observations)

    # -- Evidence collection for incidents --

    def collect(
        self,
        incident: Incident,
        entry: LogEntry,
        alerts: list[Alert],
    ) -> Evidence:
        """
        Collect evidence for an incident from a log entry and its alerts.
        Creates or updates the Evidence object linked to the incident.
        """
        evidence = self._evidence.get(incident.incident_id)
        if evidence is None:
            evidence = Evidence(
                incident_id=incident.incident_id,
                severity=incident.severity,
                first_seen=entry.timestamp,
            )
            self._evidence[incident.incident_id] = evidence

            # Set primary rule from first alert
            if alerts:
                evidence.rule_id = alerts[0].rule_id
                evidence.rule_name = alerts[0].rule_name

            # Build matched conditions
            evidence.matched_conditions = self._build_conditions(entry, alerts)

        # Update evidence with new entry data
        self._update_evidence(evidence, entry, alerts)

        # Link evidence to incident
        incident.evidence_id = evidence.evidence_id

        return evidence

    # -- Observation creation --

    def create_observation(
        self,
        entry: LogEntry,
        alerts: list[Alert],
    ) -> Optional[Observation]:
        """
        Create an observation for a sub-threshold detection.
        Called when alerts fire but no incident is created.
        """
        if not alerts:
            return None

        # Build a correlation key for grouping
        primary_alert = alerts[0]
        ip = entry.source_ip or "unknown"
        key = f"{primary_alert.rule_id}:{ip}"

        obs = self._obs_by_key.get(key)
        if obs is None:
            obs = Observation(
                rule_id=primary_alert.rule_id,
                rule_name=primary_alert.rule_name,
                severity=primary_alert.severity,
                first_seen=entry.timestamp,
            )
            obs.matched_conditions = self._build_conditions(entry, alerts)
            self._observations.append(obs)
            self._obs_by_key[key] = obs

        # Update observation
        obs.last_seen = entry.timestamp
        obs.event_count += 1

        if entry.source_ip and entry.source_ip not in obs.source_ips:
            obs.source_ips.append(entry.source_ip)
        if entry.username and entry.username not in obs.usernames:
            obs.usernames.append(entry.username)
        if entry.service and entry.service not in obs.services:
            obs.services.append(entry.service)
        if entry.hostname and entry.hostname not in obs.hostnames:
            obs.hostnames.append(entry.hostname)

        obs.related_event_ids.append(entry.event_id)
        for a in alerts:
            if a.alert_id not in obs.related_alert_ids:
                obs.related_alert_ids.append(a.alert_id)

        # Raw log ref
        if len(obs.raw_log_refs) < MAX_RAW_LOG_REFS:
            obs.raw_log_refs.append(self._make_raw_ref(entry, alerts))

        # IOCs
        iocs = extract_iocs(entry)
        existing_keys = {(i.ioc_type, i.value) for i in obs.extracted_iocs}
        for ioc in iocs:
            if (ioc.ioc_type, ioc.value) not in existing_keys:
                obs.extracted_iocs.append(ioc)
                existing_keys.add((ioc.ioc_type, ioc.value))

        obs.unique_source_count = len(set(obs.source_ips))
        obs.collection_confidence = self._calc_confidence(obs.event_count, obs.unique_source_count, len(obs.related_alert_ids))

        return obs

    # -- Promotion --

    def check_promotion(self) -> list[Observation]:
        """
        Check observations for promotion eligibility.
        Promotes when: event_count >= 3 OR distinct alerts >= 2.
        Returns list of promoted observations.
        """
        promoted: list[Observation] = []
        for obs in self._observations:
            if obs.status != ObservationStatus.OPEN:
                continue
            if obs.event_count >= 3 or len(set(obs.related_alert_ids)) >= 2:
                obs.status = ObservationStatus.PROMOTED
                obs.promoted = True
                promoted.append(obs)
                logger.info(
                    "Observation %s promoted: %d events, %d alerts",
                    obs.observation_id, obs.event_count, len(obs.related_alert_ids),
                )
        return promoted

    def promote_observation(self, observation_id: str, incident_id: str) -> bool:
        """Manually promote a specific observation."""
        for obs in self._observations:
            if obs.observation_id == observation_id:
                obs.status = ObservationStatus.PROMOTED
                obs.promoted = True
                obs.promoted_to_incident_id = incident_id
                return True
        return False

    # -- Lookup --

    def get_evidence(self, evidence_id: str) -> Optional[Evidence]:
        """Get evidence by ID."""
        for ev in self._evidence.values():
            if ev.evidence_id == evidence_id:
                return ev
        return None

    def get_evidence_by_incident(self, incident_id: str) -> Optional[Evidence]:
        """Get evidence linked to an incident."""
        return self._evidence.get(incident_id)

    def get_observation(self, observation_id: str) -> Optional[Observation]:
        """Get observation by ID."""
        for obs in self._observations:
            if obs.observation_id == observation_id:
                return obs
        return None

    def search_evidence(
        self,
        rule_id: Optional[str] = None,
        severity: Optional[str] = None,
        source_ip: Optional[str] = None,
        username: Optional[str] = None,
        service: Optional[str] = None,
        ioc: Optional[str] = None,
        keyword: Optional[str] = None,
    ) -> list[Evidence]:
        """Search evidence by various criteria."""
        results: list[Evidence] = []
        for ev in self._evidence.values():
            if rule_id and ev.rule_id != rule_id:
                continue
            if severity and ev.severity.value != severity.upper():
                continue
            if source_ip and source_ip not in ev.source_ips:
                continue
            if username and username not in ev.usernames:
                continue
            if service and service not in ev.services:
                continue
            if ioc:
                ioc_values = {i.value for i in ev.extracted_iocs}
                if ioc not in ioc_values:
                    continue
            if keyword:
                kw = keyword.lower()
                text = f"{ev.rule_name} {' '.join(ev.source_ips)} {' '.join(ev.usernames)}".lower()
                if kw not in text:
                    continue
            results.append(ev)
        return results

    # -- Clear --

    def clear(self) -> None:
        """Reset all evidence state."""
        self._evidence.clear()
        self._observations.clear()
        self._obs_by_key.clear()

    # -- Internal --

    def _update_evidence(self, evidence: Evidence, entry: LogEntry, alerts: list[Alert]) -> None:
        """Update an evidence object with data from a new entry."""
        evidence.last_seen = entry.timestamp
        evidence.event_count += 1

        # Context fields
        if entry.source_ip and entry.source_ip not in evidence.source_ips:
            evidence.source_ips.append(entry.source_ip)
        if entry.destination_ip and entry.destination_ip not in evidence.destination_ips:
            evidence.destination_ips.append(entry.destination_ip)
        if entry.hostname and entry.hostname not in evidence.hostnames:
            evidence.hostnames.append(entry.hostname)
        if entry.username and entry.username not in evidence.usernames:
            evidence.usernames.append(entry.username)
        if entry.process and entry.process not in evidence.processes:
            evidence.processes.append(entry.process)
        if entry.service and entry.service not in evidence.services:
            evidence.services.append(entry.service)

        # Port extraction
        port_match = re.search(r"DPT=(\d+)", entry.raw_log or entry.message)
        if port_match:
            port = int(port_match.group(1))
            if port not in evidence.ports:
                evidence.ports.append(port)

        # References
        evidence.related_event_ids.append(entry.event_id)
        for a in alerts:
            if a.alert_id not in evidence.related_alert_ids:
                evidence.related_alert_ids.append(a.alert_id)

        # Raw log reference (capped)
        if len(evidence.raw_log_refs) < MAX_RAW_LOG_REFS:
            evidence.raw_log_refs.append(self._make_raw_ref(entry, alerts))

        # IOCs
        iocs = extract_iocs(entry)
        existing_keys = {(i.ioc_type, i.value) for i in evidence.extracted_iocs}
        for ioc in iocs:
            if (ioc.ioc_type, ioc.value) not in existing_keys:
                evidence.extracted_iocs.append(ioc)
                existing_keys.add((ioc.ioc_type, ioc.value))

        # Counts
        evidence.unique_source_count = len(set(evidence.source_ips))
        evidence.unique_dest_count = len(set(evidence.destination_ips))
        evidence.collection_confidence = self._calc_confidence(
            evidence.event_count, evidence.unique_source_count, len(evidence.related_alert_ids)
        )

    def _build_conditions(self, entry: LogEntry, alerts: list[Alert]) -> list[MatchedCondition]:
        """Build matched conditions based on the triggering rule."""
        if not alerts:
            return _build_conditions_generic(entry, alerts)
        rule_id = alerts[0].rule_id
        builder = _CONDITION_BUILDERS.get(rule_id, _build_conditions_generic)
        return builder(entry, alerts)

    def _make_raw_ref(self, entry: LogEntry, alerts: list[Alert]) -> RawLogRef:
        """Create a RawLogRef from a log entry."""
        return RawLogRef(
            event_id=entry.event_id,
            raw_log=entry.raw_log,
            timestamp=entry.timestamp,
            hostname=entry.hostname,
            source_ip=entry.source_ip,
            destination_ip=entry.destination_ip,
            username=entry.username,
            service=entry.service,
            process=entry.process,
            event_type=entry.event_type.value,
            message=entry.message,
            severity=entry.severity.value,
            detection_rule_ids=[a.rule_id for a in alerts],
        )

    @staticmethod
    def _calc_confidence(event_count: int, unique_sources: int, alert_count: int) -> float:
        """Calculate evidence collection confidence (0-100)."""
        score = 0.0
        # More events = more confidence
        score += min(event_count * 5, 40)
        # Multiple sources = more confidence
        score += min(unique_sources * 10, 20)
        # Multiple alerts = more confidence
        score += min(alert_count * 10, 30)
        # Base confidence for having any evidence
        score += 10
        return min(score, 100.0)


# Global instance
evidence_engine = EvidenceEngine()

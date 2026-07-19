"""
SysLog Threat Analysis — Incident Merger & False Positive Reduction

Prevents duplicate incidents by merging when:
- Same attacker + same victim + same time window
- Same IOC cluster
- Same attack chain

Also reduces false positives by requiring supporting evidence
before incidents are considered valid.
"""

from __future__ import annotations

import logging
from datetime import timedelta
from typing import Optional

from models.events import Incident, IncidentStatus, Severity

logger = logging.getLogger(__name__)

# Merge window: incidents within this many seconds may be merged
MERGE_WINDOW_SECONDS = 300


class IncidentMerger:
    """
    Merges related incidents and filters false positives.
    Runs after all enrichment to avoid merging before full context is built.
    """

    def merge_candidates(self, incidents: list[Incident]) -> list[Incident]:
        """
        Find and merge duplicate/related incidents.
        Returns the updated incident list with merges applied.
        Modifies incidents in-place.
        """
        if len(incidents) < 2:
            return incidents

        active = [i for i in incidents if i.status in (IncidentStatus.ACTIVE, IncidentStatus.INVESTIGATING) and not i.is_merged]
        merged_ids: set[str] = set()

        for i, inc_a in enumerate(active):
            if inc_a.incident_id in merged_ids:
                continue
            for inc_b in active[i + 1:]:
                if inc_b.incident_id in merged_ids:
                    continue
                if self._should_merge(inc_a, inc_b):
                    self._do_merge(inc_a, inc_b)
                    merged_ids.add(inc_b.incident_id)

        return incidents

    def reduce_false_positives(self, incident: Incident) -> bool:
        """
        Check if an incident has enough supporting evidence to be valid.
        Returns True if the incident should be kept, False if likely false positive.

        False positive indicators:
        - Single event with no correlation
        - Single failed login without follow-up
        - Expected service restart patterns
        - Low confidence + low event count
        """
        # Rule 1: Single event with low confidence
        if incident.total_events <= 1 and incident.confidence < 40:
            logger.info(
                "FP filter: incident %s has only %d event(s) and %.1f%% confidence",
                incident.incident_id, incident.total_events, incident.confidence,
            )
            return False

        # Rule 2: Single alert without correlation
        if len(incident.related_alert_ids) <= 1 and len(incident.triggered_rules) <= 1:
            if incident.total_events <= 1:
                return False

        # Rule 3: Service failure with only 1 event (normal restart)
        if incident.incident_type == "Repeated Service Failure" and incident.total_events < 3:
            return False

        return True

    # -- Internal --

    def _should_merge(self, a: Incident, b: Incident) -> bool:
        """Determine if two incidents should be merged."""
        # Must be within time window
        time_gap = abs((a.last_seen - b.first_seen).total_seconds())
        if time_gap > MERGE_WINDOW_SECONDS:
            return False

        # Same attacker + same victim
        shared_ips = set(a.source_ips) & set(b.source_ips)
        same_user = a.target_user and b.target_user and a.target_user == b.target_user

        if shared_ips and same_user:
            return True

        # Same attack chain
        if (a.attack_chain_id and b.attack_chain_id and
                a.attack_chain_id == b.attack_chain_id):
            return True

        # Same type + same attacker
        if a.incident_type == b.incident_type and shared_ips:
            return True

        return False

    def _do_merge(self, primary: Incident, secondary: Incident) -> None:
        """Merge secondary into primary. Marks secondary as merged."""
        logger.info(
            "Merging incident %s into %s",
            secondary.incident_id, primary.incident_id,
        )

        # Absorb events
        primary.total_events += secondary.total_events

        # Merge source IPs
        for ip in secondary.source_ips:
            if ip not in primary.source_ips:
                primary.source_ips.append(ip)

        # Merge alerts
        for aid in secondary.related_alert_ids:
            if aid not in primary.related_alert_ids:
                primary.related_alert_ids.append(aid)

        # Merge event IDs
        for eid in secondary.related_event_ids:
            if eid not in primary.related_event_ids:
                primary.related_event_ids.append(eid)

        # Merge rules
        for rule in secondary.triggered_rules:
            if rule not in primary.triggered_rules:
                primary.triggered_rules.append(rule)

        # Merge MITRE
        for tech in secondary.mitre_techniques:
            if tech not in primary.mitre_techniques:
                primary.mitre_techniques.append(tech)

        # Merge timeline
        primary.timeline.extend(secondary.timeline)
        primary.timeline.sort(key=lambda t: t.timestamp)

        # Update time range
        if secondary.first_seen < primary.first_seen:
            primary.first_seen = secondary.first_seen
        if secondary.last_seen > primary.last_seen:
            primary.last_seen = secondary.last_seen

        # Elevate severity if needed
        sev_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
        if sev_order.get(secondary.severity.value, 0) > sev_order.get(primary.severity.value, 0):
            primary.severity = secondary.severity

        # Track merge
        primary.merged_incident_ids.append(secondary.incident_id)
        secondary.is_merged = True
        secondary.status = IncidentStatus.CLOSED

        # Merge target user
        if not primary.target_user and secondary.target_user:
            primary.target_user = secondary.target_user

        # Merge behavioural findings
        for finding in secondary.behavioural_findings:
            if finding not in primary.behavioural_findings:
                primary.behavioural_findings.append(finding)

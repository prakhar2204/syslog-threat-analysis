"""
SysLog Threat Analysis — Confidence Score Calculator

Computes a confidence percentage (0–100) for each incident based on:
- Number of correlated events
- Time density of events
- Rule certainty (severity weight)
- Correlation pattern strength

This is a deterministic, offline calculation — no ML or external APIs.
"""

from __future__ import annotations

from config import CONFIDENCE_WEIGHTS, RISK_LEVELS, SEVERITY_ORDER
from models.events import Incident, Severity


def calculate_confidence(incident: Incident) -> float:
    """
    Calculate confidence score for an incident.

    Returns a float between 0 and 100, rounded to one decimal.
    """
    weights = CONFIDENCE_WEIGHTS

    # Factor 1: Event count score (more events = higher confidence)
    event_score = _event_count_score(incident.total_events)

    # Factor 2: Time density (events packed into shorter window = more suspicious)
    time_score = _time_density_score(incident)

    # Factor 3: Rule certainty (higher severity rules = higher certainty)
    rule_score = _rule_certainty_score(incident.severity)

    # Factor 4: Correlation strength (more correlated signals = stronger case)
    correlation_score = _correlation_strength_score(incident)

    raw = (
        event_score * weights["event_count"]
        + time_score * weights["time_density"]
        + rule_score * weights["rule_certainty"]
        + correlation_score * weights["correlation_strength"]
    )

    return round(min(max(raw, 0.0), 100.0), 1)


def calculate_risk(incident: Incident) -> str:
    """
    Determine risk level based on severity, event volume, and confidence.

    Returns one of: 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'.
    """
    severity_weight = SEVERITY_ORDER.get(incident.severity.value, 0) * 20
    event_weight = min(incident.total_events * 3, 30)
    confidence_weight = incident.confidence * 0.5

    score = severity_weight + event_weight + confidence_weight

    for level, cfg in sorted(RISK_LEVELS.items(), key=lambda x: x[1]["min_score"], reverse=True):
        if score >= cfg["min_score"]:
            return level
    return "LOW"


# -------------------------------------------------------------------
# Scoring sub-functions
# -------------------------------------------------------------------

def _event_count_score(count: int) -> float:
    """Score based on number of correlated events. Caps at 100."""
    if count <= 1:
        return 10.0
    if count <= 3:
        return 30.0
    if count <= 5:
        return 50.0
    if count <= 10:
        return 70.0
    if count <= 20:
        return 85.0
    return 100.0


def _time_density_score(incident: Incident) -> float:
    """Score based on how tightly packed events are in time."""
    if incident.total_events < 2:
        return 20.0

    delta = (incident.last_seen - incident.first_seen).total_seconds()
    if delta <= 0:
        return 100.0

    events_per_second = incident.total_events / delta

    if events_per_second >= 1.0:
        return 100.0
    if events_per_second >= 0.5:
        return 85.0
    if events_per_second >= 0.1:
        return 60.0
    if events_per_second >= 0.01:
        return 40.0
    return 20.0


def _rule_certainty_score(severity: Severity) -> float:
    """Score based on the severity of the highest triggered rule."""
    mapping = {
        Severity.CRITICAL: 100.0,
        Severity.HIGH: 80.0,
        Severity.MEDIUM: 55.0,
        Severity.LOW: 30.0,
        Severity.INFO: 15.0,
    }
    return mapping.get(severity, 30.0)


def _correlation_strength_score(incident: Incident) -> float:
    """Score based on how many different rules and MITRE techniques correlate."""
    rules_count = len(incident.triggered_rules)
    mitre_count = len(incident.mitre_techniques)
    ips_count = len(incident.source_ips)

    signal_count = rules_count + mitre_count + ips_count

    if signal_count >= 6:
        return 100.0
    if signal_count >= 4:
        return 80.0
    if signal_count >= 2:
        return 55.0
    return 25.0

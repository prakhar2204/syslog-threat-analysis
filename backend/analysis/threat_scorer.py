"""
SysLog Threat Analysis — Threat Scoring Engine V2

Replaces simple severity scoring with a multi-factor composite score.
Combines: rule severity, evidence quality, IOC quality, correlation
strength, attack stage, time density, source diversity, and rule diversity.

Produces: threat_score (0-100), priority (SOC queue position).
"""

from __future__ import annotations

from models.events import Incident, Severity


def calculate_threat_score(incident: Incident) -> dict:
    """
    Calculate composite threat score from 10 weighted factors.

    Returns dict with 'score', 'priority', 'breakdown'.
    """
    factors = {}

    # 1. Rule Severity (weight: 15%)
    sev_map = {Severity.CRITICAL: 100, Severity.HIGH: 80, Severity.MEDIUM: 55, Severity.LOW: 30, Severity.INFO: 10}
    factors["rule_severity"] = sev_map.get(incident.severity, 30)

    # 2. Evidence Quality (weight: 12%) — more evidence = higher quality
    ev_count = len(incident.related_event_ids)
    factors["evidence_quality"] = min(ev_count * 8, 100)

    # 3. IOC Quality (weight: 8%) — how many distinct IOC types exist
    # Approximate from source_ips + mitre + rules
    ioc_signals = len(incident.source_ips) + len(incident.mitre_techniques)
    factors["ioc_quality"] = min(ioc_signals * 15, 100)

    # 4. Correlation Strength (weight: 12%) — rules + MITRE diversity
    corr = len(incident.triggered_rules) + len(incident.mitre_techniques) + len(incident.source_ips)
    factors["correlation_strength"] = min(corr * 12, 100)

    # 5. Attack Stage (weight: 10%) — later stages = higher score
    stage_scores = {
        "recon": 20, "brute_force": 40, "enumeration": 35,
        "credential_success": 70, "exploitation": 75,
        "privilege_escalation": 85, "data_access": 90,
        "persistence": 95, "exfiltration": 100,
        "probing": 15, "resource_exhaustion": 50,
        "service_crash": 60, "denial_of_service": 70,
    }
    factors["attack_stage"] = stage_scores.get(incident.attack_chain_stage, 30)

    # 6. Attack Progress (weight: 8%)
    factors["attack_progress"] = min(incident.attack_chain_progress, 100)

    # 7. Time Density (weight: 10%) — events per second
    duration = (incident.last_seen - incident.first_seen).total_seconds()
    if duration <= 0:
        factors["time_density"] = 100 if incident.total_events > 1 else 20
    else:
        eps = incident.total_events / duration
        if eps >= 1.0:
            factors["time_density"] = 100
        elif eps >= 0.5:
            factors["time_density"] = 85
        elif eps >= 0.1:
            factors["time_density"] = 60
        else:
            factors["time_density"] = 30

    # 8. Multiple Sources (weight: 8%)
    src_count = len(incident.source_ips)
    factors["source_diversity"] = min(src_count * 25, 100)

    # 9. Rule Diversity (weight: 10%) — more different rules = stronger case
    rule_count = len(incident.triggered_rules)
    factors["rule_diversity"] = min(rule_count * 20, 100)

    # 10. Event Volume (weight: 7%)
    factors["event_volume"] = min(incident.total_events * 5, 100)

    # Weighted composite
    weights = {
        "rule_severity": 0.15,
        "evidence_quality": 0.12,
        "ioc_quality": 0.08,
        "correlation_strength": 0.12,
        "attack_stage": 0.10,
        "attack_progress": 0.08,
        "time_density": 0.10,
        "source_diversity": 0.08,
        "rule_diversity": 0.10,
        "event_volume": 0.07,
    }

    score = sum(factors[k] * weights[k] for k in weights)
    score = round(min(max(score, 0), 100), 1)

    return {
        "score": score,
        "breakdown": {k: round(v, 1) for k, v in factors.items()},
    }


def calculate_priority(incidents: list[Incident]) -> None:
    """
    Assign SOC queue priority (1 = highest) to all incidents.
    Sorted by threat_score descending.
    """
    ranked = sorted(incidents, key=lambda i: i.threat_score, reverse=True)
    for idx, inc in enumerate(ranked):
        inc.priority = idx + 1

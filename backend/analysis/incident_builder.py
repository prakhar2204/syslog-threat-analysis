"""
SysLog Threat Analysis — Incident Builder

Takes correlated incidents from the CorrelationEngine and enriches them
with confidence scores, risk levels, reasoning, recommendations,
attack chain analysis, threat scoring V2, root cause analysis,
smart recommendations, and investigation insights.
"""

from __future__ import annotations

import logging

from analysis.attack_chain import AttackChainDetector
from analysis.behaviour import BehaviourAnalyzer
from analysis.confidence import calculate_confidence, calculate_risk
from analysis.reasoning import generate_reasoning, generate_recommendations
from analysis.root_cause import (
    generate_root_cause,
    generate_executive_summary,
    generate_technical_summary,
    generate_attack_narrative,
    generate_affected_assets,
    generate_mitre_summary,
)
from analysis.smart_recommendations import generate_smart_recommendations
from analysis.threat_scorer import calculate_threat_score
from models.events import Incident

logger = logging.getLogger(__name__)


class IncidentBuilder:
    """
    Enriches raw Incident objects produced by the CorrelationEngine
    with the full analysis pipeline.
    """

    def __init__(self) -> None:
        self.chain_detector = AttackChainDetector()
        self.behaviour_analyzer = BehaviourAnalyzer()

    def enrich(self, incident: Incident) -> Incident:
        """
        Apply full analysis pipeline to an incident:
        1. Calculate confidence score (V1 — existing)
        2. Determine risk level
        3. Attack chain analysis (V2)
        4. Threat scoring V2
        5. Behavioural analysis
        6. Root cause analysis
        7. Smart recommendations
        8. Investigation insights
        9. Generate reasoning (existing)
        10. Generate recommendations (existing — kept for backward compat)
        """
        # Phase 1: Existing enrichment (preserved)
        incident.confidence = calculate_confidence(incident)
        incident.risk = calculate_risk(incident)
        incident.reasoning = generate_reasoning(incident)
        incident.recommendations = generate_recommendations(incident)

        # Phase 2: Attack chain detection
        self.chain_detector.analyze(incident)

        # Phase 3: Threat Scoring V2
        score_result = calculate_threat_score(incident)
        incident.threat_score = score_result["score"]
        incident.threat_score_breakdown = score_result["breakdown"]

        # Phase 4: Behavioural findings
        incident.behavioural_findings = self.behaviour_analyzer.analyze_incident(incident)

        # Phase 5: Root cause analysis
        incident.root_cause = generate_root_cause(incident)

        # Phase 6: Smart recommendations
        incident.smart_recommendations = generate_smart_recommendations(incident)

        # Phase 7: Investigation insights
        incident.executive_summary = generate_executive_summary(incident)
        incident.technical_summary = generate_technical_summary(incident)
        incident.attack_narrative = generate_attack_narrative(incident)
        incident.affected_assets = generate_affected_assets(incident)
        incident.mitre_summary = generate_mitre_summary(incident)

        logger.info(
            "Enriched incident %s: confidence=%.1f%%, risk=%s, threat_score=%.1f, chain=%s",
            incident.incident_id,
            incident.confidence,
            incident.risk,
            incident.threat_score,
            incident.attack_chain_id or "none",
        )

        return incident

    def clear(self) -> None:
        """Reset stateful sub-engines."""
        self.chain_detector.clear()
        self.behaviour_analyzer.clear()

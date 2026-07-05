"""
SysLog Threat Analysis — Incident Builder

Takes correlated incidents from the CorrelationEngine and enriches them
with confidence scores, risk levels, reasoning, and recommendations
produced by the analysis sub-modules.
"""

from __future__ import annotations

import logging

from analysis.confidence import calculate_confidence, calculate_risk
from analysis.reasoning import generate_reasoning, generate_recommendations
from models.events import Incident

logger = logging.getLogger(__name__)


class IncidentBuilder:
    """
    Enriches raw Incident objects produced by the CorrelationEngine
    with confidence, risk, reasoning, and recommendations.
    """

    def enrich(self, incident: Incident) -> Incident:
        """
        Apply full analysis pipeline to an incident:
        1. Calculate confidence score
        2. Determine risk level
        3. Generate human-readable reasoning
        4. Generate recommended actions
        """
        incident.confidence = calculate_confidence(incident)
        incident.risk = calculate_risk(incident)
        incident.reasoning = generate_reasoning(incident)
        incident.recommendations = generate_recommendations(incident)

        logger.info(
            "Enriched incident %s: confidence=%.1f%%, risk=%s",
            incident.incident_id,
            incident.confidence,
            incident.risk,
        )

        return incident

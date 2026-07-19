"""
SysLog Threat Analysis — Multi-Stage Attack Chain Detection

Recognizes complete attack chains instead of treating alerts independently.
Maps sequences of correlated events to known attack patterns and tracks
progression through kill-chain stages.

No AI/ML — purely rule-based pattern matching against known attack sequences.
"""

from __future__ import annotations

import uuid
import logging
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Optional

from models.events import Incident, Severity

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Attack chain definitions — known multi-stage patterns
# ---------------------------------------------------------------------------

ATTACK_CHAINS: dict[str, dict] = {
    "credential_compromise": {
        "name": "Credential Compromise Campaign",
        "stages": ["recon", "brute_force", "credential_success", "privilege_escalation", "persistence"],
        "objective": "Gain persistent privileged access via credential compromise",
        "rule_stage_map": {
            "R001": "brute_force",
            "R014": "brute_force",
            "R002": "credential_success",
            "R003": "recon",
            "R004": "brute_force",
            "R005": "privilege_escalation",
        },
        "type_stage_map": {
            "Brute Force Attack": "brute_force",
            "Account Compromise": "credential_success",
            "Privilege Escalation Sequence": "privilege_escalation",
        },
    },
    "web_attack": {
        "name": "Web Application Attack Campaign",
        "stages": ["recon", "enumeration", "exploitation", "data_access", "exfiltration"],
        "objective": "Exploit web application vulnerabilities for data access",
        "rule_stage_map": {
            "R008": "recon",
            "R015": "enumeration",
            "R007": "enumeration",
            "R006": "exploitation",
        },
        "type_stage_map": {
            "Web Reconnaissance": "enumeration",
        },
    },
    "service_disruption": {
        "name": "Service Disruption Campaign",
        "stages": ["probing", "resource_exhaustion", "service_crash", "denial_of_service"],
        "objective": "Disrupt service availability",
        "rule_stage_map": {
            "R010": "probing",
            "R013": "service_crash",
        },
        "type_stage_map": {
            "Repeated Service Failure": "service_crash",
        },
    },
}


class AttackChainDetector:
    """
    Detects multi-stage attack chains by mapping incident rules/types
    to known attack patterns and tracking stage progression.
    """

    def __init__(self) -> None:
        # attacker_key -> { chain_id, chain_type, stages_seen, first_seen, incidents }
        self._active_chains: dict[str, dict] = {}

    def analyze(self, incident: Incident) -> None:
        """
        Analyze an incident for attack chain membership.
        Updates the incident's chain fields in-place.
        """
        attacker_key = self._build_key(incident)
        if not attacker_key:
            return

        # Try to match incident to a chain definition
        best_chain = self._match_chain(incident)
        if not best_chain:
            return

        chain_def = ATTACK_CHAINS[best_chain]

        # Get or create active chain for this attacker
        chain_key = f"{best_chain}:{attacker_key}"
        if chain_key not in self._active_chains:
            self._active_chains[chain_key] = {
                "chain_id": f"CHAIN-{uuid.uuid4().hex[:8]}",
                "chain_type": best_chain,
                "stages_seen": set(),
                "first_seen": incident.first_seen,
                "incident_ids": [],
            }

        chain = self._active_chains[chain_key]

        # Determine which stage this incident represents
        stage = self._determine_stage(incident, chain_def)
        if stage:
            chain["stages_seen"].add(stage)
        if incident.incident_id not in chain["incident_ids"]:
            chain["incident_ids"].append(incident.incident_id)

        # Update incident fields
        all_stages = chain_def["stages"]
        completed = [s for s in all_stages if s in chain["stages_seen"]]
        missing = [s for s in all_stages if s not in chain["stages_seen"]]
        progress = (len(completed) / len(all_stages)) * 100 if all_stages else 0

        incident.attack_chain_id = chain["chain_id"]
        incident.attack_chain_stage = stage or ""
        incident.attack_chain_progress = round(progress, 1)
        incident.attack_chain_stages_completed = completed
        incident.attack_chain_stages_missing = missing
        incident.estimated_objective = chain_def["objective"]

    def get_chains(self) -> list[dict]:
        """Return all active attack chains with their status."""
        result = []
        for key, chain in self._active_chains.items():
            chain_type = chain["chain_type"]
            chain_def = ATTACK_CHAINS[chain_type]
            all_stages = chain_def["stages"]
            completed = [s for s in all_stages if s in chain["stages_seen"]]
            progress = (len(completed) / len(all_stages)) * 100 if all_stages else 0

            result.append({
                "chain_id": chain["chain_id"],
                "chain_name": chain_def["name"],
                "chain_type": chain_type,
                "stages": all_stages,
                "stages_completed": completed,
                "stages_missing": [s for s in all_stages if s not in chain["stages_seen"]],
                "progress": round(progress, 1),
                "objective": chain_def["objective"],
                "incident_count": len(chain["incident_ids"]),
                "first_seen": chain["first_seen"].isoformat(),
            })
        return sorted(result, key=lambda c: c["progress"], reverse=True)

    def clear(self) -> None:
        """Reset all chain state."""
        self._active_chains.clear()

    # -- Internal --

    def _build_key(self, incident: Incident) -> str:
        """Build attacker identity key from incident data."""
        parts = []
        if incident.source_ips:
            parts.append(incident.source_ips[0])
        if incident.target_user:
            parts.append(incident.target_user)
        return ":".join(parts) if parts else ""

    def _match_chain(self, incident: Incident) -> Optional[str]:
        """Find the best matching chain definition for an incident."""
        for chain_id, chain_def in ATTACK_CHAINS.items():
            # Check by incident type
            if incident.incident_type in chain_def["type_stage_map"]:
                return chain_id
            # Check by triggered rules
            for rule in incident.triggered_rules:
                if rule in chain_def["rule_stage_map"]:
                    return chain_id
        return None

    def _determine_stage(self, incident: Incident, chain_def: dict) -> Optional[str]:
        """Determine which stage this incident represents in the chain."""
        # Check by incident type first
        if incident.incident_type in chain_def["type_stage_map"]:
            return chain_def["type_stage_map"][incident.incident_type]
        # Check by rules
        for rule in incident.triggered_rules:
            if rule in chain_def["rule_stage_map"]:
                return chain_def["rule_stage_map"][rule]
        return None

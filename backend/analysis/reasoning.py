"""
SysLog Threat Analysis — Reasoning Engine

Generates human-readable, template-based explanations for security
incidents. Every explanation is constructed from actual incident data —
no LLM, no AI APIs, no randomness. The output is deterministic and
fully traceable to parsed log events.
"""

from __future__ import annotations

from models.events import Incident, Severity

# ---------------------------------------------------------------------------
# Recommendation templates per incident type
# ---------------------------------------------------------------------------

_RECOMMENDATIONS: dict[str, list[str]] = {
    "Brute Force Attack": [
        "Block the source IP address at the firewall.",
        "Review authentication logs for the affected system.",
        "Enforce account lockout policies after repeated failures.",
        "Enable multi-factor authentication (MFA) for all user accounts.",
        "Consider deploying an intrusion prevention system (IPS).",
    ],
    "Account Compromise": [
        "Disable the compromised account immediately.",
        "Reset credentials for the affected user.",
        "Block the source IP address.",
        "Enable MFA on the affected account.",
        "Review all activity from the source IP and affected user.",
        "Check for lateral movement or data exfiltration.",
        "Notify the account owner through a secure channel.",
    ],
    "Web Reconnaissance": [
        "Block the source IP at the web application firewall.",
        "Review all HTTP requests from the source IP.",
        "Ensure directory listing is disabled on the web server.",
        "Verify no sensitive files are publicly accessible.",
        "Update web application firewall rules to detect enumeration patterns.",
    ],
    "Privilege Escalation Sequence": [
        "Verify the user is authorized for the executed commands.",
        "Review all commands executed under elevated privileges.",
        "Check for unauthorized changes to system configuration.",
        "Audit sudoers configuration for overly permissive rules.",
        "Investigate the timeline leading to the escalation.",
    ],
    "Repeated Service Failure": [
        "Restart the affected service and monitor stability.",
        "Review service logs for the root cause of crashes.",
        "Check for resource exhaustion (memory, CPU, disk).",
        "Investigate whether the failures are caused by malicious input.",
        "Consider enabling automatic crash recovery.",
    ],
}

# Fallback recommendations
_DEFAULT_RECOMMENDATIONS = [
    "Investigate the source of the activity.",
    "Review related logs for additional context.",
    "Monitor the affected system for further anomalies.",
    "Document findings and escalate if necessary.",
]


def generate_reasoning(incident: Incident) -> str:
    """
    Generate a human-readable explanation for why this incident was created.

    Returns a multi-paragraph reasoning string based on incident data.
    """
    inc_type = incident.incident_type
    ips = ", ".join(incident.source_ips) if incident.source_ips else "unknown source"
    user = incident.target_user or "unknown user"
    event_count = incident.total_events
    first = incident.first_seen.strftime("%H:%M:%S")
    last = incident.last_seen.strftime("%H:%M:%S")
    duration = (incident.last_seen - incident.first_seen).total_seconds()
    rules = ", ".join(incident.triggered_rules) if incident.triggered_rules else "none"
    mitre = ", ".join(incident.mitre_techniques) if incident.mitre_techniques else "N/A"

    parts: list[str] = []

    # Opening statement
    if inc_type == "Brute Force Attack":
        parts.append(
            f"The source IP {ips} generated {event_count} failed SSH login "
            f"attempts between {first} and {last} ({duration:.0f} seconds). "
            f"This volume and frequency of authentication failures from a single "
            f"source strongly indicates an automated brute-force attack."
        )
    elif inc_type == "Account Compromise":
        parts.append(
            f"The source IP {ips} made multiple failed authentication attempts "
            f"targeting user '{user}', followed by a successful login at {last}. "
            f"The pattern of repeated failures immediately preceding a success "
            f"indicates a high probability of credential compromise through brute-force."
        )
    elif inc_type == "Web Reconnaissance":
        parts.append(
            f"The source IP {ips} probed multiple unique paths on the web server "
            f"within a short time window ({first} to {last}). This systematic "
            f"enumeration pattern is consistent with automated directory scanning "
            f"or vulnerability assessment tooling."
        )
    elif inc_type == "Privilege Escalation Sequence":
        parts.append(
            f"User '{user}' executed privilege escalation commands between "
            f"{first} and {last}. {event_count} escalation events were recorded. "
            f"This activity should be verified as authorized."
        )
    elif inc_type == "Repeated Service Failure":
        parts.append(
            f"A system service experienced {event_count} failures between "
            f"{first} and {last} ({duration:.0f} seconds). Repeated crashes "
            f"within a short window may indicate resource exhaustion, malicious "
            f"input, or a denial-of-service condition."
        )
    else:
        parts.append(
            f"A security event of type '{inc_type}' was detected involving "
            f"{ips}. {event_count} related events were observed between "
            f"{first} and {last}."
        )

    # Technical details
    parts.append(
        f"Detection was triggered by rules: {rules}. "
        f"MITRE ATT&CK techniques: {mitre}."
    )

    # Correlation explanation (from the correlation engine)
    if incident.correlation_explanation:
        parts.append(incident.correlation_explanation)

    return "\n\n".join(parts)


def generate_recommendations(incident: Incident) -> list[str]:
    """
    Generate recommended actions for an incident based on its type and severity.
    """
    recs = _RECOMMENDATIONS.get(incident.incident_type, _DEFAULT_RECOMMENDATIONS).copy()

    # Add severity-specific recommendations
    if incident.severity == Severity.CRITICAL:
        recs.insert(0, "URGENT: Escalate to senior analyst immediately.")
    elif incident.severity == Severity.HIGH:
        recs.insert(0, "Prioritize investigation of this incident.")

    return recs

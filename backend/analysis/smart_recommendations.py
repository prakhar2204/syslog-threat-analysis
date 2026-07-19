"""
SysLog Threat Analysis — Smart Recommendation Engine

Generates attack-specific, structured recommendations with priority,
reason, and expected impact. Replaces simple string lists with
actionable intelligence.
"""

from __future__ import annotations

from models.events import Incident, Severity


# ---------------------------------------------------------------------------
# Structured recommendation templates per incident type
# ---------------------------------------------------------------------------

_SMART_RECS: dict[str, list[dict]] = {
    "Brute Force Attack": [
        {
            "action": "Block source IP at perimeter firewall",
            "priority": "CRITICAL",
            "reason": "Stop ongoing brute-force attempts immediately",
            "impact": "Eliminates current attack vector; attacker must change source",
        },
        {
            "action": "Enable account lockout after 5 failed attempts",
            "priority": "HIGH",
            "reason": "Prevent credential guessing by rate-limiting authentication",
            "impact": "Reduces brute-force success probability by 95%+",
        },
        {
            "action": "Deploy multi-factor authentication (MFA)",
            "priority": "HIGH",
            "reason": "Even compromised passwords become insufficient for access",
            "impact": "Neutralizes brute-force as an attack vector entirely",
        },
        {
            "action": "Review SSH configuration for key-only authentication",
            "priority": "MEDIUM",
            "reason": "Disable password authentication to eliminate attack surface",
            "impact": "Removes password guessing as a viable attack method",
        },
        {
            "action": "Deploy fail2ban or equivalent IPS",
            "priority": "MEDIUM",
            "reason": "Automate IP blocking after repeated failures",
            "impact": "Reduces analyst workload and speeds response time",
        },
    ],
    "Account Compromise": [
        {
            "action": "Disable compromised account immediately",
            "priority": "CRITICAL",
            "reason": "Prevent further unauthorized access with stolen credentials",
            "impact": "Stops active exploitation; attacker loses access",
        },
        {
            "action": "Reset password and revoke all active sessions",
            "priority": "CRITICAL",
            "reason": "Invalidate compromised credentials across all services",
            "impact": "Forces attacker re-authentication which will fail",
        },
        {
            "action": "Block attacker IP at network perimeter",
            "priority": "HIGH",
            "reason": "Prevent the attacker from attempting other accounts",
            "impact": "Disrupts attacker infrastructure targeting this network",
        },
        {
            "action": "Audit all activity from compromised account",
            "priority": "HIGH",
            "reason": "Determine scope of compromise and data exposure",
            "impact": "Identifies lateral movement and data exfiltration",
        },
        {
            "action": "Check for lateral movement to other systems",
            "priority": "HIGH",
            "reason": "Compromised credentials may have been used on other hosts",
            "impact": "Detects broader compromise before damage escalates",
        },
        {
            "action": "Notify account owner via secure channel",
            "priority": "MEDIUM",
            "reason": "User may have additional context about unauthorized access",
            "impact": "Enables user-side investigation and password hygiene",
        },
    ],
    "Web Reconnaissance": [
        {
            "action": "Block scanner IP at WAF/firewall",
            "priority": "HIGH",
            "reason": "Stop active enumeration before exploitation phase",
            "impact": "Prevents attacker from completing attack surface mapping",
        },
        {
            "action": "Review all HTTP requests from scanner IP",
            "priority": "HIGH",
            "reason": "Identify if any probed paths returned sensitive data",
            "impact": "Determines if any information was already exposed",
        },
        {
            "action": "Disable directory listing on web server",
            "priority": "MEDIUM",
            "reason": "Reduce information leakage from automated scanning",
            "impact": "Limits attacker's ability to discover hidden endpoints",
        },
        {
            "action": "Update WAF rules to detect enumeration patterns",
            "priority": "MEDIUM",
            "reason": "Automate blocking of directory scanning tools",
            "impact": "Reduces future reconnaissance success rate",
        },
    ],
    "Privilege Escalation Sequence": [
        {
            "action": "Verify user authorization for executed commands",
            "priority": "CRITICAL",
            "reason": "Determine if escalation was legitimate or malicious",
            "impact": "Confirms or rules out active compromise",
        },
        {
            "action": "Review complete sudo history for the user",
            "priority": "HIGH",
            "reason": "Identify all commands executed with elevated privileges",
            "impact": "Reveals scope of potential system modification",
        },
        {
            "action": "Audit sudoers configuration",
            "priority": "HIGH",
            "reason": "Check for overly permissive privilege grants",
            "impact": "Hardens privilege boundaries to prevent future abuse",
        },
        {
            "action": "Search for signs of lateral movement",
            "priority": "MEDIUM",
            "reason": "Privilege escalation often precedes lateral movement",
            "impact": "Detects broader compromise early",
        },
    ],
    "Repeated Service Failure": [
        {
            "action": "Restart affected service and monitor stability",
            "priority": "HIGH",
            "reason": "Restore service availability while investigating root cause",
            "impact": "Minimizes service downtime for legitimate users",
        },
        {
            "action": "Analyze service logs for crash root cause",
            "priority": "HIGH",
            "reason": "Determine if crashes are due to malicious input or bug",
            "impact": "Enables targeted fix instead of repeated restarts",
        },
        {
            "action": "Check for resource exhaustion (CPU, memory, disk)",
            "priority": "MEDIUM",
            "reason": "Resource starvation is a common DoS technique",
            "impact": "Identifies infrastructure-level countermeasures",
        },
        {
            "action": "Enable automatic crash recovery with rate limiting",
            "priority": "MEDIUM",
            "reason": "Reduce manual intervention for service recovery",
            "impact": "Improves service resilience and reduces downtime",
        },
    ],
}

_DEFAULT_RECS = [
    {
        "action": "Investigate the source of activity",
        "priority": "HIGH",
        "reason": "Determine if activity is malicious or legitimate",
        "impact": "Enables appropriate response action",
    },
    {
        "action": "Review related logs for additional context",
        "priority": "MEDIUM",
        "reason": "Single events may miss broader attack patterns",
        "impact": "Provides complete picture for accurate assessment",
    },
    {
        "action": "Document findings and escalate if necessary",
        "priority": "MEDIUM",
        "reason": "Maintain audit trail for compliance and future reference",
        "impact": "Supports incident response process",
    },
]


def generate_smart_recommendations(incident: Incident) -> list[dict]:
    """
    Generate structured recommendations based on incident type and severity.
    Each recommendation includes action, priority, reason, and expected impact.
    """
    recs = _SMART_RECS.get(incident.incident_type, _DEFAULT_RECS).copy()

    # Add severity-specific urgency
    if incident.severity == Severity.CRITICAL:
        recs.insert(0, {
            "action": "URGENT: Escalate to senior analyst and incident commander",
            "priority": "CRITICAL",
            "reason": "Critical severity requires immediate senior oversight",
            "impact": "Ensures fastest possible containment with expert guidance",
        })

    # Add chain-specific recommendations
    if incident.attack_chain_progress > 50:
        recs.insert(1, {
            "action": f"Attack chain {incident.attack_chain_progress:.0f}% complete — prioritize containment",
            "priority": "CRITICAL",
            "reason": f"Attacker has progressed through {len(incident.attack_chain_stages_completed)} stages",
            "impact": "Stopping the chain now prevents objective completion",
        })

    return recs

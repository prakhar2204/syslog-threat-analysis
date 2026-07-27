"""
SysLog Threat Analysis — Root Cause Analysis Engine

Generates deterministic, rule-based root cause explanations for every
incident. Answers "WHY did this happen?" using actual incident data.

Also generates investigation insights: executive summary, technical
summary, attack narrative, affected assets, and MITRE summary.

No AI APIs — everything is template-driven from real evidence.
"""

from __future__ import annotations

from models.events import Incident


# ---------------------------------------------------------------------------
# Root cause templates per incident type
# ---------------------------------------------------------------------------

def generate_root_cause(incident: Incident) -> str:
    """
    Generate a root cause paragraph explaining WHY this incident occurred.
    Derived entirely from incident data — no generic text.
    """
    inc_type = incident.incident_type
    ips = ", ".join(incident.source_ips[:3]) if incident.source_ips else "unknown source"
    user = incident.target_user or "unknown user"
    events = incident.total_events
    duration = (incident.last_seen - incident.first_seen).total_seconds()
    rules = incident.triggered_rules
    first = incident.first_seen.strftime("%H:%M:%S")
    last = incident.last_seen.strftime("%H:%M:%S")

    if inc_type == "Brute Force Attack":
        return (
            f"Repeated authentication failures ({events} attempts) from {ips} "
            f"over {duration:.0f} seconds indicate an automated brute-force tool "
            f"systematically guessing credentials. The attack density "
            f"({events/max(duration,0.1):.1f} attempts/sec) confirms non-human origin. "
            f"Root cause: externally-facing SSH service without rate limiting or "
            f"account lockout policy."
        )

    if inc_type == "Account Compromise":
        return (
            f"Successful authentication from {ips} immediately following "
            f"multiple failed attempts targeting user '{user}' indicates "
            f"credential compromise through brute-force. The attacker gained "
            f"valid credentials after sustained password guessing. "
            f"Root cause: weak or reused password on account '{user}' combined "
            f"with absence of multi-factor authentication."
        )

    if inc_type == "Web Reconnaissance":
        return (
            f"Systematic probing of {events} web paths from {ips} within "
            f"{duration:.0f} seconds indicates automated directory enumeration. "
            f"The attacker is mapping the application's attack surface before "
            f"attempting exploitation. "
            f"Root cause: web server exposes enumerable endpoints without "
            f"WAF-level rate limiting or path-based access controls."
        )

    if inc_type == "Privilege Escalation Sequence":
        return (
            f"User '{user}' executed {events} privilege escalation commands "
            f"between {first} and {last}. "
            f"This may indicate a compromised account being used to escalate "
            f"from standard to administrative access. "
            f"Root cause: overly permissive sudo configuration or compromised "
            f"credentials for a user with escalation rights."
        )

    if inc_type == "Repeated Service Failure":
        return (
            f"Service experienced {events} failures in {duration:.0f} seconds. "
            f"Repeated crashes in rapid succession may indicate resource "
            f"exhaustion, malicious input causing segfaults, or a deliberate "
            f"denial-of-service attack. "
            f"Root cause: service lacks input validation or resource limits, "
            f"or is under active DoS attack."
        )

    # Generic fallback
    return (
        f"Security event '{inc_type}' involving {ips} generated {events} "
        f"related events between {first} and {last}. "
        f"Detection rules {', '.join(rules[:3])} triggered on correlated activity. "
        f"Root cause requires further investigation of the triggering conditions."
    )


# ---------------------------------------------------------------------------
# Investigation insights generation
# ---------------------------------------------------------------------------

def generate_executive_summary(incident: Incident) -> str:
    """One-paragraph executive summary suitable for management."""
    sev = incident.severity.value
    inc_type = incident.incident_type
    conf = incident.confidence
    ips = ", ".join(incident.source_ips[:2]) if incident.source_ips else "unknown"
    user = incident.target_user or "N/A"

    return (
        f"A {sev}-severity {inc_type} incident was detected with {conf}% "
        f"confidence. The attack originated from {ips} targeting {user}. "
        f"{incident.total_events} events were correlated across "
        f"{len(incident.triggered_rules)} detection rules. "
        f"Immediate investigation and response are {'required' if sev in ('CRITICAL', 'HIGH') else 'recommended'}."
    )


def generate_technical_summary(incident: Incident) -> str:
    """Technical summary with detection details."""
    duration = (incident.last_seen - incident.first_seen).total_seconds()
    rules = ", ".join(incident.triggered_rules[:5])
    mitre = ", ".join(incident.mitre_techniques[:5]) if incident.mitre_techniques else "None mapped"

    return (
        f"Incident {incident.incident_id}: {incident.incident_type} | "
        f"Severity: {incident.severity.value} | Confidence: {incident.confidence}% | "
        f"Risk: {incident.risk} | Events: {incident.total_events} | "
        f"Duration: {duration:.0f}s | Rules: {rules} | "
        f"MITRE ATT&CK: {mitre} | "
        f"Sources: {', '.join(incident.source_ips[:5])} | "
        f"Target: {incident.target_user or 'N/A'}"
    )


def generate_attack_narrative(incident: Incident) -> str:
    """Chronological attack narrative derived from timeline."""
    if not incident.timeline:
        return "No timeline events available for narrative reconstruction."

    parts = [f"Attack narrative for {incident.incident_type}:"]

    for i, event in enumerate(incident.timeline[:15]):
        time_str = event.timestamp.strftime("%H:%M:%S")
        parts.append(f"  [{time_str}] {event.description}")

    if len(incident.timeline) > 15:
        parts.append(f"  ... and {len(incident.timeline) - 15} additional events.")

    return "\n".join(parts)


def generate_affected_assets(incident: Incident) -> list[str]:
    """List all affected assets from incident data."""
    assets = []

    for ip in incident.source_ips:
        assets.append(f"IP: {ip} (attacker)")

    if incident.target_user:
        assets.append(f"User: {incident.target_user} (target)")

    # Deduplicate from timeline descriptions
    services = set()
    for event in incident.timeline:
        desc_lower = event.description.lower()
        for svc in ("sshd", "apache", "nginx", "httpd", "mysql", "sudo"):
            if svc in desc_lower:
                services.add(svc)

    for svc in sorted(services):
        assets.append(f"Service: {svc}")

    return assets


def generate_mitre_summary(incident: Incident) -> str:
    """Generate MITRE ATT&CK mapping summary."""
    if not incident.mitre_techniques:
        return "No MITRE ATT&CK techniques mapped for this incident."

    # Known technique descriptions
    technique_names = {
        "T1110": "Brute Force (Credential Access)",
        "T1110.001": "Password Guessing",
        "T1110.003": "Password Spraying",
        "T1078": "Valid Accounts (Defense Evasion)",
        "T1548": "Abuse Elevation Control Mechanism",
        "T1548.003": "Sudo and Sudo Caching",
        "T1595": "Active Scanning (Reconnaissance)",
        "T1190": "Exploit Public-Facing Application",
        "T1059": "Command and Scripting Interpreter",
        "T1046": "Network Service Scanning",
        "T1498": "Network Denial of Service",
        "T1499": "Endpoint Denial of Service",
    }

    parts = ["MITRE ATT&CK Techniques:"]
    for tech in incident.mitre_techniques:
        name = technique_names.get(tech, "Unknown Technique")
        parts.append(f"  • {tech}: {name}")

    return "\n".join(parts)

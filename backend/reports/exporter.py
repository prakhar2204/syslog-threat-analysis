"""
SysLog Threat Analysis — Report Exporter

Generates incident reports in JSON, CSV, and PDF formats.
All report data originates from the in-memory pipeline buffers.
"""

from __future__ import annotations

import csv
import io
import json
import logging
from datetime import datetime
from typing import Any

from config import PROJECT_NAME, PROJECT_VERSION
from models.events import Alert, DashboardStats, Incident, LogEntry

logger = logging.getLogger(__name__)

# Conditionally import fpdf2
try:
    from fpdf import FPDF

    _HAS_FPDF = True
except ImportError:
    _HAS_FPDF = False
    logger.warning("fpdf2 not installed — PDF export will be unavailable")


class ReportExporter:
    """Generates exportable reports from pipeline data."""

    def export_json(
        self,
        stats: DashboardStats,
        incidents: list[Incident],
        alerts: list[Alert],
        entries: list[LogEntry],
    ) -> str:
        """Generate a JSON report string."""
        report = {
            "report_metadata": {
                "tool": f"{PROJECT_NAME} v{PROJECT_VERSION}",
                "generated_at": datetime.now().isoformat(),
                "total_entries_analyzed": len(entries),
            },
            "statistics": stats.model_dump(mode="json"),
            "incidents": [i.model_dump(mode="json") for i in incidents],
            "alerts": [a.model_dump(mode="json") for a in alerts[-500:]],
        }
        return json.dumps(report, indent=2, default=str)

    def export_csv(self, entries: list[LogEntry]) -> str:
        """Generate a CSV of all parsed log entries."""
        output = io.StringIO()
        writer = csv.writer(output)

        writer.writerow([
            "event_id", "timestamp", "hostname", "source_ip",
            "username", "service", "event_type", "severity",
            "message", "log_format",
        ])

        for entry in entries:
            writer.writerow([
                entry.event_id,
                entry.timestamp.isoformat(),
                entry.hostname,
                entry.source_ip or "",
                entry.username or "",
                entry.service,
                entry.event_type.value,
                entry.severity.value,
                entry.message[:300],
                entry.log_format,
            ])

        return output.getvalue()

    def export_pdf(
        self,
        stats: DashboardStats,
        incidents: list[Incident],
        alerts: list[Alert],
    ) -> bytes:
        """Generate a PDF incident report. Requires fpdf2."""
        if not _HAS_FPDF:
            raise RuntimeError("fpdf2 is not installed. Install it with: pip install fpdf2")

        pdf = _IncidentPDF()
        pdf.add_page()

        # Title
        pdf.set_font("Helvetica", "B", 18)
        pdf.cell(0, 12, PROJECT_NAME, ln=True, align="C")
        pdf.set_font("Helvetica", "", 10)
        pdf.cell(0, 6, f"Incident Report - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True, align="C")
        pdf.ln(8)

        # Statistics section
        pdf.set_font("Helvetica", "B", 13)
        pdf.cell(0, 8, "Summary Statistics", ln=True)
        pdf.set_font("Helvetica", "", 10)
        pdf.ln(2)

        stat_lines = [
            f"Total Log Entries: {stats.total_logs}",
            f"Total Alerts: {stats.total_alerts} (Active: {stats.active_alerts})",
            f"Total Incidents: {stats.total_incidents} (Active: {stats.active_incidents})",
            f"Critical Events: {stats.critical_events}",
            f"High Events: {stats.high_events}",
        ]
        for line in stat_lines:
            pdf.cell(0, 6, line, ln=True)
        pdf.ln(6)

        # Incidents section
        pdf.set_font("Helvetica", "B", 13)
        pdf.cell(0, 8, f"Incidents ({len(incidents)})", ln=True)
        pdf.ln(2)

        for inc in incidents[:20]:
            pdf.set_font("Helvetica", "B", 10)
            pdf.cell(0, 6, f"[{inc.severity.value}] {inc.incident_type} - {inc.incident_id}", ln=True)
            pdf.set_font("Helvetica", "", 9)
            pdf.cell(0, 5, f"  Confidence: {inc.confidence}% | Risk: {inc.risk} | Events: {inc.total_events}", ln=True)
            pdf.cell(0, 5, f"  Source IPs: {', '.join(inc.source_ips[:5])}", ln=True)
            pdf.cell(0, 5, f"  First Seen: {inc.first_seen.strftime('%H:%M:%S')} | Last Seen: {inc.last_seen.strftime('%H:%M:%S')}", ln=True)

            if inc.reasoning:
                pdf.set_font("Helvetica", "I", 9)
                safe_reason = inc.reasoning[:300].encode("ascii", "replace").decode("ascii")
                pdf.multi_cell(0, 5, f"  Reasoning: {safe_reason}")

            if inc.recommendations:
                pdf.set_font("Helvetica", "", 9)
                pdf.cell(0, 5, "  Recommendations:", ln=True)
                for rec in inc.recommendations[:5]:
                    safe_rec = rec.encode("ascii", "replace").decode("ascii")
                    pdf.cell(0, 5, f"    - {safe_rec}", ln=True)

            pdf.ln(4)

        # Active Alerts section
        pdf.set_font("Helvetica", "B", 13)
        pdf.cell(0, 8, f"Active Alerts ({len(alerts)})", ln=True)
        pdf.ln(2)

        for alert in alerts[:30]:
            pdf.set_font("Helvetica", "", 9)
            pdf.cell(
                0, 5,
                f"[{alert.severity.value}] {alert.rule_name} - "
                f"IP: {alert.source_ip or 'N/A'} - {alert.timestamp.strftime('%H:%M:%S')}",
                ln=True,
            )

        return pdf.output()


class _IncidentPDF(FPDF if _HAS_FPDF else object):  # type: ignore[misc]
    """Custom PDF with header/footer for incident reports."""

    def header(self) -> None:
        self.set_font("Helvetica", "I", 8)
        self.cell(0, 5, PROJECT_NAME, align="L")
        self.cell(0, 5, datetime.now().strftime("%Y-%m-%d"), align="R", ln=True)
        self.line(10, 15, 200, 15)
        self.ln(5)

    def footer(self) -> None:
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.cell(0, 10, f"Page {self.page_no()}/{{nb}}", align="C")

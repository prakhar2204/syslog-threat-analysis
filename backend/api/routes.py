"""
SysLog Threat Analysis — REST API Routes

All HTTP endpoints for the dashboard frontend.
Security logic stays in the backend pipeline — the API
only exposes query and control interfaces.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import Response

from api.schemas import AlertActionRequest, MonitorStartRequest, MonitorStopResponse
from config import LOG_WATCH_DIRS, SAMPLE_LOGS_DIR
from reports.exporter import ReportExporter
from services.pipeline import pipeline
from services.log_watcher import LogWatcher
from utils.helpers import get_log_files

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api")

# Shared watcher instance (managed at app level, referenced here)
_watcher: Optional[LogWatcher] = None


def set_watcher(watcher: LogWatcher) -> None:
    """Inject the log watcher instance from main.py."""
    global _watcher
    _watcher = watcher


# ---------------------------------------------------------------------------
# Statistics
# ---------------------------------------------------------------------------

@router.get("/stats")
async def get_stats():
    """Current dashboard statistics."""
    return pipeline.compute_stats().model_dump(mode="json")


# ---------------------------------------------------------------------------
# Log Entries
# ---------------------------------------------------------------------------

@router.get("/logs")
async def get_logs(
    search: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    event_type: Optional[str] = Query(None),
    source_ip: Optional[str] = Query(None),
    username: Optional[str] = Query(None),
    service: Optional[str] = Query(None),
    limit: int = Query(200, ge=1, le=1000),
    offset: int = Query(0, ge=0),
):
    """Query parsed log entries with optional filters and pagination."""
    entries, total = pipeline.get_entries(
        search=search,
        severity=severity,
        event_type=event_type,
        source_ip=source_ip,
        username=username,
        service=service,
        limit=limit,
        offset=offset,
    )
    return {
        "items": [e.model_dump(mode="json") for e in entries],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get("/logs/{event_id}")
async def get_log_detail(event_id: str):
    """Get detailed info about a single log entry including triggered rules."""
    detail = pipeline.get_entry_detail(event_id)
    if detail is None:
        raise HTTPException(status_code=404, detail="Log entry not found")
    return detail


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------

@router.get("/alerts")
async def get_alerts(status: Optional[str] = Query(None)):
    """Get all alerts, optionally filtered by status."""
    alerts = pipeline.alerts
    if status:
        alerts = [a for a in alerts if a.status.value == status.upper()]
    # Sort newest first
    alerts = sorted(alerts, key=lambda a: a.timestamp, reverse=True)
    return [a.model_dump(mode="json") for a in alerts[:500]]


@router.post("/alerts/action")
async def alert_action(request: AlertActionRequest):
    """Acknowledge or resolve an alert."""
    if request.action == "acknowledge":
        success = pipeline.threat_engine.acknowledge_alert(request.alert_id)
    elif request.action == "resolve":
        success = pipeline.threat_engine.resolve_alert(request.alert_id)
    else:
        raise HTTPException(status_code=400, detail="Action must be 'acknowledge' or 'resolve'")

    if not success:
        raise HTTPException(status_code=404, detail="Alert not found")

    return {"status": "ok", "alert_id": request.alert_id, "action": request.action}


# ---------------------------------------------------------------------------
# Incidents
# ---------------------------------------------------------------------------

@router.get("/incidents")
async def get_incidents():
    """Get all incidents, sorted by severity and recency."""
    incidents = sorted(
        pipeline.incidents,
        key=lambda i: (
            -{"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}.get(i.severity.value, 0),
            i.last_seen,
        ),
        reverse=True,
    )
    # Return without full timeline for list view
    return [
        {
            **i.model_dump(mode="json"),
            "timeline": i.timeline[:5] if i.timeline else [],  # Preview only
        }
        for i in incidents
    ]


@router.get("/incidents/{incident_id}")
async def get_incident_detail(incident_id: str):
    """Get full incident details including timeline, reasoning, recommendations."""
    incident = pipeline.correlation_engine.get_incident(incident_id)
    if incident is None:
        # Also search pipeline buffer
        incident = next((i for i in pipeline.incidents if i.incident_id == incident_id), None)
    if incident is None:
        raise HTTPException(status_code=404, detail="Incident not found")

    # Get related log entries
    related_logs = [
        e.model_dump(mode="json")
        for e in pipeline.log_entries
        if e.event_id in incident.related_event_ids
    ]

    result = incident.model_dump(mode="json")
    result["related_logs"] = related_logs
    return result


# ---------------------------------------------------------------------------
# Monitoring Control
# ---------------------------------------------------------------------------

@router.get("/monitor/status")
async def monitor_status():
    """Get current monitoring status."""
    return {
        "active": _watcher.is_active if _watcher else False,
        "file_path": _watcher.file_path if _watcher else "",
        "lines_processed": _watcher.lines_processed if _watcher else 0,
        "last_event_time": (
            pipeline.monitoring.last_event_time.isoformat()
            if pipeline.monitoring.last_event_time
            else None
        ),
    }


@router.post("/monitor/start")
async def start_monitoring(request: MonitorStartRequest):
    """Start monitoring a log file."""
    if _watcher is None:
        raise HTTPException(status_code=500, detail="Watcher not initialized")

    file_path = request.file_path
    if not Path(file_path).exists():
        raise HTTPException(status_code=404, detail=f"File not found: {file_path}")

    try:
        await _watcher.start(
            file_path,
            on_new_lines=pipeline.process_lines,
            from_beginning=request.from_beginning,
        )
        pipeline.monitoring.active = True
        pipeline.monitoring.file_path = file_path
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))

    return {"status": "started", "file_path": file_path}


@router.post("/monitor/stop")
async def stop_monitoring():
    """Stop monitoring the current log file."""
    if _watcher is None or not _watcher.is_active:
        return MonitorStopResponse(status="already_stopped", lines_processed=0)

    lines = _watcher.lines_processed
    await _watcher.stop()
    pipeline.monitoring.active = False

    return MonitorStopResponse(status="stopped", lines_processed=lines)


# ---------------------------------------------------------------------------
# Available Files
# ---------------------------------------------------------------------------

@router.get("/files")
async def list_files():
    """List available log files from configured directories."""
    return get_log_files([Path(d) for d in LOG_WATCH_DIRS])


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

@router.get("/export/{fmt}")
async def export_report(fmt: str):
    """Export report in json, csv, or pdf format."""
    exporter = ReportExporter()
    stats = pipeline.compute_stats()

    if fmt == "json":
        content = exporter.export_json(stats, pipeline.incidents, pipeline.alerts, pipeline.log_entries)
        return Response(
            content=content,
            media_type="application/json",
            headers={"Content-Disposition": "attachment; filename=syslog_threat_report.json"},
        )

    elif fmt == "csv":
        content = exporter.export_csv(pipeline.log_entries)
        return Response(
            content=content,
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=syslog_threat_report.csv"},
        )

    elif fmt == "pdf":
        try:
            content = exporter.export_pdf(stats, pipeline.incidents, pipeline.alerts)
            return Response(
                content=content,
                media_type="application/pdf",
                headers={"Content-Disposition": "attachment; filename=syslog_threat_report.pdf"},
            )
        except RuntimeError as exc:
            raise HTTPException(status_code=501, detail=str(exc))

    else:
        raise HTTPException(status_code=400, detail=f"Unsupported format: {fmt}. Use json, csv, or pdf.")


# ---------------------------------------------------------------------------
# Dashboard Clear
# ---------------------------------------------------------------------------

@router.post("/clear")
async def clear_dashboard():
    """Clear all in-memory data and reset the pipeline."""
    if _watcher and _watcher.is_active:
        await _watcher.stop()
    pipeline.clear()
    return {"status": "cleared"}

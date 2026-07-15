"""
SysLog Threat Analysis - REST API Routes

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

from api.schemas import (
    AlertActionRequest,
    MonitorStartRequest,
    MonitorStopResponse,
    SimulationGenerateRequest,
    SimulationStartRequest,
)
from config import LOG_WATCH_DIRS, SAMPLE_LOGS_DIR
from reports.exporter import ReportExporter
from services.pipeline import pipeline
from services.monitoring import MonitorManager
from services.simulator import SimulatorEngine, SimSpeed, SCENARIOS
from utils.helpers import get_log_files

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api")

# Shared instances (injected from main.py via set_*)
_monitor: Optional[MonitorManager] = None
_simulator: Optional[SimulatorEngine] = None


def set_monitor(monitor: MonitorManager) -> None:
    """Inject the monitor manager from main.py."""
    global _monitor
    _monitor = monitor


def set_simulator(sim: SimulatorEngine) -> None:
    """Inject the simulator from main.py."""
    global _simulator
    _simulator = sim


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
    """Full monitoring status including session, folder, EPS, uptime."""
    if _monitor is None:
        return {"active": False, "error": "Monitor not initialized"}
    return _monitor.get_status()


@router.post("/monitor/start")
async def start_monitoring(request: MonitorStartRequest):
    """Start monitoring a folder or file."""
    if _monitor is None:
        raise HTTPException(status_code=500, detail="Monitor not initialized")

    if request.folder:
        result = await _monitor.start_folder_monitoring(request.folder)
    elif request.file_path:
        if not Path(request.file_path).exists():
            raise HTTPException(status_code=404, detail=f"File not found: {request.file_path}")
        result = await _monitor.start_file_monitoring(request.file_path, request.from_beginning)
    else:
        # Default: monitor sample_logs folder
        result = await _monitor.start_folder_monitoring()

    return result


@router.post("/monitor/stop")
async def stop_monitoring():
    """Stop monitoring the current source."""
    if _monitor is None:
        return MonitorStopResponse(status="not_initialized")
    result = await _monitor.stop_monitoring()
    return result


@router.post("/monitor/pause")
async def pause_monitoring():
    """Pause monitoring without ending the session."""
    if _monitor is None:
        raise HTTPException(status_code=500, detail="Monitor not initialized")
    return await _monitor.pause_monitoring()


@router.post("/monitor/resume")
async def resume_monitoring():
    """Resume a paused monitoring session."""
    if _monitor is None:
        raise HTTPException(status_code=500, detail="Monitor not initialized")
    return await _monitor.resume_monitoring()


@router.get("/monitor/session")
async def get_current_session():
    """Get current monitoring session details."""
    if _monitor is None or _monitor.current_session is None:
        return {"session": None}
    return _monitor.current_session.to_dict()


@router.get("/monitor/history")
async def get_session_history():
    """Get all completed monitoring sessions."""
    if _monitor is None:
        return []
    return _monitor.get_session_history()


@router.get("/monitor/pipeline")
async def get_pipeline_stats():
    """Live pipeline flow statistics."""
    if _monitor is None:
        return {}
    return _monitor.get_pipeline_stats()


# ---------------------------------------------------------------------------
# Attack Simulation
# ---------------------------------------------------------------------------

@router.get("/simulation/scenarios")
async def list_scenarios():
    """List all available attack simulation scenarios."""
    return [
        {
            "id": sid,
            "name": s["name"],
            "description": s["description"],
            "category": s["category"],
        }
        for sid, s in SCENARIOS.items()
    ]


@router.post("/simulation/start")
async def start_simulation(request: SimulationStartRequest):
    """Start continuous attack simulation."""
    if _simulator is None:
        raise HTTPException(status_code=500, detail="Simulator not initialized")

    try:
        speed = SimSpeed(request.speed)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid speed: {request.speed}. Use slow, normal, fast, very_fast")

    await _simulator.start(
        scenarios=request.scenarios,
        speed=speed,
        target_user=request.target_user,
        randomize_ips=request.randomize_ips,
    )
    return {"status": "started", "speed": speed.value}


@router.post("/simulation/stop")
async def stop_simulation():
    """Stop continuous simulation."""
    if _simulator is None:
        return {"status": "not_initialized"}
    await _simulator.stop()
    return {"status": "stopped", "events_generated": _simulator.events_generated}


@router.post("/simulation/reset")
async def reset_simulation():
    """Reset simulation state and clear simulation log."""
    if _simulator is None:
        return {"status": "not_initialized"}
    _simulator.reset()
    return {"status": "reset"}


@router.post("/simulation/generate")
async def generate_once(request: SimulationGenerateRequest):
    """Generate a single batch of attack logs."""
    if _simulator is None:
        raise HTTPException(status_code=500, detail="Simulator not initialized")
    count = _simulator.generate_once(
        scenarios=request.scenarios,
        target_user=request.target_user,
    )
    return {"status": "generated", "lines": count}


@router.get("/simulation/status")
async def simulation_status():
    """Get current simulation state."""
    if _simulator is None:
        return {"active": False}
    return _simulator.status()



# ---------------------------------------------------------------------------
# Evidence
# ---------------------------------------------------------------------------

@router.get("/evidence")
async def list_evidence(
    rule_id: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    source_ip: Optional[str] = Query(None),
    username: Optional[str] = Query(None),
    service: Optional[str] = Query(None),
):
    """List all evidence objects, optionally filtered."""
    if rule_id or severity or source_ip or username or service:
        results = pipeline.evidence_engine.search_evidence(
            rule_id=rule_id, severity=severity, source_ip=source_ip,
            username=username, service=service,
        )
    else:
        results = pipeline.evidence_engine.evidence_list
    return [e.model_dump(mode="json") for e in results]


@router.get("/evidence/search")
async def search_evidence(
    rule_id: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    source_ip: Optional[str] = Query(None),
    username: Optional[str] = Query(None),
    service: Optional[str] = Query(None),
    ioc: Optional[str] = Query(None),
    keyword: Optional[str] = Query(None),
):
    """Search evidence by various criteria."""
    results = pipeline.evidence_engine.search_evidence(
        rule_id=rule_id, severity=severity, source_ip=source_ip,
        username=username, service=service, ioc=ioc, keyword=keyword,
    )
    return [e.model_dump(mode="json") for e in results]


@router.get("/evidence/by-incident/{incident_id}")
async def get_evidence_by_incident(incident_id: str):
    """Get evidence linked to a specific incident."""
    evidence = pipeline.evidence_engine.get_evidence_by_incident(incident_id)
    if evidence is None:
        raise HTTPException(status_code=404, detail="Evidence not found for incident")
    return evidence.model_dump(mode="json")


@router.get("/evidence/{evidence_id}")
async def get_evidence_detail(evidence_id: str):
    """Get a single evidence object by ID."""
    evidence = pipeline.evidence_engine.get_evidence(evidence_id)
    if evidence is None:
        raise HTTPException(status_code=404, detail="Evidence not found")
    return evidence.model_dump(mode="json")


# ---------------------------------------------------------------------------
# Observations
# ---------------------------------------------------------------------------

@router.get("/observations")
async def list_observations():
    """List all observations."""
    return [o.model_dump(mode="json") for o in pipeline.evidence_engine.observations]


@router.get("/observations/{observation_id}")
async def get_observation_detail(observation_id: str):
    """Get a single observation by ID."""
    obs = pipeline.evidence_engine.get_observation(observation_id)
    if obs is None:
        raise HTTPException(status_code=404, detail="Observation not found")
    return obs.model_dump(mode="json")


@router.post("/observations/promote")
async def promote_observation(observation_id: str = Query(...), incident_id: str = Query("")):
    """Manually promote an observation."""
    success = pipeline.evidence_engine.promote_observation(observation_id, incident_id)
    if not success:
        raise HTTPException(status_code=404, detail="Observation not found")
    return {"status": "promoted", "observation_id": observation_id}


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
                content=bytes(content),
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
    if _monitor and _monitor.is_active:
        await _monitor.stop_monitoring()
    if _simulator and _simulator.is_active:
        await _simulator.stop()
    pipeline.clear()
    return {"status": "cleared"}

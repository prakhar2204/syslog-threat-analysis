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


# ---------------------------------------------------------------------------
# Phase 5.4: Attack Chain Intelligence
# ---------------------------------------------------------------------------

@router.get("/attack-chains")
async def get_attack_chains():
    """Get all active attack chains with stage progression."""
    chains = pipeline.incident_builder.chain_detector.get_chains()
    return {"chains": chains, "total": len(chains)}


# ---------------------------------------------------------------------------
# Phase 5.4: IOC Relationship Intelligence
# ---------------------------------------------------------------------------

@router.get("/ioc-relationships")
async def get_ioc_relationships(limit: int = Query(default=20, le=100)):
    """Get top IOCs ranked by confidence with relationships."""
    iocs = pipeline.ioc_engine.get_top_iocs(limit)
    return {"iocs": iocs, "total": len(iocs)}


@router.get("/ioc-relationships/{ioc_type}/{value}")
async def get_ioc_detail(ioc_type: str, value: str):
    """Get detailed IOC information with all relationships."""
    ioc = pipeline.ioc_engine.get_ioc(ioc_type, value)
    if not ioc:
        raise HTTPException(status_code=404, detail="IOC not found")
    related = pipeline.ioc_engine.get_related_iocs(ioc_type, value)
    return {"ioc": ioc, "related": related}


@router.get("/ioc-relationships/incident/{incident_id}")
async def get_iocs_for_incident(incident_id: str):
    """Get all IOCs related to a specific incident."""
    iocs = pipeline.ioc_engine.get_iocs_for_incident(incident_id)
    return {"iocs": iocs, "total": len(iocs)}


# ---------------------------------------------------------------------------
# Phase 5.4: Dashboard Intelligence
# ---------------------------------------------------------------------------

@router.get("/dashboard-intelligence")
async def get_dashboard_intelligence():
    """
    SOC-focused dashboard intelligence replacing generic statistics.
    Returns: most dangerous attack, most active attacker, most targeted user,
    most targeted service, top IOCs, attack chain progress, SOC queue.
    """
    incidents = [i for i in pipeline.incidents if not i.is_merged]
    alerts = pipeline.alerts

    # Most dangerous attack (highest threat score)
    most_dangerous = None
    if incidents:
        top = max(incidents, key=lambda i: i.threat_score)
        most_dangerous = {
            "incident_id": top.incident_id,
            "type": top.incident_type,
            "threat_score": top.threat_score,
            "severity": top.severity.value,
            "confidence": top.confidence,
        }

    # Most active attacker
    from collections import Counter
    ip_counts = Counter()
    for inc in incidents:
        for ip in inc.source_ips:
            ip_counts[ip] += inc.total_events
    most_active_attacker = None
    if ip_counts:
        ip, count = ip_counts.most_common(1)[0]
        most_active_attacker = {"ip": ip, "event_count": count}

    # Most targeted user
    user_counts = Counter()
    for inc in incidents:
        if inc.target_user:
            user_counts[inc.target_user] += inc.total_events
    most_targeted_user = None
    if user_counts:
        user, count = user_counts.most_common(1)[0]
        most_targeted_user = {"user": user, "event_count": count}

    # Most targeted service
    service_counts = Counter()
    for alert in alerts:
        rule_id = alert.rule_id
        if rule_id in ("R001", "R002", "R003", "R004", "R014"):
            service_counts["sshd"] += 1
        elif rule_id in ("R006", "R007", "R008", "R015"):
            service_counts["web"] += 1
        elif rule_id == "R005":
            service_counts["sudo"] += 1
        elif rule_id == "R010":
            service_counts["firewall"] += 1
    most_targeted_service = None
    if service_counts:
        svc, count = service_counts.most_common(1)[0]
        most_targeted_service = {"service": svc, "event_count": count}

    # Top IOCs
    top_iocs = pipeline.ioc_engine.get_top_iocs(5)

    # Attack chains
    chains = pipeline.incident_builder.chain_detector.get_chains()

    # SOC queue (priority-ordered incidents)
    soc_queue = [
        {
            "incident_id": i.incident_id,
            "type": i.incident_type,
            "severity": i.severity.value,
            "threat_score": i.threat_score,
            "priority": i.priority,
            "confidence": i.confidence,
        }
        for i in sorted(incidents, key=lambda x: x.priority)[:10]
    ]

    # Behavioural findings
    behaviour_findings = pipeline.incident_builder.behaviour_analyzer.get_global_findings()

    return {
        "most_dangerous_attack": most_dangerous,
        "most_active_attacker": most_active_attacker,
        "most_targeted_user": most_targeted_user,
        "most_targeted_service": most_targeted_service,
        "top_iocs": top_iocs,
        "attack_chains": chains,
        "soc_queue": soc_queue,
        "behaviour_findings": behaviour_findings,
        "total_incidents": len(incidents),
        "merged_incidents": len([i for i in pipeline.incidents if i.is_merged]),
    }


# ---------------------------------------------------------------------------
# Phase 5.4: Investigation Insights
# ---------------------------------------------------------------------------

@router.get("/incidents/{incident_id}/insights")
async def get_incident_insights(incident_id: str):
    """Get full investigation insights for a single incident."""
    incident = pipeline.correlation_engine.get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    return {
        "incident_id": incident.incident_id,
        "executive_summary": incident.executive_summary,
        "technical_summary": incident.technical_summary,
        "attack_narrative": incident.attack_narrative,
        "root_cause": incident.root_cause,
        "affected_assets": incident.affected_assets,
        "mitre_summary": incident.mitre_summary,
        "behavioural_findings": incident.behavioural_findings,
        "smart_recommendations": incident.smart_recommendations,
        "attack_chain": {
            "chain_id": incident.attack_chain_id,
            "stage": incident.attack_chain_stage,
            "progress": incident.attack_chain_progress,
            "stages_completed": incident.attack_chain_stages_completed,
            "stages_missing": incident.attack_chain_stages_missing,
            "estimated_objective": incident.estimated_objective,
        },
        "threat_score": incident.threat_score,
        "threat_score_breakdown": incident.threat_score_breakdown,
        "priority": incident.priority,
    }


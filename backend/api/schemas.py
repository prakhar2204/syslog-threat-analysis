"""
SysLog Threat Analysis - API Schemas

Pydantic models for API request/response validation.
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel


class MonitorStartRequest(BaseModel):
    file_path: str = ""
    folder: str = ""
    from_beginning: bool = True


class MonitorStopResponse(BaseModel):
    status: str
    lines_processed: int = 0


class AlertActionRequest(BaseModel):
    alert_id: str
    action: str  # "acknowledge" or "resolve"


class IncidentActionRequest(BaseModel):
    action: str  # "investigate", "resolve", "close", "reopen"
    note: str = ""  # Optional analyst note


class SimulationStartRequest(BaseModel):
    scenarios: Optional[list[str]] = None
    speed: str = "normal"
    target_user: str = "admin"
    randomize_ips: bool = True


class SimulationGenerateRequest(BaseModel):
    scenarios: Optional[list[str]] = None
    target_user: str = "admin"

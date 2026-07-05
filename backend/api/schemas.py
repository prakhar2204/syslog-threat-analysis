"""
SysLog Threat Analysis — API Schemas

Pydantic models for API request/response validation.
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel


class MonitorStartRequest(BaseModel):
    file_path: str
    from_beginning: bool = True


class MonitorStopResponse(BaseModel):
    status: str
    lines_processed: int


class AlertActionRequest(BaseModel):
    alert_id: str
    action: str  # "acknowledge" or "resolve"


class LogQueryParams(BaseModel):
    search: Optional[str] = None
    severity: Optional[str] = None
    event_type: Optional[str] = None
    source_ip: Optional[str] = None
    username: Optional[str] = None
    service: Optional[str] = None
    limit: int = 200
    offset: int = 0


class PaginatedResponse(BaseModel):
    items: list
    total: int
    limit: int
    offset: int


class ExportRequest(BaseModel):
    format: str = "json"  # json, csv, pdf

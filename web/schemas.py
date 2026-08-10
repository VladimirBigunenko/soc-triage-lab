"""Pydantic schemas for the Ninja API (web/delivery layer)."""

from __future__ import annotations

from datetime import datetime

from ninja import Schema


class IocOut(Schema):
    type: str
    value: str
    confidence: float


class AlertOut(Schema):
    id: str
    detector: str
    title: str
    severity: str
    mitre: str
    source: str
    timestamp: datetime
    iocs: list[IocOut] = []


class PlaybookStepOut(Schema):
    order: int
    action: str
    description: str
    assignee_role: str


class IncidentOut(Schema):
    id: str
    title: str
    severity: str
    status: str
    opened_at: datetime
    alerts_count: int
    mitre_ttps: list[str]
    playbook: str | None = None


class IncidentDetailOut(IncidentOut):
    summary: str = ""
    alerts: list[AlertOut] = []
    playbook_steps: list[PlaybookStepOut] = []


class StatsOut(Schema):
    incidents: int
    alerts: int
    by_severity: dict[str, int]
    by_detector: dict[str, int]
    updated_at: str | None
    timestamp: str

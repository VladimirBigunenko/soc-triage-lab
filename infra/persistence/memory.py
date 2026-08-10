"""MemoryAlertRepository — in-memory AlertRepository adapter."""

from __future__ import annotations

from core.entities.alert import Alert
from core.entities.severity import AlertStatus


class MemoryAlertRepository:
    """Simple in-memory repository (demo/dev use)."""

    name = "memory"

    def __init__(self) -> None:
        self.alerts: list[Alert] = []

    def save(self, alert: Alert) -> None:
        self.alerts.append(alert)

    def list_by_status(self, status: AlertStatus) -> list[Alert]:
        return [a for a in self.alerts if a.status == status]

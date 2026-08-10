"""IncidentStore — shared in-memory store for the demo.

Bridges the pipeline (management command) and the API/dashboard layer.
In production this would be a real database; for the demo it keeps the
project dependency-free and instantly usable.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone

from core.entities.alert import Alert
from core.entities.incident import Incident


class IncidentStore:
    """Singleton-ish in-memory store of alerts and incidents."""

    _instance: "IncidentStore | None" = None

    def __new__(cls) -> "IncidentStore":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance.reset()
        return cls._instance

    def reset(self) -> None:
        self.alerts: list[Alert] = []
        self.incidents: list[Incident] = []
        self.updated_at: datetime | None = None

    def add_alerts(self, alerts: list[Alert]) -> None:
        self.alerts.extend(alerts)

    def add_incident(self, incident: Incident) -> None:
        self.incidents.append(incident)

    def list_incidents(self, severity: str | None = None) -> list[Incident]:
        incidents = sorted(self.incidents, key=lambda i: i.severity, reverse=True)
        if severity:
            incidents = [i for i in incidents if i.severity.name.lower() == severity.lower()]
        return incidents

    def get_incident(self, incident_id: str) -> Incident | None:
        for incident in self.incidents:
            if incident.id == incident_id:
                return incident
        return None

    def stats(self) -> dict:
        by_severity = Counter(i.severity.name for i in self.incidents)
        by_detector = Counter(a.detector for a in self.alerts)
        return {
            "incidents": len(self.incidents),
            "alerts": len(self.alerts),
            "by_severity": dict(by_severity),
            "by_detector": dict(by_detector),
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }


# Shared instance used by both pipeline and API.
store = IncidentStore()

__all__ = ["IncidentStore", "store"]

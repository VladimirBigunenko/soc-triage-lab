"""Incident entity — a correlated group of alerts."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from core.entities.alert import Alert
from core.entities.severity import IncidentStatus, Severity


@dataclass
class Incident:
    """An incident groups related alerts into a single case for investigation."""

    id: str
    title: str
    severity: Severity = Severity.MEDIUM
    alerts: list[Alert] = field(default_factory=list)
    status: IncidentStatus = IncidentStatus.OPEN
    opened_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    closed_at: datetime | None = None
    summary: str = ""

    def add_alert(self, alert: Alert) -> None:
        """Attach an alert; escalate severity if the alert is more severe."""
        self.alerts.append(alert)
        if alert.severity > self.severity:
            self.severity = alert.severity

    @property
    def mitre_ttps(self) -> set[str]:
        """Unique MITRE ATT&CK techniques across all alerts."""
        return {a.mitre for a in self.alerts if a.mitre}

    @property
    def iocs(self) -> list[object]:
        """Unique IoCs across all alerts (deduplicated by (type, value))."""
        seen: set[tuple[str, str]] = set()
        result = []
        for alert in self.alerts:
            for ioc in alert.iocs:
                key = (ioc.type, ioc.value)
                if key not in seen:
                    seen.add(key)
                    result.append(ioc)
        return result

    def close(self, summary: str = "") -> None:
        """Close the incident with an optional summary."""
        self.status = IncidentStatus.CLOSED
        self.closed_at = datetime.now(timezone.utc)
        if summary:
            self.summary = summary

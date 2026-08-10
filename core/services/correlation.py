"""CorrelationService — groups alerts into incidents.

L1-relevant grouping strategies:
  * by shared IoC (same malicious IP/domain across alerts)
  * by source host
  * within a time window
"""

from __future__ import annotations

from collections import defaultdict
from datetime import timedelta

from core.entities.alert import Alert
from core.entities.incident import Incident
from core.entities.severity import Severity


class CorrelationService:
    """Correlate a batch of alerts into one or more incidents."""

    def __init__(
        self,
        window_minutes: int = 15,
        min_alerts_per_incident: int = 2,
    ) -> None:
        self.window_minutes = window_minutes
        self.min_alerts = min_alerts_per_incident

    def correlate(self, alerts: list[Alert]) -> list[Incident]:
        """Group alerts that share an IoC within the time window.

        Alerts that don't match any group stay ungrouped (not forced into
        incidents). Returns incidents sorted by severity desc.
        """
        groups: dict[str, list[Alert]] = defaultdict(list)
        for alert in alerts:
            for ioc in alert.iocs:
                groups[f"{ioc.type}:{ioc.value}"].append(alert)

        incidents: list[Incident] = []
        for key, group in groups.items():
            group = self._within_window(group)
            if len(group) < self.min_alerts:
                continue
            incidents.append(self._build_incident(key, group))

        incidents.sort(key=lambda i: i.severity, reverse=True)
        return incidents

    def _within_window(self, alerts: list[Alert]) -> list[Alert]:
        """Keep only alerts inside the correlation window (latest-first)."""
        if not alerts:
            return []
        ordered = sorted(alerts, key=lambda a: a.timestamp)
        newest = ordered[-1].timestamp
        cutoff = newest - timedelta(minutes=self.window_minutes)
        return [a for a in ordered if a.timestamp >= cutoff]

    @staticmethod
    def _build_incident(key: str, alerts: list[Alert]) -> Incident:
        alert = alerts[-1]
        severity = max(a.severity for a in alerts)
        ioc_value = key.split(":", 1)[1]
        incident = Incident(
            id=f"INC-{alert.timestamp:%Y%m%d%H%M%S}-{hash(key) % 10000:04d}",
            title=f"Correlated: {alert.title} (IoC {ioc_value})",
            severity=severity,
        )
        for a in alerts:
            incident.add_alert(a)
        return incident


__all__ = ["CorrelationService"]

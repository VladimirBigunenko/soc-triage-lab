"""CorrelationService — groups alerts into incidents.

Supported grouping strategies:
  * "ioc"       — alerts sharing an IoC (default)
  * "source"    — alerts sharing a source IP/host
  * "technique" — alerts sharing a MITRE ATT&CK technique id
All strategies respect the time window.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import timedelta

from core.entities.alert import Alert
from core.entities.incident import Incident
from core.entities.severity import Severity

VALID_STRATEGIES = {"ioc", "source", "technique"}


class CorrelationService:
    """Correlate a batch of alerts into one or more incidents."""

    def __init__(
        self,
        window_minutes: int = 15,
        min_alerts_per_incident: int = 2,
        strategy: str = "ioc",
    ) -> None:
        if strategy not in VALID_STRATEGIES:
            raise ValueError(f"Unknown strategy {strategy!r}; choose from {sorted(VALID_STRATEGIES)}")
        self.window_minutes = window_minutes
        self.min_alerts = min_alerts_per_incident
        self.strategy = strategy

    def correlate(self, alerts: list[Alert]) -> list[Incident]:
        """Group alerts by the configured strategy within the time window."""
        groups: dict[str, list[Alert]] = defaultdict(list)
        for alert in alerts:
            for key in self._keys_for(alert):
                groups[key].append(alert)

        incidents: list[Incident] = []
        for key, group in groups.items():
            group = self._within_window(group)
            if len(group) < self.min_alerts:
                continue
            incidents.append(self._build_incident(key, group))

        incidents.sort(key=lambda i: i.severity, reverse=True)
        return incidents

    def _keys_for(self, alert: Alert) -> list[str]:
        """Extract grouping keys for an alert under the active strategy."""
        if self.strategy == "ioc":
            return [f"{ioc.type}:{ioc.value}" for ioc in alert.iocs]
        if self.strategy == "source":
            return [f"source:{ip}" for ip in self._source_ips(alert)]
        if self.strategy == "technique":
            return [f"ttp:{alert.mitre}"] if alert.mitre else []
        return []

    @staticmethod
    def _source_ips(alert: Alert) -> list[str]:
        """Collect source IPs from alert IoCs (ip type)."""
        return [ioc.value for ioc in alert.iocs if ioc.type == "ip"]

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
        key_value = key.split(":", 1)[1] if ":" in key else key
        incident = Incident(
            id=f"INC-{alert.timestamp:%Y%m%d%H%M%S}-{abs(hash(key)) % 10000:04d}",
            title=f"Correlated: {alert.title} ({key_value})",
            severity=severity,
        )
        for a in alerts:
            incident.add_alert(a)
        return incident


__all__ = ["CorrelationService", "VALID_STRATEGIES"]

"""ConsoleNotifier — AlertNotifier adapter printing to stdout (demo)."""

from __future__ import annotations

from core.entities.alert import Alert
from core.entities.incident import Incident


class ConsoleNotifier:
    """Prints notifications to stdout — useful for demo mode."""

    name = "console"

    def notify_alert(self, alert: Alert) -> None:
        print(f"[ALERT] {alert.severity.label} | {alert.title} (MITRE: {alert.mitre or 'n/a'})")

    def notify_incident(self, incident: Incident) -> None:
        print(
            f"[INCIDENT] {incident.severity.label} | {incident.title} "
            f"| alerts={len(incident.alerts)} | {incident.id}"
        )

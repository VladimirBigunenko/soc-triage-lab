"""TriageService — the core L1 analyst decision engine.

Decides what to do with an alert: escalate (to L2/L3), resolve, or
mark as false positive. Depends on ports only (repository + notifier).
"""

from __future__ import annotations

from dataclasses import dataclass

from core.entities.alert import Alert
from core.entities.severity import AlertStatus, Severity
from core.ports.ports import AlertNotifier, AlertRepository


@dataclass(frozen=True)
class TriageDecision:
    """Result of triaging a single alert."""

    alert_id: str
    action: str  # "escalate" | "resolve" | "false_positive"
    severity: Severity
    reason: str


class TriageService:
    """Applies a simple, configurable escalation policy to alerts.

    Policy (L1 baseline):
      * CRITICAL / HIGH  -> escalate to L2/L3 immediately
      * MEDIUM           -> resolve (monitor) unless alert carries IoCs,
                            in which case escalate
      * LOW / INFO       -> resolve
    """

    def __init__(
        self,
        repository: AlertRepository,
        notifier: AlertNotifier,
        escalate_from: Severity = Severity.HIGH,
    ) -> None:
        self._repository = repository
        self._notifier = notifier
        self._escalate_from = escalate_from

    def triage(self, alert: Alert) -> TriageDecision:
        """Apply the policy to a single alert and record the outcome."""
        if alert.severity >= self._escalate_from:
            action = "escalate"
            reason = f"Severity {alert.severity.label} >= threshold {self._escalate_from.label}"
            alert.escalate()
            self._notifier.notify_alert(alert)
        elif alert.severity == Severity.MEDIUM and alert.iocs:
            action = "escalate"
            reason = "MEDIUM severity but carries IoCs"
            alert.escalate()
            self._notifier.notify_alert(alert)
        elif alert.severity == Severity.MEDIUM:
            action = "resolve"
            reason = "MEDIUM severity, no IoCs — monitor and resolve"
            alert.resolve()
        else:
            action = "resolve"
            reason = "LOW/INFO severity"
            alert.resolve()

        self._repository.save(alert)
        return TriageDecision(
            alert_id=alert.id,
            action=action,
            severity=alert.severity,
            reason=reason,
        )

    def triage_many(self, alerts: list[Alert]) -> list[TriageDecision]:
        """Triage multiple alerts; returns one decision per alert."""
        return [self.triage(alert) for alert in alerts]

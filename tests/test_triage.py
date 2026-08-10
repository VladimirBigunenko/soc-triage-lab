"""Tests for TriageService with in-memory doubles."""

from core.entities.severity import AlertStatus, Severity
from core.services.triage import TriageService

from tests.conftest import make_alert, make_ioc


class MemoryRepository:
    """In-memory AlertRepository test double."""

    def __init__(self) -> None:
        self.alerts: list = []

    def save(self, alert) -> None:
        self.alerts.append(alert)

    def list_by_status(self, status):
        return [a for a in self.alerts if a.status == status]


class RecordingNotifier:
    """AlertNotifier test double — records notifications."""

    def __init__(self) -> None:
        self.alert_notifications: list = []
        self.incident_notifications: list = []

    def notify_alert(self, alert) -> None:
        self.alert_notifications.append(alert)

    def notify_incident(self, incident) -> None:
        self.incident_notifications.append(incident)


class TestTriageService:
    def _make(self, escalate_from: Severity = Severity.HIGH):
        repo = MemoryRepository()
        notifier = RecordingNotifier()
        service = TriageService(repo, notifier, escalate_from=escalate_from)
        return service, repo, notifier

    def test_critical_escalated_and_notified(self):
        service, repo, notifier = self._make()
        alert = make_alert(severity=Severity.CRITICAL)
        decision = service.triage(alert)

        assert decision.action == "escalate"
        assert alert.status == AlertStatus.ESCALATED
        assert len(notifier.alert_notifications) == 1
        assert len(repo.alerts) == 1

    def test_high_escalated(self):
        service, _, notifier = self._make()
        alert = make_alert(severity=Severity.HIGH)
        decision = service.triage(alert)
        assert decision.action == "escalate"
        assert len(notifier.alert_notifications) == 1

    def test_medium_without_ioc_resolved(self):
        service, _, notifier = self._make()
        alert = make_alert(severity=Severity.MEDIUM, iocs=[])
        decision = service.triage(alert)
        assert decision.action == "resolve"
        assert alert.status == AlertStatus.RESOLVED
        assert notifier.alert_notifications == []

    def test_medium_with_ioc_escalated(self):
        service, _, notifier = self._make()
        alert = make_alert(severity=Severity.MEDIUM, iocs=[make_ioc()])
        decision = service.triage(alert)
        assert decision.action == "escalate"
        assert len(notifier.alert_notifications) == 1

    def test_low_resolved(self):
        service, _, notifier = self._make()
        alert = make_alert(severity=Severity.LOW)
        decision = service.triage(alert)
        assert decision.action == "resolve"

    def test_custom_escalation_threshold(self):
        # threshold MEDIUM -> MEDIUM and above escalate, LOW resolves
        service, _, notifier = self._make(escalate_from=Severity.MEDIUM)
        low = make_alert(severity=Severity.LOW)
        assert service.triage(low).action == "resolve"
        medium = make_alert(severity=Severity.MEDIUM)
        assert service.triage(medium).action == "escalate"

    def test_triage_many(self):
        service, _, notifier = self._make()
        alerts = [
            make_alert(severity=Severity.CRITICAL),
            make_alert(severity=Severity.LOW),
            make_alert(severity=Severity.HIGH),
        ]
        decisions = service.triage_many(alerts)
        assert [d.action for d in decisions] == ["escalate", "resolve", "escalate"]

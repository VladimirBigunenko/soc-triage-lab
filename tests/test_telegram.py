"""Tests for TelegramNotifier."""

from core.entities.incident import Incident
from core.entities.severity import Severity
from infra.notifiers.telegram import TelegramNotifier

from tests.conftest import make_alert


class FakeResponse:
    def raise_for_status(self):
        return None


class FakeClient:
    """Test double for httpx.Client — records calls."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []

    def post(self, url: str, json: dict | None = None) -> FakeResponse:
        self.calls.append((url, json))
        return FakeResponse()


class TestTelegramNotifier:
    def test_disabled_without_token(self):
        notifier = TelegramNotifier()
        assert notifier.enabled is False
        # must not raise and must not send
        notifier.notify_alert(make_alert())
        notifier.notify_incident(Incident(id="INC-1", title="Case"))

    def test_notify_alert_sends_message(self):
        notifier = TelegramNotifier(token="tok123", chat_id="-10042")
        fake = FakeClient()
        notifier._client = fake
        alert = make_alert(title="Brute force detected", severity=Severity.HIGH)

        notifier.notify_alert(alert)

        assert len(fake.calls) == 1
        url, payload = fake.calls[0]
        assert url.endswith("/bottok123/sendMessage")
        assert payload["chat_id"] == "-10042"
        assert "Brute force detected" in payload["text"]

    def test_notify_incident_sends_message(self):
        notifier = TelegramNotifier(token="tok123", chat_id="-10042")
        fake = FakeClient()
        notifier._client = fake

        incident = Incident(id="INC-7", title="Correlated case")
        notifier.notify_incident(incident)

        assert len(fake.calls) == 1
        assert "[INCIDENT]" in fake.calls[0][1]["text"]
        assert "INC-7" in fake.calls[0][1]["text"]

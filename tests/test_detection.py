"""Tests for DetectionService with fake detectors."""

from core.entities.severity import Severity
from core.services.detection import DetectionService

from tests.conftest import make_alert, make_event


class FakeDetector:
    """Test double: always fires an alert for a given source."""

    def __init__(self, name: str = "fake", source: str = "auth") -> None:
        self.name = name
        self._source = source

    def analyze(self, event):
        if event.source == self._source:
            return make_alert(detector=self.name, severity=Severity.HIGH)
        return None


class SilentDetector:
    """Test double: never fires."""

    name = "silent"

    def analyze(self, event):
        return None


class TestDetectionService:
    def test_process_event_with_matching_detector(self):
        service = DetectionService([FakeDetector("auth-detect", "auth")])
        alerts = service.process_event(make_event(source="auth"))
        assert len(alerts) == 1
        assert alerts[0].detector == "auth-detect"

    def test_process_event_no_match(self):
        service = DetectionService([FakeDetector("auth-detect", "auth")])
        alerts = service.process_event(make_event(source="web"))
        assert alerts == []

    def test_process_event_multiple_detectors(self):
        service = DetectionService(
            [
                FakeDetector("d1", "auth"),
                FakeDetector("d2", "auth"),
                SilentDetector(),
            ]
        )
        alerts = service.process_event(make_event(source="auth"))
        assert len(alerts) == 2
        assert {a.detector for a in alerts} == {"d1", "d2"}

    def test_process_batch(self):
        service = DetectionService([FakeDetector("d1", "auth")])
        events = [make_event(source="auth"), make_event(source="web"), make_event(source="auth")]
        alerts = service.process_batch(events)
        assert len(alerts) == 2

    def test_register_adds_detector(self):
        service = DetectionService()
        service.register(FakeDetector("d1", "auth"))
        assert [d.name for d in service.detectors] == ["d1"]
